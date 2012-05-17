// PiXiEServ by Gynvael Coldwind & Mateusz "j00ru" Jurczyk
// http://gynvael.coldwind.pl/
// http://j00ru.vexillium.org/
//
// LICENSE
//   Copyright 2009 Gynvael Coldwind & Mateusz "j00ru" Jurczyk
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//
#include <cstdio>
#include <cstdlib>
#include <cstring>
#ifdef _WIN32
#  include <windows.h>
#  include <winsock.h>
#endif
#ifdef __unix__
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#endif
#include "NetSock.h"
#include <map>

using namespace std;

// ------------------------------------------------------------------
// Global stuff
// ------------------------------------------------------------------

// Version
#define VERSION "0.0.1"

// Macros
#define UNUSED (void)

// Functions
#ifdef _WIN32
bool InitWinsock();
#endif

#ifdef __unix__
struct myin_addr {
  union {
    struct {
      u_char s_b1,s_b2,s_b3,s_b4;
    } S_un_b;
    struct {
      u_short s_w1,s_w2;
    } S_un_w;
    u_long S_addr;
  } S_un;
};

// This is kinda stupid, but I know where and how I use inet_ntoa
#  define inet_ntoa(a) inet_ntoa(*(in_addr*)&(a))
#endif

#ifdef _WIN32
#  define myin_addr in_addr
#endif

namespace Global
{
  const char *BootFile = NULL;
  myin_addr     FirstIP     = { { { 0, 0, 0, 0 } } };
  myin_addr     MyIP        = { { { 0, 0, 0, 0 } } };
  myin_addr     BroadcastIP = { { { 0xff, 0xff, 0xff, 0xff } } };
};

// Protocols
#define PORT_BOOTPS 67
#define PORT_TFTP   69
#define PORT_TFTP_DATA 3069

// ------------------------------------------------------------------
// DHCP BOOTP
// ------------------------------------------------------------------

#define DHCP_DISCOVER  1
#define DHCP_OFFER     2
#define DHCP_REQUEST   3
#define DHCP_ACK       5
#define BOOTREQUEST 1
#define BOOTREPLY   2
#define MAGICCOOKIE 0x63538263 // LE

#pragma pack(push,1)
// http://www.javvin.com/protocolBOOTP.html
// http://www2.themanualpage.org/dhcp/dhcp_messages.php3
struct BOOTP_Packet
{
  unsigned char Op;         // Opcode (BOOTREQUEST or BOOTREPLY)
  unsigned char Htype;      // Hardware type (1 == eth)
  unsigned char Hlen;       // Len of hw addres (6 for MAC)
  unsigned char Hops;       // No idea
  unsigned int Xid;         // Transaction ID
  unsigned short Secs;      // Seconds elapsed from start
  unsigned short Flags;     // Flags
  unsigned int Ciaddr;      // Client IP address
  unsigned int Yiaddr;      // "Your" (client) IP address
  unsigned int Siaddr;      // Next server in bootstrap (myself!)
  unsigned int Giaddr;      // Replay agent
  unsigned char Chaddr[16]; // Client HW address
  unsigned char Sname[64];  // Server name
  unsigned char File[128];  // File name
  unsigned int  MagicCookie; // Must be (hex) 63 82 53 63
  // Followed by options... (at least one ff byte)
};

struct BOOTP_Option
{
  unsigned char Op;      // Option
  unsigned char Len;     // Length of Data
  unsigned char Data[1]; // Data
};
#pragma pack(pop)

// State of exchange
struct BOOTP_State
{
  bool DiscoverReceived;
  bool RequestReceived;
  myin_addr PromisedIP;

  // Clear all
  BOOTP_State()
  {
    this->DiscoverReceived = false;
    this->RequestReceived = false;
    this->PromisedIP.S_un.S_addr = 0;
  }
};

const char *MACtoStr(void *MAC);

int
HandleDHCP(NetSock *Sock, char *SrcHost, unsigned short SrcPort, void *Data, int DataSize)
{
  UNUSED SrcHost;

  // Static stuff
  static map<unsigned int, BOOTP_State*> Transactions;

  // Convert
  BOOTP_Packet *bp = (BOOTP_Packet*)Data;
  BOOTP_Option *bo = (BOOTP_Option*)(bp+1);
  void *end = (void*)((unsigned char*)Data + DataSize);

  // Check OP
  if(bp->Op != BOOTREQUEST)
  {
    printf("Ignoring unsupported DHCP request (%i)\n", bp->Op);
    return 1;
  }

  if(bp->Htype != 1 || bp->Hlen != 6)
  {
    printf("Ignoring unsupported network type (Htype=%i, Hlen=%i)\n",
        bp->Htype, bp->Hlen);
    return 2;
  }

  if(bp->MagicCookie != MAGICCOOKIE)
  {
    printf("Ignoring invalid magic cookie (MagicCookie=%.8x)\n",
        bp->MagicCookie);
    return 3;
  }
  //
  printf("BOOTP:MAC=%s:XID=%.8x: Packet received\n", MACtoStr(bp->Chaddr), bp->Xid);

  // Is such a transaction present ?
  BOOTP_State *CurrentTrans = NULL;
  if(Transactions.find(bp->Xid) != Transactions.end())
  {
    // Get the current
    CurrentTrans = Transactions[bp->Xid];
  }
  else
  {
    // Create new
    CurrentTrans = new BOOTP_State;
    Transactions[bp->Xid] = CurrentTrans;    

    printf("BOOTP:MAC=%s:XID=%.8x: New transaction created\n", MACtoStr(bp->Chaddr), bp->Xid);
  }

  bool SendOffer = false;
  bool SendACK   = false;

  // Parse options
  while(bo->Op != 0xff && bo < end)
  {
    unsigned char *OpData = (unsigned char*)bo + 2;

    // Check size
    void *opend = (unsigned char*)bo + bo->Len;
    if(opend >= end)
    {
      printf("BOOTP:MAC=%s:XID=%.8x:  Option out of bounds!\n", MACtoStr(bp->Chaddr), bp->Xid);
      break;
    }

    // Switch
    switch(bo->Op)
    {
      case 53:
        switch(bo->Data[0])
        {
          case DHCP_DISCOVER:
            printf("BOOTP:MAC=%s:XID=%.8x:  DHCP Discover\n", MACtoStr(bp->Chaddr), bp->Xid);
            SendOffer = true;
            CurrentTrans->DiscoverReceived = true;
            break;

          case DHCP_REQUEST:
            printf("BOOTP:MAC=%s:XID=%.8x:  DHCP Request\n", MACtoStr(bp->Chaddr), bp->Xid);
            SendACK = true;
            CurrentTrans->RequestReceived = true;
            break;

          default:
            printf("BOOTP:MAC=%s:XID=%.8x:  DHCP WTF(%u)\n", MACtoStr(bp->Chaddr), bp->Xid,
                bo->Data[0]);
            return 1;
        }

        break;

      case 60:
        printf("BOOTP:MAC=%s:XID=%.8x:  VCI: ", MACtoStr(bp->Chaddr), bp->Xid);
        fwrite(OpData, 1, bo->Len, stdout);
        putchar('\n');
        break;

      case 93:
        printf("BOOTP:MAC=%s:XID=%.8x:  Arch: %s\n", MACtoStr(bp->Chaddr), bp->Xid,
            (*(unsigned short*)OpData) == 0 ? "IA x86 PC" : "???");
        break;

      case 55:
        {
          int i;
          for(i = 0; i < bo->Len; i++)
          {
            switch(OpData[i])
            {
              case 67:
                printf("BOOTP:MAC=%s:XID=%.8x:  Bootfile name requested!\n", MACtoStr(bp->Chaddr), bp->Xid);
                break;

            }
          }
          break;
        }
    }

    // Next!
    bo = (BOOTP_Option*)(OpData + bo->Len);
  }
  
  // Packets common
  static char Buffer[4096];
  BOOTP_Packet *sp = (BOOTP_Packet*)Buffer;
  BOOTP_Option *so = (BOOTP_Option*)(sp + 1);

  memset(Buffer, 0, sizeof(Buffer));
  memcpy(sp, bp, sizeof(BOOTP_Packet));

  // OP
  sp->Op = BOOTREPLY;

  // My address
  sp->Siaddr = Global::MyIP.S_un.S_addr;  

  // Boot file name
  strcpy((char*)sp->File, Global::BootFile);

#define NEXT_SO(a) a = (BOOTP_Option*)((unsigned char*)a + a->Len + 2);  

  // What should I do ?
  if(SendOffer)
  {
    // Send Offer
    printf("BOOTP:MAC=%s:XID=%.8x: Sending offer!\n", MACtoStr(bp->Chaddr), bp->Xid);    

    // Client address (promised)
    sp->Yiaddr = Global::FirstIP.S_un.S_addr;
    CurrentTrans->PromisedIP = Global::FirstIP;
    Global::FirstIP.S_un.S_un_b.s_b4++;

    // And now, the options!
    so->Op = 53;
    so->Len = 1;
    so->Data[0] = DHCP_OFFER;
    NEXT_SO(so);
  }
  else if(SendACK)
  {
    // Send ACK
    printf("BOOTP:MAC=%s:XID=%.8x: Sending ACK!\n", MACtoStr(bp->Chaddr), bp->Xid);    

    // Client address (promised)
    sp->Yiaddr = CurrentTrans->PromisedIP.S_un.S_addr;

    // And now, the options!
    so->Op = 53;
    so->Len = 1;
    so->Data[0] = DHCP_ACK;
    NEXT_SO(so);

  }
  else
  {
    // No idea
    printf("BOOTP:MAC=%s:XID=%.8x: What does he want from me???\n", MACtoStr(bp->Chaddr), bp->Xid);
    return 1;
  }

  // Common options
  so->Op = 54;
  so->Len = 4;
  *(unsigned int*)so->Data = Global::MyIP.S_un.S_addr;
  NEXT_SO(so);

  // Last option
  so->Op = 0xff;
#undef NEXT_SO    

  // Calc size
  int Sz = (int)(((unsigned long)so + 1) - (unsigned long)Buffer);
  if(Sz < 590)
    Sz = 590;

  // Send!

  Sock->SetMode(NetSock::SYNCHRONIC);
  int RetSend = Sock->BroadcastUDP(inet_ntoa(Global::BroadcastIP), SrcPort, Buffer, Sz);
  if(RetSend != Sz)
  {
#ifdef WIN32
    printf("BOOTP:MAC=%s:XID=%.8x: Send error (%i)\n",
        MACtoStr(bp->Chaddr), bp->Xid, WSAGetLastError());
#else
    printf("BOOTP:MAC=%s:XID=%.8x: Send error (%i returned)\n",
        MACtoStr(bp->Chaddr), bp->Xid, RetSend);
    perror("sendto");
#endif
  }
   
  Sock->SetMode(NetSock::ASYNCHRONIC);  

  // Done
  return 0;
}

// ------------------------------------------------------------------
// TFTP 
// ------------------------------------------------------------------


// Received
#define TFTP_READREQUEST 1
#define TFTP_ACKBLOCK    4
#define TFTP_ERRORCODE   5

// Sent
#define TFTP_DATAPACKET  3
#define TFTP_OPTIONACK   6

struct TFTP_State
{
  int BlockSize;
  FILE *f;
  bool DataSent;

  TFTP_State()
  {
    // Zero everything
    this->BlockSize = 0;
    this->f = NULL;
    this->DataSent = false;
  }
};

union TFTP_Id
{
  unsigned long long Id;
  struct
  {
    unsigned int IP;
    unsigned short Port;
  } Str;
};

int
SendTFTPOptAck(NetSock *Sock, char *DstHost, unsigned short DstPort, 
    const char *Opt, int OptVal)
{
  char Buffer[1024];
  char *Ptr = Buffer;

  // Set TFTP_OPTIONACK
  *Ptr++ = 0;
  *Ptr++ = TFTP_OPTIONACK;
  strcpy(Ptr, Opt);
  Ptr += strlen(Opt) + 1;
  sprintf(Ptr, "%i", OptVal);
  Ptr += strlen(Ptr) + 1;

  return Sock->WriteUDP(DstHost, DstPort,  Buffer, (int)(Ptr - Buffer));
}

int 
GetBootFileSize()
{
  FILE *f;
  int Size = 0;
  f = fopen(Global::BootFile, "rb");
  if(!f) return 0;
  fseek(f, 0, SEEK_END);
  Size = (int)ftell(f);
  fclose(f);

  return Size;
}

// Handle
int
HandleTFTP(NetSock *Sock, NetSock *SockData,
          char *SrcHost, unsigned short SrcPort, void *Data, int DataSize)
{
  UNUSED Sock;
  UNUSED DataSize;

  static map<unsigned long long,TFTP_State*> Clients;

  // Check if a client is on the list
  TFTP_State *CurrentClient = NULL;
  TFTP_Id Id;
  Id.Id = 0;
  Id.Str.IP = inet_addr(SrcHost);
  Id.Str.Port = SrcPort;

  // Find
  if(Clients.find(Id.Id) != Clients.end())
  {
    // A returning client!
    CurrentClient = Clients[Id.Id];
  }
  else
  {
    CurrentClient = new TFTP_State;
    Clients[Id.Id] = CurrentClient;
  }

  // Create a pointer
  unsigned char *Ptr = (unsigned char*)Data;

  // What do you want us do to ?
  unsigned short Op = *(unsigned short*)Ptr;
  Op = (Op >> 8) | (Op << 8);
  Ptr += 2;

  // Opcode ?
  switch(Op)
  {
    case TFTP_READREQUEST:
      {
        // Read the options
        const char *FileName = (const char*)Ptr;    Ptr += strlen(FileName) + 1;
        const char *Type = (const char*)Ptr;        Ptr += strlen(Type) + 1;
        const char *OptionName = (const char*)Ptr;  Ptr += strlen(OptionName) + 1;
        const char *OptionValue = (const char*)Ptr; Ptr += strlen(OptionName) + 1;

        printf("TFTP:IP=%s:PORT=%u: Read Req: %s (%s)\n", 
          SrcHost, SrcPort, FileName, Type);
 
        printf("TFTP:IP=%s:PORT=%u:  Option: %s=%s\n", 
          SrcHost, SrcPort, OptionName, OptionValue);

        if(strcmp(Type, "octet") != 0)
        {
          printf("TFTP:IP=%s:PORT=%u: Unknown type, only octet supported!", 
            SrcHost, SrcPort);
          return 1;
        }

        // The filename is ignored
        // I just serve one file ;>

        // What are the options?
        if(strcmp(OptionName, "tsize") == 0)
        {
          // total size!
          int tsize = atoi(OptionValue);
          if(tsize == 0)
          {
            printf("TFTP:IP=%s:PORT=%u: Sending boot file size!\n", 
              SrcHost, SrcPort);

            // Send him tsize of the file
            SendTFTPOptAck(SockData, SrcHost, SrcPort, OptionName, 
                GetBootFileSize());

            return 0;

          }
          else
          {
            printf("TFTP:IP=%s:PORT=%u: Unknown intention of tsize!", 
              SrcHost, SrcPort);
            return 2;            
          }
        }
        else if(strcmp(OptionName, "blksize") == 0)
        {
          int BlockSize = atoi(OptionValue);
          CurrentClient->BlockSize = BlockSize;
          printf("TFTP:IP=%s:PORT=%u: Setting BlockSize to %i\n", 
              SrcHost, SrcPort, BlockSize);

          printf("TFTP:IP=%s:PORT=%u: Sending BlockSize ACK!\n", 
              SrcHost, SrcPort);

          // Send ack!
          SendTFTPOptAck(SockData, SrcHost, SrcPort, OptionName, BlockSize);

          return 0;
        }
        else
        {
          printf("TFTP:IP=%s:PORT=%u: Unknown option detected!\n", 
            SrcHost, SrcPort);    
          return 2;            
        }

      // Check options
      }
      // read request;
      break;

    case TFTP_ERRORCODE:
      {
        // Read error msg
        unsigned short ErrorCode = *Ptr++;
        ErrorCode = ErrorCode * 0x100 + *Ptr++;
        const char *ErrorMsg = (const char*)Ptr; // TODO sth more here?
        printf("TFTP:IP=%s:PORT=%u: Error %u: %s\n", 
            SrcHost, SrcPort, ErrorCode, ErrorMsg);
        return 1;
      }
      break;

    case TFTP_ACKBLOCK:
      {
        // Request a block
        unsigned short BlockNo = *Ptr++;
        BlockNo = BlockNo * 0x100 + *Ptr++;
   
        if(!CurrentClient->DataSent)
        {
           // Send data
          char *Packet = new char[4 + CurrentClient->BlockSize];
          int SendSize = 4;


          if(!CurrentClient->f)
          {
            CurrentClient->f = fopen(Global::BootFile, "rb");
            if(!CurrentClient->f)
            {
              printf("Could not access boot file!\n");
              return 2;
            }
          }

          SendSize += fread(Packet + 4, 1, CurrentClient->BlockSize, CurrentClient->f);
          if(SendSize != 4 + CurrentClient->BlockSize)
          {
            fclose(CurrentClient->f);
            CurrentClient->f = NULL;
            CurrentClient->DataSent = true;
          }

          Packet[0] = 0;
          Packet[1] = TFTP_DATAPACKET;
          Packet[2] = 0;
          Packet[3] = BlockNo + 1;
        
          printf("TFTP:IP=%s:PORT=%u: Sending block %u!\n", 
            SrcHost, SrcPort, BlockNo);

          SockData->WriteUDP(SrcHost, SrcPort, Packet, SendSize);

          delete Packet;
          // Done

        }
        else
        {
          // Data already sent
          printf("TFTP:IP=%s:PORT=%u: Final ACK received.\n", 
            SrcHost, SrcPort);

        }


        return 0;
      }

      break;

    default:
      printf("TFTP:IP=%s:PORT=%u: Unknown opcode (%u)\n", 
          SrcHost, SrcPort, Op);
      return 1;
  }
  

  // Done
  return 0;
}



// ------------------------------------------------------------------
// main
// ------------------------------------------------------------------
int
main(int argc, char **argv)
{
  // Banner
  puts("PiXiEServ v." VERSION " by Gynvael Coldwind & Mateusz \"j00ru\" Jurczyk");

  // Argc
  if(argc < 4 || argc > 5)
  {
    puts("usage: PiXiEServ <BootFile> <HostIP> <DHCPFirstIP> [BroadcastAddr]\n"
         "e.g. : PiXiEServ bootdebug.bin 192.168.1.123 192.168.1.200\n"
         "     : PiXiEServ bootdebug.bin 192.168.1.123 192.168.1.200 192.168.1.255\n" 
         "notes: PiXiEServ currently binds at 0.0.0.0\n"
         "     : on Windows Vista+ you'll probably need to provide BroadcastAddr");
    return 1;
  }

  // Get args
  Global::BootFile = argv[1];
  FILE *ftest = fopen(Global::BootFile, "rb");
  if(!ftest)
  {
    printf("error: could not open boot file \"%s\"\n", Global::BootFile);
    return 2;
  }
  fclose(ftest);
  printf("Boot File: %s\n", Global::BootFile);

  Global::MyIP.S_un.S_addr = inet_addr(argv[2]);
  printf("My IP    : %s\n", inet_ntoa(Global::MyIP));

  Global::FirstIP.S_un.S_addr = inet_addr(argv[3]);
  printf("First IP : %s\n", inet_ntoa(Global::FirstIP));

  if(argc >= 5)
    Global::BroadcastIP.S_un.S_addr = inet_addr(argv[4]);
  printf("Broadcast: %s\n", inet_ntoa(Global::BroadcastIP));

  // Init windosck
#ifdef _WIN32
  if(!InitWinsock())
    return 2;
#endif

  // Start both sockets
  NetSock SockDHCP;
  NetSock SockTFTP, SockTFTPData;

  // Start BOOTP DHCP server
  if(!SockDHCP.ListenAllUDP(PORT_BOOTPS))
  {
    puts("error: could not bind to bootps (67/UDP)\n"
         "       (not root/admin? another bootps?)");
    return 3;
  }

  // Start TFTP server
  if(!SockTFTP.ListenAllUDP(PORT_TFTP))
  {
    puts("error: could not bind to tftp (69/UDP)\n"
         "       (not root/admin? another tftp?)");
    return 4;
  }

  if(!SockTFTPData.ListenAllUDP(PORT_TFTP_DATA))
  {
    // TODO make this more random
    puts("error: could not bind to tftp (3069/UDP)\n"
         "       (bad luck ;p)");
    return 5;
  }  

  // Switch both to asynch
  SockDHCP.SetMode(NetSock::ASYNCHRONIC);
  SockTFTP.SetMode(NetSock::ASYNCHRONIC);
  SockTFTPData.SetMode(NetSock::ASYNCHRONIC);  

  // Enter main loop
  printf("Entering main loop...\n");

  for(;;)
  {
    // Buffer
    static char Buffer[4096];
    int Ret;
    unsigned short SrcPort;
    char SrcHost[32];

    // Sleep some time
#ifdef WIN32
    Sleep(100);
#else
    usleep(100*1000);
#endif

    // For BOOTP, only receive packets larger or equal to BOOTP size
    Ret = SockDHCP.ReadUDP(Buffer, sizeof(Buffer), SrcHost, &SrcPort);
    if(Ret > 0)
    {
      if(Ret <= (int)sizeof(BOOTP_Packet))
      {
        printf("Ignored DHCP packet from %s:%u (too short, only %i bytes)\n", 
            SrcHost, SrcPort, Ret);
      }
      else
      {
        HandleDHCP(&SockDHCP, SrcHost, SrcPort, Buffer, Ret);
      }
    }

    // For TFTP, get everything that is larger than 2 bytes ;D
    Ret = SockTFTP.ReadUDP(Buffer, sizeof(Buffer), SrcHost, &SrcPort);
    if(Ret > 0)
    {
      if(Ret < 2)
      {
        printf("Ignoring TFTP packet from %s:%u (too short, only %i bytes)\n",
            SrcHost, SrcPort, Ret);
      }
      else
      {
        HandleTFTP(&SockTFTP, &SockTFTPData, SrcHost, SrcPort, Buffer, Ret);
      }
    }

    // Same here
    Ret = SockTFTPData.ReadUDP(Buffer, sizeof(Buffer), SrcHost, &SrcPort);
    if(Ret > 0)
    {
      if(Ret < 2)
      {
        printf("Ignoring TFTP packet from %s:%u (too short, only %i bytes)\n",
            SrcHost, SrcPort, Ret);
      }
      else
      {
        HandleTFTP(&SockTFTP, &SockTFTPData, SrcHost, SrcPort, Buffer, Ret);
      }
    }    
  }

        

  return 0;
}

#ifdef _WIN32
bool
InitWinsock()
{
  WSADATA wsdat;
  memset(&wsdat,0,sizeof(wsdat));

  if(WSAStartup(0x0101,&wsdat))
  {
    printf("WSAStartup()\n");
    return false;
  }

  return true;
}
#endif


const char *
MACtoStr(void *MAC)
{
  unsigned char *cMAC = (unsigned char*)MAC;
  static char Buffer[32];
  sprintf(Buffer, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
      cMAC[0], cMAC[1], cMAC[2], cMAC[3], cMAC[4], cMAC[5]);
  return Buffer;
}

