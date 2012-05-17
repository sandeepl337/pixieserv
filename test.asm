[bits 16]
mov bx, 0xb800
mov ds, bx
xor bx, bx
mov [bx], word 0x6161
jmp $
