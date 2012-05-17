#   Copyright 2009 Gynvael Coldwind & Mateusz "j00ru" Jurczyk
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

all:
	@echo ---------------------------------------------------
	@echo If this fails try "make old" or update Platform API
	@echo ---------------------------------------------------
	g++ -Wall -Wextra NetSock.cpp PiXiEServ.cpp \
	    -lws2_32 -o PiXiEServ.exe \
	    -static-libgcc -static-libstdc++

old:
	g++ NetSock.cpp PiXiEServ.cpp -lws2_32 \
	    -DWIN32_OLD -o PiXiEServ.exe \
	    -static-libgcc -static-libstdc++
