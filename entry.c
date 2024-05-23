#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h> 
#include <lm.h>

/*
#pragma warning(disable:4996)
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "ws2_32.lib")

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_DEPRECATE 1
*/


#ifdef BOF
#include "beacon.h"

WINBASEAPI int WINAPI Kernel32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
WINBASEAPI void* __cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI int WINAPI MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
WINBASEAPI void __cdecl MSVCRT$free(void* memblock);
DECLSPEC_IMPORT LPVOID	WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL	WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
DECLSPEC_IMPORT LPVOID	WINAPI KERNEL32$HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT void* __cdecl  MSVCRT$memcpy(LPVOID, LPVOID, size_t);
DECLSPEC_IMPORT void __cdecl   MSVCRT$memset(void*, int, size_t);

#define calloc MSVCRT$calloc
#define vsnprintf MSVCRT$vsnprintf
#define free MSVCRT$free
#define memcpy MSVCRT$memcpy
#define memset MSVCRT$memset


#define WideCharToMultiByte Kernel32$WideCharToMultiByte

#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)	/* trustedsec */
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (LPVOID)addr)	/* trustedsec */


WINBASEAPI DWORD WINAPI NETAPI32$NetServerEnum(LMCSTR servername, DWORD level, LPBYTE* bufptr, DWORD prefmaxlen, LPDWORD entriesread, LPDWORD totalentries, DWORD servertype, LMCSTR domain, LPDWORD resume_handle);
WINBASEAPI DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);


#define NetServerEnum NETAPI32$NetServerEnum
#define NetApiBufferFree NETAPI32$NetApiBufferFree


DECLSPEC_IMPORT int __stdcall WS2_32$WSAStartup(WORD wVersionRequired, LPWSADATA lpWSAData);
DECLSPEC_IMPORT int __stdcall WS2_32$WSACleanup(void);
DECLSPEC_IMPORT int __stdcall WS2_32$getaddrinfo(char* host, char* port, const struct addrinfo* hints, struct addrinfo** result);
DECLSPEC_IMPORT char* __stdcall WS2_32$inet_ntoa(struct in_addr in); 
DECLSPEC_IMPORT char* __stdcall WS2_32$inet_ntop(INT Family, const VOID* pAddr, PSTR pStringBuf, size_t StringBufSize);
DECLSPEC_IMPORT void __stdcall WS2_32$freeaddrinfo(struct addrinfo* ai);
DECLSPEC_IMPORT INT __stdcall WS2_32$WSAAddressToStringA(LPSOCKADDR, DWORD, LPWSAPROTOCOL_INFOA, LPSTR, LPDWORD);
DECLSPEC_IMPORT int __stdcall WS2_32$WSAGetLastError();


#define WSAGetLastError WS2_32$WSAGetLastError
#define WSAStartup WS2_32$WSAStartup
#define WSACleanup WS2_32$WSACleanup
#define inet_ntoa WS2_32$inet_ntoa
#define inet_ntop WS2_32$inet_ntop
#define getaddrinfo WS2_32$getaddrinfo
#define freeaddrinfo WS2_32$freeaddrinfo
#define WSAAddressToStringA WS2_32$WSAAddressToStringA

#define PRINT_INFO(...) { \
	BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__); \
}

#define PRINT_ERROR(...) { \
	BeaconPrintf(CALLBACK_ERROR, __VA_ARGS__); \
}

#else

#include <stdio.h>

#define PRINT_INFO(...) { \
	fprintf(stdout, "[+] "); \
	fprintf(stdout, __VA_ARGS__); \
}

#define PRINT_ERROR(...) { \
	fprintf(stdout, "[-] "); \
	fprintf(stdout, __VA_ARGS__); \
}

#define internal_printf printf
#define printoutput
#define bofstart

#endif


#ifndef bufsize
#define bufsize 8192
#endif

char* output __attribute__((section(".data"))) = 0;  // this is just done so its we don't go into .bss which isn't handled properly
WORD currentoutsize __attribute__((section(".data"))) = 0;
HANDLE trash __attribute__((section(".data"))) = NULL; // Needed for x64 to not give relocation error

int bofstart();
void internal_printf(const char* format, ...);
void printoutput(BOOL done);

int bofstart() {
    output = (char*)calloc(bufsize, 1);
    currentoutsize = 0;
    return 1;
}

void internal_printf(const char* format, ...) {
    int buffersize = 0;
    int transfersize = 0;
    char* curloc = NULL;
    char* intBuffer = NULL;
    va_list args;
    va_start(args, format);
    buffersize = vsnprintf(NULL, 0, format, args);
    va_end(args);

    if (buffersize == -1)
        return;

    char* transferBuffer = (char*)intAlloc(bufsize);
    intBuffer = (char*)intAlloc(buffersize);
    va_start(args, format);
    vsnprintf(intBuffer, buffersize, format, args);
    va_end(args);
    if (buffersize + currentoutsize < bufsize)
    {
        memcpy(output + currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    }
    else {
        curloc = intBuffer;
        while (buffersize > 0)
        {
            transfersize = bufsize - currentoutsize;
            if (buffersize < transfersize)
            {
                transfersize = buffersize;
            }
            memcpy(output + currentoutsize, curloc, transfersize);
            currentoutsize += transfersize;
            if (currentoutsize == bufsize)
            {
                printoutput(FALSE);
            }
            memset(transferBuffer, 0, transfersize);
            curloc += transfersize;
            buffersize -= transfersize;
        }
    }
    intFree(intBuffer);
    intFree(transferBuffer);
}

void printoutput(BOOL done) {
    char* msg = NULL;
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    memset(output, 0, bufsize);
    if (done) {free(output); output = NULL; }
}

void net_neum() {

    WSADATA wsaData;
	
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        PRINT_INFO("WSAStartup failed: %d\n", iResult);
        return;
    }

    DWORD dwLevel = 101;
    LPSERVER_INFO_101 si101;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead, dwTotalEntries;

    NET_API_STATUS nStatus = NetServerEnum(NULL, dwLevel, (LPBYTE*)&si101, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries, SV_TYPE_SERVER, NULL, NULL);

    if (nStatus == NERR_Success) {
        struct addrinfo* result = NULL;
        struct addrinfo hints;

        SecureZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

		if (si101 != NULL) {
		for (int i = 0; i < dwEntriesRead; i++) {
			internal_printf("ServerName: %-16ls, Version: %lu.%lu, Platform: %lu\n",
					si101[i].sv101_name,
					si101[i].sv101_version_major,
					si101[i].sv101_version_minor,
					si101[i].sv101_platform_id
				);

				int bufferSize = WideCharToMultiByte(CP_ACP, 0, si101[i].sv101_name, -1, NULL, 0, NULL, NULL);

				// 分配缓冲区
				char* buffer = intAlloc(bufferSize);

				// 进行转换
				WideCharToMultiByte(CP_ACP, 0, si101[i].sv101_name, -1, buffer, bufferSize, NULL, NULL);

				// 获取服务器IP地址信息
				iResult = getaddrinfo(buffer, NULL, &hints, &result);
				if (iResult == 0) {
					for (result; result != NULL; result = result->ai_next) {
						CHAR ipstr[INET6_ADDRSTRLEN];
						void* addr;
						//const char* ipver;
						INT iRetval;

						if (result->ai_family == AF_INET) { // IPv4
							struct sockaddr_in* ipv4 = (struct sockaddr_in*)result->ai_addr;
							addr = &(ipv4->sin_addr);
							//ipver = "IPv4";
							
							inet_ntop(result->ai_family, addr, ipstr, sizeof(ipstr));
							internal_printf("\tIPv4: %s\n", ipstr);
						}
						else if (result->ai_family == AF_INET6){ // IPv6
							//struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)result->ai_addr;
							//addr = &(ipv6->sin6_addr);
							LPSOCKADDR sockaddr_ip = (LPSOCKADDR) result->ai_addr;
							DWORD ipbufferlength = sizeof(ipstr);
							iRetval = WSAAddressToStringA(sockaddr_ip, (DWORD) result->ai_addrlen, NULL, ipstr, &ipbufferlength);
							if (iRetval)
								internal_printf("IPv6 WSAAddressToString failed with %u\n", WSAGetLastError() );
							else
								internal_printf("\tIPv6: %s\n", ipstr);
							//ipver = "IPv6";
						}

					}
					freeaddrinfo(result);
				}
				else {
					internal_printf("getaddrinfo failed: %d\n", iResult);
				}

				intFree(buffer);
			}
			NetApiBufferFree(si101);
		}
		else {
			PRINT_ERROR("Error %d occurred.\n", nStatus);
		}
	}


	WSACleanup();
}


#ifdef BOF
void go(char* buff, int len) {
    if (!bofstart())
    {
        return;
    }

    net_neum();

    printoutput(TRUE);

}


#else

int main(int argc, char* argv[]) {


    net_neum();

    return 0;

}

#endif
