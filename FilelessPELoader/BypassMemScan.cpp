#include "Commun.h"

void (WINAPI* pSleep)(
    DWORD dwMilliseconds
    ) = Sleep;


void SuspendThreads(DWORD mainThread) {

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32))
        return;

    do {
        if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != mainThread) {

            SuspendThread(OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID));
        }
    } while (Thread32Next(hSnapshot, &te32));
}


void ResumeThreads(DWORD mainThread) {

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32))
        return;

    do {
        if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != mainThread) {

            ResumeThread(OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID));
        }
    } while (Thread32Next(hSnapshot, &te32));

}


void HeapEncryptDecrypt(BYTE KeyBuf[16]) {


    PROCESS_HEAP_ENTRY entry;
    SecureZeroMemory(&entry, sizeof(entry));
    while (HeapWalk(GetProcessHeap(), &entry)) {
        if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {
            XorIT((BYTE*)entry.lpData, entry.cbData, KeyBuf);

        }

    }

}


// our Hooking function
void HeapSleep(DWORD dwMilliseconds) {

    BYTE KeyBuf[16];
    unsigned int r = 0;
    for (int i = 0; i < 16; i++) {
        rand_s(&r);
        KeyBuf[i] = (CHAR)r;

    }

    printf("[+] Encrypt the HEAP allocations for %d Seconds\n\n", (int)(dwMilliseconds/1000));
    HeapEncryptDecrypt(KeyBuf);


    pSleep(dwMilliseconds);

    HeapEncryptDecrypt(KeyBuf);

    printf("[+] Decrypt the Heap allocations\n\n");

}



BOOL Hookit(char* dllName, char* func, PROC myFunc) {

    HANDLE baseAddress = GetModuleHandle(NULL);
    IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)baseAddress;
    IMAGE_NT_HEADERS* NT_HEADER = (IMAGE_NT_HEADERS*)((DWORD64)baseAddress + DOS_HEADER->e_lfanew);


    IMAGE_IMPORT_DESCRIPTOR* IMPORT_DATA = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD64)baseAddress + NT_HEADER->OptionalHeader.DataDirectory[1].VirtualAddress);

    LPCSTR ModuleName = "";
    BOOL found = FALSE;

    while (IMPORT_DATA->Name != NULL) {
        ModuleName = (LPCSTR)IMPORT_DATA->Name + (DWORD64)baseAddress;
        if (_stricmp(ModuleName, dllName) == 0) {
            found = TRUE;
            break;
        }
        IMPORT_DATA++;
    }

    if (!found)
        return FALSE;

    PROC Sleep = (PROC)GetProcAddress(GetModuleHandleA(dllName), func);

    PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PBYTE)baseAddress + IMPORT_DATA->FirstThunk);
    while (thunk->u1.Function) {
        PROC* FunctionAddr = (PROC*)&thunk->u1.Function;


        if (*FunctionAddr == Sleep) {


            DWORD oldProtect = 0;
            VirtualProtect((LPVOID)FunctionAddr, 4096, PAGE_READWRITE, &oldProtect);

            *FunctionAddr = (PROC)myFunc;

            VirtualProtect((LPVOID)FunctionAddr, 4096, oldProtect, &oldProtect);

            return TRUE;
        }
        thunk++;
    }

    return FALSE;



}




DWORD WINAPI EncryptDecryptThread(LPVOID lpParam) {
    DWORD currentThreadId = GetCurrentThreadId();
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create snapshot. Error: %lu\n", GetLastError());
        return 1;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != currentThreadId) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);

                if (hThread != NULL) {
                    SuspendThread(hThread);

                    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                    NtQueryInformationThreadPtr NtQueryInformationThread = (NtQueryInformationThreadPtr)GetProcAddress(ntdll, "NtQueryInformationThread");

                    THREAD_BASIC_INFORMATION tbi;
                    NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), NULL);

                    if (status == 0) {
                        PVOID teb_base_address = tbi.TebBaseAddress;
                        PNT_TIB tib = (PNT_TIB)malloc(sizeof(NT_TIB));
                        SIZE_T bytesRead;

                        if (ReadProcessMemory(GetCurrentProcess(), teb_base_address, tib, sizeof(NT_TIB), &bytesRead)) {
                            PVOID stack_top = tib->StackLimit;
                            PVOID stack_base = tib->StackBase;

                            xor_stack(stack_top, stack_base);
                        }
                        else {
                            printf("ReadProcessMemory (TEB) failed. Error: %lu\n", GetLastError());
                        }

                        free(tib);
                    }
                    else {
                        printf("NtQueryInformationThread failed with status: 0x%X\n", status);
                    }
                }
                else {
                    printf("Failed to open thread. Error: %lu\n", GetLastError());
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    else {
        printf("Thread32First failed. Error:%lu\n", GetLastError());
    }

    Sleep(5000); // Sleep for 5 seconds

    // Decrypt the stacks and resume threads
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != currentThreadId) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                if (hThread != NULL) {
                    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                    NtQueryInformationThreadPtr NtQueryInformationThread = (NtQueryInformationThreadPtr)GetProcAddress(ntdll, "NtQueryInformationThread");

                    THREAD_BASIC_INFORMATION tbi;
                    NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), NULL);

                    if (status == 0) {
                        PVOID teb_base_address = tbi.TebBaseAddress;
                        PNT_TIB tib = (PNT_TIB)malloc(sizeof(NT_TIB));
                        SIZE_T bytesRead;

                        if (ReadProcessMemory(GetCurrentProcess(), teb_base_address, tib, sizeof(NT_TIB), &bytesRead)) {
                            PVOID stack_top = tib->StackLimit;
                            PVOID stack_base = tib->StackBase;

                            xor_stack(stack_top, stack_base);
                        }
                        else {
                            printf("ReadProcessMemory (TEB) failed. Error: %lu\n", GetLastError());
                        }

                        free(tib);
                    }
                    else {
                        printf("NtQueryInformationThread failed with status: 0x%X\n", status);
                    }

                    ResumeThread(hThread);
                    CloseHandle(hThread);
                }
                else {
                    printf("Failed to open thread. Error: %lu\n", GetLastError());
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    else {
        printf("Thread32First failed. Error:%lu\n", GetLastError());
    }

    CloseHandle(hSnapshot);
    return 0;
}
