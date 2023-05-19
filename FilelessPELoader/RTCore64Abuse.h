
wchar_t* DropRTCore64();
BOOL install_driver_as_service(PCWSTR serviceName, PCWSTR displayName, PCWSTR binPath, DWORD serviceType, DWORD startType, BOOL startIt);
VOID SearchAndPatch(DWORD64 routineva, DWORD64 driverCount, LPVOID drivers2, BOOL Patch);
DWORD64 FindKernelBaseAddr();


