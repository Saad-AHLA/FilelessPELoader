
DWORD WINAPI EncryptDecryptThread(LPVOID lpParam);
BOOL Hookit(char* dllName, char* func, PROC myFunc);
void ResumeThreads(DWORD mainThread);
void SuspendThreads(DWORD mainThread);
void HeapSleep(DWORD dwMilliseconds);
