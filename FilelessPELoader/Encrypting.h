
void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen);
void xor_data(unsigned char* data, size_t dataLen);
void XorIT(BYTE* input, size_t length, BYTE key[16]);
void xor_stack(void* stack_top, void* stack_base);