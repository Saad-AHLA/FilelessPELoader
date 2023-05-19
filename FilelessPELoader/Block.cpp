#include "Commun.h"



BOOL BlockNonMSDlls() {
    // Define the policy
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signaturePolicy = {};
    signaturePolicy.MicrosoftSignedOnly = 1;
    signaturePolicy.MitigationOptIn = 1;

    // Set the process mitigation policy for loading only Microsoft DLLs
    BOOL result = SetProcessMitigationPolicy(ProcessSignaturePolicy, &signaturePolicy, sizeof(signaturePolicy));
    if (!result)
    {
        printf("Failed to set policy (%u)\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}


void SetProcessSecurityDescriptor() {
    // Define a security descriptor string in SDDL format
    // The following SDDL string denies all access to the process, except for the SYSTEM account and the process owner
    LPCWSTR sddl = L"D:P"
        L"(D;OICI;GA;;;WD)"  // Deny all access to the "World" (Everyone)
        L"(A;OICI;GA;;;SY)"  // Allow all access to the "System"
        L"(A;OICI;GA;;;OW)"; // Allow all access to the process "Owner"

    PSECURITY_DESCRIPTOR securityDescriptor = nullptr;

    // Convert the SDDL string to a security descriptor
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &securityDescriptor, nullptr)) {
        // Handle the error
        return;
    }

    // Set the security descriptor for the process
    if (!SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, securityDescriptor)) {
        // Handle the error
    }

    // Free the security descriptor
    LocalFree(securityDescriptor);
}
