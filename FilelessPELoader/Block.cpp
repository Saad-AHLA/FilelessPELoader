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


