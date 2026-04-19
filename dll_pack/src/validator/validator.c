#include "validator.h"
#include <stdio.h>

// Validation logic - can be customized
// Currently: appid must be in range 100-1000
BOOL WINAPI Validate(DWORD appid) {
    char msg[128];

    // Simple validation: appid should be between 100 and 1000
    if (appid >= 100 && appid <= 1000) {
        wsprintfA(msg, "AppID: %lu\nValidation PASSED!", appid);
        MessageBoxA(NULL, msg, "Validator - Success", MB_OK | MB_ICONINFORMATION);
        return TRUE;
    }

    wsprintfA(msg, "AppID: %lu\nValidation FAILED!", appid);
    MessageBoxA(NULL, msg, "Validator - Failed", MB_OK | MB_ICONERROR);
    return FALSE;
}
