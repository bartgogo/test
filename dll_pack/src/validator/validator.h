#ifndef VALIDATOR_H
#define VALIDATOR_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Exported validation function
// Returns TRUE if appid is valid, FALSE otherwise
__declspec(dllexport) BOOL WINAPI Validate(DWORD appid);

#ifdef __cplusplus
}
#endif

#endif // VALIDATOR_H
