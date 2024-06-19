#pragma once
#include <VehLib.h>


LONG WINAPI AC_ExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo);

// for now just skips the instruction that causes it
inline bool StopCrash(EXCEPTION_POINTERS* pExceptionInfo);
inline bool ValidReturn(EXCEPTION_POINTERS* pExceptionInfo);

void SetUpExceptionHandler();
void CleanUpExceptionHandler();