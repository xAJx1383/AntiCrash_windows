// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "AntiCrashHandler.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        SetUpExceptionHandler();
        __debugbreak();//for testing
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        CleanUpExceptionHandler();
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void loadDLL()
{}