#pragma once
#include <Windows.h>
#include <processsnapshot.h>
#include <tbb/spin_mutex.h>
#include <vector>
#include <stdint.h>
#include <iostream>
#include <unordered_set>
#define CACHE_ALIGN  __declspec(align(64))
using ExcepHandler_t = LONG(WINAPI*)(EXCEPTION_POINTERS* pExceptionInfo);

#if defined(_Win64) || defined(_AMD64_)
#define XIP Rip
#define XSP Rsp
#define XBP Rbp
#define XCX Rcx
#else
#define XIP Eip
#define XSP Esp
#define XBP Ebp
#define XCX Ecx
#endif // _Win64

///HwBps Addresses and do action depending on other 2 array
extern uintptr_t HwBreakPoints[4];

/// of any address is set with same indext as triggered address in HwBreakPoints[] this is the address that will be set for next HwBP and when it triggered it restore orginal one
extern uintptr_t HWBPsReApply[4];

/// if HwBreakPoints[i] triggered and there is a Address in HWBPsRedirect[i] it will be redirected to that address: Rip == HWBPsRedirect[i]
extern uintptr_t HWBPsRedirect[4];

///Base addresses of pages for Page_Guard_Exceptions to check if its in rage of our page to handle and reapply it if thrown
extern std::unordered_set<HANDLE> BaseAddresses;

/// Queue that if single step thrown if there was an address it will be ReApply(For Page_Guard_Exception)
//extern std::vector<uintptr_t> ReApplyQueue;

///Addresses of Orginal Function you want to hook(For Page_Guard_Exception/SwBPs)
extern std::vector<uintptr_t> OrgFuncAddrs;

///Addresses of Hk Functions you want to redirect to from OrgFunction : OrgFuncAddrs[i] -> HkFuncAddrs[i] (redirect)(For Page_Guard_Exception/SwBPs)
extern std::vector<uintptr_t> HkFuncAddrs;

void CollectThreadIDs(IN HANDLE hProcess, OUT std::vector<DWORD>& Threads);
bool HwBpUpdate(std::vector<DWORD>& ThreadIDs);
bool SetExceptionHandler(ExcepHandler_t pFunction = nullptr);
DWORD def_ExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo);
//Page_Guard 
bool Sw_ActivateVehHooks();
//Page_Guard
bool Sw_DeActivateVehHooks();
void SetUpSystemPageSize();

//Example : for HwBP : just fill that 3 array corresponding to ur needs and then just pass the thread ids u want to HwBp apply to , to HwBpUpdate
//Example : for Page_guard/SwBP(0xCC/int3(for now)) : just fill OrgFuncAddrs and HkFuncAddrs and then call SetExceptionHandler(it has a default handler) then call ActivateVehHooks


// sets HwPB in *that thread* to target Address , Condition : Execution (XIP == TargetAddrs) , this require unused HwBp register to set hwBP
void SetHwBP_EH(EXCEPTION_POINTERS* pExceptionInfo, PVOID TargetAddrs);

// Removes HwBP from *that thread* which points to TargetAddrs
void RemoveHwBP_EH(EXCEPTION_POINTERS* pExceptionInfo, PVOID TargetAddrs);


typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

// PEB defined by rewolf
// http://blog.rewolf.pl/blog/?p=573
typedef struct _PEB_LDR_DATA {
	ULONG      Length;
	BOOL       Initialized;
	LPVOID     SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY     InLoadOrderLinks;
	LIST_ENTRY     InMemoryOrderLinks;
	LIST_ENTRY     InInitializationOrderLinks;
	LPVOID         DllBase;
	LPVOID         EntryPoint;
	ULONG          SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
	BYTE                         InheritedAddressSpace;
	BYTE                         ReadImageFileExecOptions;
	BYTE                         BeingDebugged;
	BYTE                         _SYSTEM_DEPENDENT_01;

	LPVOID                       Mutant;
	LPVOID                       ImageBaseAddress;

	PPEB_LDR_DATA                Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	LPVOID                       SubSystemData;
	LPVOID                       ProcessHeap;
	LPVOID                       FastPebLock;
	LPVOID                       _SYSTEM_DEPENDENT_02;
	LPVOID                       _SYSTEM_DEPENDENT_03;
	LPVOID                       _SYSTEM_DEPENDENT_04;
	union {
		LPVOID                     KernelCallbackTable;
		LPVOID                     UserSharedInfoPtr;
	};
	DWORD                        SystemReserved;
	DWORD                        _SYSTEM_DEPENDENT_05;
	LPVOID                       _SYSTEM_DEPENDENT_06;
	LPVOID                       TlsExpansionCounter;
	LPVOID                       TlsBitmap;
	DWORD                        TlsBitmapBits[2];
	LPVOID                       ReadOnlySharedMemoryBase;
	LPVOID                       _SYSTEM_DEPENDENT_07;
	LPVOID                       ReadOnlyStaticServerData;
	LPVOID                       AnsiCodePageData;
	LPVOID                       OemCodePageData;
	LPVOID                       UnicodeCaseTableData;
	DWORD                        NumberOfProcessors;
	union {
		DWORD                      NtGlobalFlag;
		LPVOID                     dummy02;
	};
	LARGE_INTEGER                CriticalSectionTimeout;
	LPVOID                       HeapSegmentReserve;
	LPVOID                       HeapSegmentCommit;
	LPVOID                       HeapDeCommitTotalFreeThreshold;
	LPVOID                       HeapDeCommitFreeBlockThreshold;
	DWORD                        NumberOfHeaps;
	DWORD                        MaximumNumberOfHeaps;
	LPVOID                       ProcessHeaps;
	LPVOID                       GdiSharedHandleTable;
	LPVOID                       ProcessStarterHelper;
	LPVOID                       GdiDCAttributeList;
	LPVOID                       LoaderLock;
	DWORD                        OSMajorVersion;
	DWORD                        OSMinorVersion;
	WORD                         OSBuildNumber;
	WORD                         OSCSDVersion;
	DWORD                        OSPlatformId;
	DWORD                        ImageSubsystem;
	DWORD                        ImageSubsystemMajorVersion;
	LPVOID                       ImageSubsystemMinorVersion;
	union {
		LPVOID                     ImageProcessAffinityMask;
		LPVOID                     ActiveProcessAffinityMask;
	};
#ifdef _WIN64
	LPVOID                       GdiHandleBuffer[64];
#else
	LPVOID                       GdiHandleBuffer[32];
#endif  
	LPVOID                       PostProcessInitRoutine;
	LPVOID                       TlsExpansionBitmap;
	DWORD                        TlsExpansionBitmapBits[32];
	LPVOID                       SessionId;
	ULARGE_INTEGER               AppCompatFlags;
	ULARGE_INTEGER               AppCompatFlagsUser;
	LPVOID                       pShimData;
	LPVOID                       AppCompatInfo;
	PUNICODE_STRING              CSDVersion;
	LPVOID                       ActivationContextData;
	LPVOID                       ProcessAssemblyStorageMap;
	LPVOID                       SystemDefaultActivationContextData;
	LPVOID                       SystemAssemblyStorageMap;
	LPVOID                       MinimumStackCommit;
} PEB, * PPEB;

