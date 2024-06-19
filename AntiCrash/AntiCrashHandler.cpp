#include "pch.h"
#include "AntiCrashHandler.h"
#define ZYDIS_STATIC_BUILD
#include <Zydis/Zydis.h>
#include <Zydis/Decoder.h>
#include <Zydis/DecoderTypes.h>
#include <unordered_map>
#include <iostream>
#include <fstream>
#pragma comment(lib , "Zycore.lib")
#pragma comment(lib , "Zydis.lib")
//#define SafetyCheck


#ifdef SkipLoop
std::unordered_map<size_t, size_t> AccessPerAddr;
#endif // SkipLoop

//DECLSPEC_ALIGN(64)//these two to a cache line others to another
static ZydisDecoder ZD{};
static PVOID Veh_handle{};

DECLSPEC_ALIGN(64)
static size_t Stoped_Crashes{};
static size_t ValidReturnActions{};
static size_t StopCrashActions{};

void SetUpExceptionHandler()
{
	if(!Veh_handle)
	{
#ifdef _WIN64
		ZydisDecoderInit(&ZD, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
		ZydisDecoderInit(&ZD, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);//ZYDIS_MACHINE_MODE_LONG_COMPAT_32
#endif // _WIN64
		Veh_handle = AddVectoredExceptionHandler(0, &AC_ExceptionHandler);
	}
}

void CleanUpExceptionHandler()
{
	// For what ever reason it may called even when the executable is still active (and not exiting)
	//if (Veh_handle)
	//	RemoveVectoredExceptionHandler(Veh_handle);


	if (!Stoped_Crashes)
	{
		return;
	}
	std::ofstream file;
	file.open("AntiCrash.log", std::ofstream::out | std::ofstream::trunc);
	if (file.is_open())
	{
		file << "Number Of Stopped Crashes : " << Stoped_Crashes << '\n';
		file << "Number Of ValidReturnActions : " << ValidReturnActions << '\n';
		file << "Number Of StopCrash(skip inst.) : " << StopCrashActions << '\n';
		file.close();
	}
}

//https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record
LONG WINAPI AC_ExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo)
{
	constexpr size_t AlignMent = (size_t)~(0x3f);//for more assurance bc it may point to the instrution next to the one that throw exception
	auto ExceptionCode = pExceptionInfo->ExceptionRecord->ExceptionCode;
	switch (ExceptionCode)
	{
	case EXCEPTION_ACCESS_VIOLATION:
		if (pExceptionInfo->ContextRecord->XIP  == (uintptr_t)pExceptionInfo->ExceptionRecord->ExceptionInformation[1])//The second array element specifies the virtual address of the inaccessible data.
			if(ValidReturn(pExceptionInfo))// return to previous function
			{
				++ValidReturnActions;
				++Stoped_Crashes;
				return EXCEPTION_CONTINUE_EXECUTION;
			}
	case EXCEPTION_BREAKPOINT://it seems it didnt skips 0xcc/int3 it self and usually after int3 in some dll like ntdll might be a mov data that sets something like flag that shows the error have been happened
		//++pExceptionInfo->ContextRecord->XIP;//(its just the case for 1 byte instructions)
		//return EXCEPTION_CONTINUE_EXECUTION;
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
	case EXCEPTION_ILLEGAL_INSTRUCTION:
	case EXCEPTION_PRIV_INSTRUCTION:
		if(StopCrash(pExceptionInfo))//skip the instructure that cause exception
		{
			++Stoped_Crashes;
			++StopCrashActions;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		
		MessageBoxA(0,"Wasnt Able To Skip Instruction\n Crash might be ahead!\n","Warning",MB_ICONWARNING|MB_OK);
	default:
		return EXCEPTION_CONTINUE_SEARCH;
	}
}

inline bool StopCrash(EXCEPTION_POINTERS* pExceptionInfo)
{
	ZydisDecodedInstruction ZDE{};
	const auto Addr = pExceptionInfo->ContextRecord->XIP;
	//constexpr size_t AddrMask = ~(0xfff);//per page is 4096 bytes Atleast?/right 12bit is offset to page if im not mistaken
	bool result{ false };
	ZyanUSize size{16};// untill end of the page
	//size = Addr & AddrMask;
	//size = Addr - size ;
	//size = 4096 - size ;//based on page size
#ifdef SafetyCheck
	DWORD OldProtect;
	DWORD OldProtect2;
	VirtualProtect((uint8_t*)Addr, size, PAGE_EXECUTE_READ, &OldProtect);
#endif
//#ifdef _WIN64
	//if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, Addr, (const char*)Addr, size, &instructionInfo)))//slower bc of additional actions thats not needed
	if (ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&ZD, (ZydisDecoderContext*)ZYAN_NULL, (const char*)Addr, size, &ZDE)))
	{
		pExceptionInfo->ContextRecord->XIP += ZDE.length;
		result = true;
	}
#ifdef SafetyCheck
	VirtualProtect((uint8_t*)Addr, size, OldProtect, &OldProtect);
#endif

//#else
//	if(ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LEGACY_32,Addr,(const char*)Addr,size,&instructionInfo)))
//	{
//		pExceptionInfo->ContextRecord->XIP += instructionInfo.info.length;
//		result = true;
//	}
//#endif // _WIN64
#ifdef SkipLoop
	if (AccessPerAddr.find(Addr) != AccessPerAddr.end())
	{
		AccessPerAddr[Addr] += 1;
		if (AccessPerAddr[Addr] > 1000000)
			if (CheckDeadLoop(pExceptionInfo))
				pExceptionInfo->ContextRecord->XIP;//backup this
	}
	else
		AccessPerAddr.emplace(Addr, 1);
#endif // SkipLoop
	return result;
}

//not used yet (it might not be good)
// finds conditional jump and set Xip to next instruction(the instruction after conditional jump)
inline bool CheckDeadLoop(EXCEPTION_POINTERS* pExceptionInfo)
{
	auto Addr = pExceptionInfo->ContextRecord->XIP;
	ZydisDisassembledInstruction instructionInfo{ };
	MEMORY_BASIC_INFORMATION mbi{};
	VirtualQuery((PVOID)Addr, &mbi, sizeof(mbi));
	size_t EndOfPage{ (size_t)mbi.BaseAddress + 4096 };
	bool result{false};
#ifdef _WIN64
	while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, Addr, (const char*)Addr, EndOfPage - Addr, &instructionInfo)))
#else
	while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LEGACY_32, Addr, (const char*)Addr, EndOfPage - Addr, &instructionInfo)))
#endif
	{
		/// scan for jumps
		/// je , jne , jge  , jbe , jle , jae , jno , jo , jz , jnz
		/// jb , jnb , jnbe , jg , jl , jnle , ja? , js
		/// jmp
		/// Or just scan for compars (cmp) which sets flag for conditional jump
		///
		bool setXip{false};
		switch ((*(uint8_t*)Addr))
		{
		case 0x0f:// near jumps opcodes prefix
			switch ((*(uint8_t*)(Addr+1)))
			{
			case 0x80:
			case 0x81:
			case 0x82:
			case 0x83:
			case 0x84:
			case 0x85:
			case 0x86:
			case 0x87:
			case 0x88:
			case 0x89:
			case 0x8a:
			case 0x8b:
			case 0x8c:
			case 0x8d:
			case 0x8e:
			case 0x8f:
				result = true;
				setXip = true;
				break;
			default:
				break;
			}
			break;
		case 0x70:// short jump opcodes
		case 0x71:
		case 0x72:
		case 0x73:
		case 0x74:
		case 0x75:
		case 0x76:
		case 0x77:
		case 0x78:
		case 0x79:
		case 0x7a:
		case 0x7b:
		case 0x7c:
		case 0x7d:
		case 0x7e:
		case 0x7f:
			result = true;
			setXip = true;
			break;
		default:
			break;
		}
		Addr += instructionInfo.info.length;
		if ( EndOfPage <= Addr || setXip)
			break;
	}
	if (result)
	{
		pExceptionInfo->ContextRecord->XIP = Addr;
	}
	return result;
}

inline bool ValidReturn(EXCEPTION_POINTERS* pExceptionInfo)
{
	size_t RetAddr = pExceptionInfo->ContextRecord->XBP + sizeof(void*);//return address before previous ebp/rbp
	if (!RetAddr)
		return false;
	//simulate Ret
	pExceptionInfo->ContextRecord->XIP = *(size_t*)RetAddr;//address before previous stack frame // ret

	pExceptionInfo->ContextRecord->XBP = *(size_t*)pExceptionInfo->ContextRecord->XBP;//pop ebx/rbx
	pExceptionInfo->ContextRecord->XSP = pExceptionInfo->ContextRecord->XBP + sizeof(void*);//pop ebx/rbx

	//pExceptionInfo->ContextRecord->XSP = (pExceptionInfo->ContextRecord->XSP + sizeof(void*)) & ~(15ull);
	return true;
}


void Log_AccessViolation(EXCEPTION_POINTERS* pExceptionInfo)
{
	static const auto BaseAddr = (uintptr_t)reinterpret_cast<PPEB>(__readgsdword(0x60))->ImageBaseAddress;// the .exe image base
	
	auto xip = pExceptionInfo->ContextRecord->XIP;
	// the operation with that cause A.V (read,write,execute)
	auto operation = pExceptionInfo->ExceptionRecord->ExceptionInformation[0];
	//address of the location the operation was going to happen(e.g: address of address that was meant to read in to but failed bc A,V)
	auto DstAddr = pExceptionInfo->ExceptionRecord->ExceptionInformation[1];

	auto RVADstAddr = DstAddr - BaseAddr;
	auto RVAxip = xip - BaseAddr;
	/// then the destination you want your debug data to be
}

inline bool RecoverNon_VOLATILE_Registers()
{
	//for now not implemented for this program some clue:
	// RtlVirtualUnwind
	// RtlLookupFunctionEntry
	//	these 2 could be used to retrives non volatile register values be for current function to recover thse might have to be initialized before...
	// or just RtlLookupFunctionEntry to get function frame and disasseble it and scan for changes to non valotile registers and how to recover them
	// or mabe we can use this 	//pExceptionInfo->ContextRecord->LastBranchFromRip or pExceptionInfo->ContextRecord->LastExceptionFromRip
}