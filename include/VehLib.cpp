#include "pch.h"
#include "VehLib.h"
// These HwBPs is triggered when the instruction at that address wants to be executed : Condition = execution b00
CACHE_ALIGN
//HwBps Addresses and do action depending on other 2 array
uintptr_t HwBreakPoints[4]{};

// of any address is set with same indext as triggered address in HwBreakPoints[] this is the address that will be set for next HwBP and when it triggered it restore orginal one
uintptr_t HWBPsReApply[4]{};

// if HwBreakPoints[i] triggered and there is a Address in HWBPsRedirect[i] it will be redirected to that address: Rip == HWBPsRedirect[i]
uintptr_t HWBPsRedirect[4]{};

//Base addresses of pages for Page_Guard_Exceptions to check if its in rage of our page to handle and reapply it if thrown
std::unordered_set<HANDLE> BaseAddresses;

// Queue that if single step thrown if there was an address it will be ReApply(For Page_Guard_Exception)
std::vector<uintptr_t> ReApplyQueue;

//Addresses of Orginal Function you want to hook(For Page_Guard_Exception/SwBPs)
std::vector<uintptr_t> OrgFuncAddrs;

//Addresses of Hk Functions you want to redirect to from OrgFunction : OrgFuncAddrs[i] -> HkFuncAddrs[i] (redirect)(For Page_Guard_Exception/SwBPs)
std::vector<uintptr_t> HkFuncAddrs;

std::vector<DWORD> OldProtection;
//PlaceCC not Ready in this ...
#define PlaceCC 1
#define DEBUG 1
#define Hook_AVEH 1
#ifdef PlaceCC
// collection of Func Ptrs in each Page
std::vector<std::vector<uintptr_t>> FuncsInPages;
// collection of orginal byte codes each pages
std::vector<std::vector<uint8_t*>> AddressOfCC;
std::vector<std::vector<uint8_t>> OrgByteCodes;
//Page Indexes to be restored
std::vector<uint32_t> RestoreQueue;
std::vector<size_t> NumOfAccesses;
#endif

CACHE_ALIGN
// the Function that called when exception thrown be care full to handle the exception u want : HwBps = Exception_Single_Step : SoftwareBPs(0xCC/int3) = Exception_Break_Point ...
	// and also return right Return Value like : EXCEPTION_CONTINUE_EXECUTION or  EXCEPTION_CONTINUE_SEARCH
ExcepHandler_t UserFunction{};
HANDLE ExceptionHandler{};
DWORD PageSize{};
tbb::spin_mutex Lock;
bool GotPageSize{};
// cast function pointer to ExcepHandler_t
//  If Returned False There is another function in place or the ptr is invalid
bool SetExceptionHandler(ExcepHandler_t pFunction )
{
	if (ExceptionHandler)
		return false;
	if (pFunction)
		UserFunction = pFunction;
	else
		UserFunction = (ExcepHandler_t)&def_ExceptionHandler;

	ExceptionHandler = AddVectoredExceptionHandler(true, UserFunction);
	return true;
}
bool Sw_ActivateVehHooks()
{
	if (!PageSize)
	{
		SetUpSystemPageSize();
	}
	for (auto i : OrgFuncAddrs)
	{
		MEMORY_BASIC_INFORMATION mbi;
		VirtualQuery((PVOID)i, &mbi, sizeof(mbi));
		BaseAddresses.insert(mbi.BaseAddress);
		NumOfAccesses.emplace_back();
	}
	uint32_t AppliedHooks{};
	for (PVOID i : BaseAddresses)
	{

#ifdef PlaceCC
		auto& FuncPtrs = FuncsInPages.emplace_back();
		OrgByteCodes.emplace_back();
		AddressOfCC.emplace_back();
		for (uintptr_t p : OrgFuncAddrs)
		{
			if (p >= (uintptr_t)i && p < ((uintptr_t)i) + PageSize)
			{
				FuncPtrs.push_back(p);
			}
		}
#endif
		//Toggle PAGE_GUARD flag on the page
		if (ExceptionHandler && VirtualProtect(i, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &OldProtection.emplace_back()))
		{
#if defined(DEBUG) || defined(PlaceCC)
			++AppliedHooks;
#endif
		}
#ifdef DEBUG
		else
			std::cout << "Function at Page Addrs of " << i << "did not hooked!!\n";
#endif

	}
	return true;
}
bool Sw_DeActivateVehHooks()
{
	uint32_t idx{};
	DWORD dwtmp;
	for (auto i : BaseAddresses)
	{
		VirtualProtect(i, 1, OldProtection[idx], &dwtmp);
		++idx;
	}
	return true;
}
void RemoveExceptionHandler()
{
	if (ExceptionHandler)
		RemoveVectoredExceptionHandler(ExceptionHandler);
	UserFunction = NULL;
	ExceptionHandler = nullptr;
}
void SetUpSystemPageSize()
{
	SYSTEM_INFO si{};
	GetSystemInfo(&si);
	PageSize = si.dwPageSize ? si.dwPageSize : 4096;
}

void CollectThreadIDs(IN HANDLE hProcess,OUT std::vector<DWORD>& Threads)
{
	HPSS hSnapshot;
	DWORD CurrentThread{ GetCurrentThreadId() };
	//PssCaptureSnapshot(GetCurrentProcess(), PSS_CAPTURE_THREADS, 0, &hSnapshot);
	DWORD error = PssCaptureSnapshot(hProcess, PSS_CAPTURE_THREADS, 0, &hSnapshot);

	HPSSWALK hWalk;
	if (ERROR_SUCCESS == PssWalkMarkerCreate(nullptr, &hWalk)) {
		PSS_THREAD_ENTRY thread;
		while (ERROR_SUCCESS == PssWalkSnapshot(hSnapshot, PSS_WALK_THREADS, hWalk, &thread, sizeof(thread)))
		{
			if (CurrentThread == thread.ThreadId)
				continue;
			Threads.push_back(thread.ThreadId);
			// OpenThread(THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT, 0, thread.ThreadId)
		}
		PssWalkMarkerFree(hWalk);
	}
	PssFreeSnapshot(GetCurrentProcess(), hSnapshot);
}

bool HwBreakPointHandler(EXCEPTION_POINTERS* pExceptionInfo)
{
	auto Rip = pExceptionInfo->ContextRecord->Rip;
	for (uint32_t i = 0; i < 4; ++i)
	{
		if (HwBreakPoints[i] == Rip)
		{// redirect or swap
			if (HWBPsReApply[i])//swap breakpoint
			{
				if (pExceptionInfo->ContextRecord->Dr0 == HwBreakPoints[i])
					pExceptionInfo->ContextRecord->Dr0 = HWBPsReApply[i];
				else if (pExceptionInfo->ContextRecord->Dr1 == HwBreakPoints[i])
					pExceptionInfo->ContextRecord->Dr1 = HWBPsReApply[i];
				else if (pExceptionInfo->ContextRecord->Dr2 == HwBreakPoints[i])
					pExceptionInfo->ContextRecord->Dr2 = HWBPsReApply[i];
				else if (pExceptionInfo->ContextRecord->Dr3 == HwBreakPoints[i])
					pExceptionInfo->ContextRecord->Dr3 = HWBPsReApply[i];
				return true;
			}
			else//redirect execution
			{
				if (HWBPsRedirect[i])
				{
					pExceptionInfo->ContextRecord->Rip = HWBPsRedirect[i];
					return true;
				}
			}
		}
		else if (HWBPsReApply[i] == Rip)
		{
			if (pExceptionInfo->ContextRecord->Dr0 == HWBPsReApply[i])
				pExceptionInfo->ContextRecord->Dr0 = HwBreakPoints[i];
			else if (pExceptionInfo->ContextRecord->Dr1 == HWBPsReApply[i])
				pExceptionInfo->ContextRecord->Dr1 = HwBreakPoints[i];
			else if (pExceptionInfo->ContextRecord->Dr2 == HWBPsReApply[i])
				pExceptionInfo->ContextRecord->Dr2 = HwBreakPoints[i];
			else if (pExceptionInfo->ContextRecord->Dr3 == HWBPsReApply[i])
				pExceptionInfo->ContextRecord->Dr3 = HwBreakPoints[i];

			return true;
		}
	}
	return false;
}
inline bool HwBpUpdate(std::vector<DWORD>& ThreadIDs)
{	
	DWORD CurrentThreadId = GetCurrentThreadId();
	for (uint32_t c = 0; c < ThreadIDs.size(); ++c)
	{
		auto ThID = ThreadIDs[c];
		if (ThID == CurrentThreadId)// prevent freezes /// btw CollectThreadIds function filter current thread ID from list
			continue;
		auto th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT, 0, ThID);
		if (!th)
			continue;
		SuspendThread(th);
		CONTEXT ctx;
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if (!GetThreadContext(th, &ctx))
		{
#ifdef DEBUG
			std::cout << " Wasn't able to Get Context Of Thread : " << std::hex << th << '\n' << std::dec;
#endif // DEBUG
			continue;
		}
		uint32_t RegIdx{ 0 };
		for (uint32_t idx = 0; idx < (sizeof(HwBreakPoints) / sizeof(void*)); ++idx)
		{
			if (!HwBreakPoints[idx])
				continue;
			bool foundReg{ false };
			for (RegIdx; RegIdx < 4; ++RegIdx)
			{
				if (!(ctx.Dr7 & (1ull << (RegIdx * 2))))// there was a bug
				{
					foundReg = true;
					break;
				}
			}
			if (foundReg)
			{
				switch (RegIdx)
				{
				case 0:
					ctx.Dr0 = HwBreakPoints[idx];
					break;
				case 1:
					ctx.Dr1 = HwBreakPoints[idx];
					break;
				case 2:
					ctx.Dr2 = HwBreakPoints[idx];
					break;
				case 3:
					ctx.Dr3 = HwBreakPoints[idx];
					break;
				}
				ctx.Dr7 &= ~(3ULL << (16 + 4 * RegIdx)); //00b at 16-17, 20-21, 24-25, 28-29 is execute bp//break condition / execute = 00b / write = 01b / read&write= 11b / I/O reads and writes(only defined if CR4.DE = 1) = 10b
				ctx.Dr7 &= ~(3ULL << (18 + 4 * RegIdx)); // size of 1 (val 0), at 18-19, 22-23, 26-27, 30-31 // 1 byte break point = 00b / 2 byte = 01b / 4byte= 11b / 8byte = 10b
				ctx.Dr7 |= 1ULL << (2 * RegIdx);
			}
		}
		SetThreadContext(th, &ctx);
		ResumeThread(th);
		CloseHandle(th);
	}
	return true;
}

DWORD def_ExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo)
{
#ifdef Hook_AVEH
	static uintptr_t RetAddr{};
	static uint8_t RetAVEHOrg{};// orginal byte code of ret address for AVEH
#endif
	const auto ExceptionCode = pExceptionInfo->ExceptionRecord->ExceptionCode;
	if (ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		MEMORY_BASIC_INFORMATION mbi;
		VirtualQuery((PVOID)pExceptionInfo->ContextRecord->Rip, &mbi, sizeof(mbi));
		for (PVOID i : BaseAddresses)
		{
			if (mbi.BaseAddress == i)
			{
				for (uint32_t j = 0; j < OrgFuncAddrs.size(); ++j)
				{
					if (pExceptionInfo->ContextRecord->Rip == OrgFuncAddrs[j]) //Make sure we are at the address we want within the page
					{
						pExceptionInfo->ContextRecord->Rip = HkFuncAddrs[j]; //Modify EIP/RIP to where we want to jump to instead of the original function
#ifdef DEBUG
#ifdef DEBUGALL
						std::cout << "+ ExceptionHandler: Matches One of OrgFuncs 0xCC !!\n";
#endif //DEBUGALL
						++NumOfAccesses[j];
#endif
						return EXCEPTION_CONTINUE_EXECUTION; //Continue to next instruction
					}
				}
				break;
				return EXCEPTION_CONTINUE_EXECUTION; //Continue to next instruction
			}
		}
#ifdef DEBUG
#ifdef DEBUGALL
		std::cout << "ExceptionHandler Just 0xCC !!\n";
#endif //DEBUGALL
#endif
#ifdef Hook_AVEH
		if (pExceptionInfo->ContextRecord->Rip == RetAddr + 1 || pExceptionInfo->ContextRecord->Rip == RetAddr)
		{
			pExceptionInfo->ContextRecord->Rip = RetAddr;
			DWORD dwOld;
			DWORD dwTMP;
			//restore orginal byte code
			VirtualProtect((void*)RetAddr, 1, PAGE_EXECUTE_READWRITE, &dwOld);
			(*(uint8_t*)RetAddr) = RetAVEHOrg;
			VirtualProtect((void*)RetAddr, 1, dwOld, &dwTMP);

			RetAddr = 0;
			// re apply AVEH PageGuard
			VirtualProtect((LPVOID)&AddVectoredExceptionHandler, 1/*ToNotMessUpWithAnotherPage*/, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOld);
			return EXCEPTION_CONTINUE_EXECUTION;
		}
#endif
	}
	// this might be thrown as GUARD_PAGE_VOILATION if any thing in same page(4096) has been accessed
	else if (ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) //We will catch PAGE_GUARD Violation
	{
		MEMORY_BASIC_INFORMATION mbi;
		VirtualQuery((PVOID)pExceptionInfo->ContextRecord->Rip, &mbi, sizeof(mbi));
#ifdef PlaceCC
		uint32_t PageIndex{};
#endif
		for (PVOID i : BaseAddresses)
		{
			if (mbi.BaseAddress == i)
			{
				for (uint32_t j = 0; j < OrgFuncAddrs.size(); ++j)
				{
					if (pExceptionInfo->ContextRecord->Rip == OrgFuncAddrs[j]) //Make sure we are at the address we want within the page
					{
#ifdef PlaceCC
						DWORD Temp;
						DWORD oldp;
						VirtualProtect((void*)i, 1, PAGE_EXECUTE_READWRITE, &oldp);
						//getting first orginal function ptr index which in the page and iterating and place 0xCC in address of any
						//  function that has been accessed more than 3 times
						size_t FuncptrInPageIdx{ };
						for (uint32_t k = 0; k < PageIndex; ++k)
						{
							FuncptrInPageIdx += FuncsInPages[k].size();
						}
						Lock.lock();
						for (auto p : FuncsInPages[PageIndex])
						{// for every function in that page Do...
							//Backup Bytes
							if (NumOfAccesses[FuncptrInPageIdx] >= 4 || FuncptrInPageIdx == j)//if the function is frequently accessed then place cc
							{
								OrgByteCodes[PageIndex].push_back(*(uint8_t*)p);
								AddressOfCC[PageIndex].push_back((uint8_t*)p);
								//Write 0xCC (software breakpoint / aka int 3)
								(*(uint8_t*)p) = 0xCC;//1byte of 0xCC aka int 3
							}
							++FuncptrInPageIdx;
						}
						Lock.unlock();
						VirtualProtect((void*)i, 1, oldp, &Temp);
#endif
						pExceptionInfo->ContextRecord->Rip = HkFuncAddrs[j]; //Modify EIP/RIP to where we want to jump to instead of the original function
						Lock.lock();
						ReApplyQueue.push_back((uintptr_t)i);// push to queue for ReApply
						Lock.unlock();
#ifdef PlaceCC
						RestoreQueue.push_back(PageIndex);
#endif
#ifdef DEBUG
#ifdef DEBUGALL
						std::cout << "+ ExceptionHandler: Matches One of OrgFuncs !!\n";
#endif //DEBUGALL
						++NumOfAccesses[j];
#endif
						pExceptionInfo->ContextRecord->EFlags |= 0x100; //Will trigger an STATUS_SINGLE_STEP exception right after the next instruction get executed. In short, we come right back into this exception handler 1 instruction later
						return EXCEPTION_CONTINUE_EXECUTION; //Continue to next instruction
					}
				}
#ifdef Hook_AVEH
				// just hope RetAddr and AVEH function isnt in a same page and RetAddr Page IsOK
				if (pExceptionInfo->ContextRecord->Rip == (uintptr_t)&AddVectoredExceptionHandler)
				{
					pExceptionInfo->ContextRecord->Rcx = 0;
					RetAddr = (*((size_t*)pExceptionInfo->ContextRecord->Rsp));//reading ret address
					RetAVEHOrg = *(uint8_t*)RetAddr;// backup orginal byte code
					DWORD dwold;
					DWORD dwtmp;
					VirtualProtect((void*)RetAddr, 1, PAGE_EXECUTE_READWRITE, &dwold);
					(*(uint8_t*)RetAddr) = 0xCC;
					VirtualProtect((void*)RetAddr, 1, dwold, &dwtmp);

					return EXCEPTION_CONTINUE_EXECUTION; //Continue to next instruction
				}
#endif
#ifdef DEBUG
#ifdef DEBUGALL
				std::cout << "ExceptionHandler Just ReApplying !!\n";
#endif //DEBUGALL
#endif
				Lock.lock();
				ReApplyQueue.push_back((uintptr_t)i);// push to queue for ReApply
				Lock.unlock();
				pExceptionInfo->ContextRecord->EFlags |= 0x100; //Will trigger an STATUS_SINGLE_STEP exception right after the next instruction get executed. In short, we come right back into this exception handler 1 instruction later
				return EXCEPTION_CONTINUE_EXECUTION; //Continue to next instruction
			}
#ifdef PlaceCC
			++PageIndex;
#endif
		}
		//pExceptionInfo->ExceptionRecord->ExceptionAddress;// where caused the exception in code maybe?
		bool IsInRange{ false };
		for (auto i : BaseAddresses)
		{
			if (i <= (PVOID)pExceptionInfo->ContextRecord->Rdi && ((uintptr_t)i) + PageSize > pExceptionInfo->ContextRecord->Rdi)
			{
				IsInRange = true;
			}
			else if (i <= (PVOID)pExceptionInfo->ContextRecord->Rsi && (((uintptr_t)i) + PageSize) > pExceptionInfo->ContextRecord->Rsi)
			{
				IsInRange = true;
			}
			else if (i <= (PVOID)pExceptionInfo->ContextRecord->Rdx && (((uintptr_t)i) + PageSize) > pExceptionInfo->ContextRecord->Rdi)
			{
				IsInRange = true;
			}
			else if (i <= (PVOID)pExceptionInfo->ContextRecord->Rbx && (((uintptr_t)i) + PageSize) > pExceptionInfo->ContextRecord->Rbx)
			{
				IsInRange = true;
			}
			else if (i <= (PVOID)pExceptionInfo->ContextRecord->Rcx && (((uintptr_t)i) + PageSize) > pExceptionInfo->ContextRecord->Rcx)
			{
				IsInRange = true;
			}
			else if (i <= (PVOID)pExceptionInfo->ContextRecord->R8 && (((uintptr_t)i) + PageSize) > pExceptionInfo->ContextRecord->R8)
			{
				IsInRange = true;
			}
			else if (i <= (PVOID)pExceptionInfo->ContextRecord->R9 && (((uintptr_t)i) + PageSize) > pExceptionInfo->ContextRecord->R9)
			{
				IsInRange = true;
			}
			else if (i <= (PVOID)pExceptionInfo->ContextRecord->R10 && (((uintptr_t)i) + PageSize) > pExceptionInfo->ContextRecord->R10)
			{
				IsInRange = true;
			}
			else if (i <= (PVOID)pExceptionInfo->ContextRecord->R11 && (((uintptr_t)i) + PageSize) > pExceptionInfo->ContextRecord->R11)
			{
				IsInRange = true;
			}
			else if (i <= (PVOID)pExceptionInfo->ContextRecord->R12 && (((uintptr_t)i) + PageSize) > pExceptionInfo->ContextRecord->R12)
			{
				IsInRange = true;
			}
			else if (i <= (PVOID)pExceptionInfo->ContextRecord->R13 && (((uintptr_t)i) + PageSize) > pExceptionInfo->ContextRecord->R13)
			{
				IsInRange = true;
			}
			else if (i <= (PVOID)pExceptionInfo->ContextRecord->R14 && (((uintptr_t)i) + PageSize) > pExceptionInfo->ContextRecord->R14)
			{
				IsInRange = true;
			}
			else if (i <= (PVOID)pExceptionInfo->ContextRecord->R15 && (((uintptr_t)i) + PageSize) > pExceptionInfo->ContextRecord->R15)
			{
				IsInRange = true;
			}
			else if (i <= (PVOID)pExceptionInfo->ContextRecord->Rax && (((uintptr_t)i) + PageSize) > pExceptionInfo->ContextRecord->Rax)
			{
				IsInRange = true;
			}

			if (IsInRange)
			{
				Lock.lock();
				ReApplyQueue.push_back((uintptr_t)i);// push to queue for ReApply
				Lock.unlock();

				pExceptionInfo->ContextRecord->EFlags |= 0x100;
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
	}
	else if (ExceptionCode == STATUS_SINGLE_STEP) //We will also catch STATUS_SINGLE_STEP, meaning we just had a PAGE_GUARD violation
	{
		if (HwBreakPointHandler(pExceptionInfo))
			return EXCEPTION_CONTINUE_EXECUTION;
		if (ReApplyQueue.size())
		{
			DWORD dwOld;
			Lock.lock();
			auto Ptr = ReApplyQueue.back();
			ReApplyQueue.pop_back();
			Lock.unlock();
#ifdef PlaceCC
			if (RestoreQueue.size())
			{
				uint32_t Pageindex = RestoreQueue.back();
				/**/
				uint32_t index1{};
				for (auto i : BaseAddresses)
				{
					if (Pageindex == index1)
					{
						if (i != (void*)Ptr)
						{
							goto SKIP_RESTORE;
						}
						else
						{
							break;
						}
					}
					++index1;
				}
				/**/
				RestoreQueue.pop_back();
				uint32_t index{};
				DWORD oldP;
				Lock.lock();
				// what ever the size it apply the protection to whole page if u give size that exceeds 1 page size it may change other pages too
				VirtualProtect((void*)FuncsInPages[Pageindex][0], 1, PAGE_EXECUTE_READWRITE, &oldP);
				for (auto p : AddressOfCC[Pageindex])
				{
					(*(uint8_t*)p) = OrgByteCodes[Pageindex][index];
					++index;
				}
				VirtualProtect((void*)FuncsInPages[Pageindex][0], 1, oldP, &dwOld);// maybe no need for this?

				OrgByteCodes[Pageindex].clear();
				AddressOfCC[Pageindex].clear();
				Lock.unlock();
			}
		SKIP_RESTORE:
#endif

			if (!VirtualProtect((LPVOID)Ptr, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOld))//Reapply the PAGE_GUARD flag because everytime it is triggered, it get removes
				if (GetLastError() == STATUS_GUARD_PAGE_VIOLATION)
					VirtualProtect((LPVOID)Ptr, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOld);
		}
		return EXCEPTION_CONTINUE_EXECUTION; //Continue the next instruction
	}

	return EXCEPTION_CONTINUE_SEARCH; //Keep going down the exception handling list to find the right handler IF it is not PAGE_GUARD nor SINGLE_STEP
}

void Def_HwBpUpdater() 
{
	static std::vector<DWORD> OldThreadIds;
	static std::vector<DWORD> ThreadsIds;
	static std::vector<DWORD> ThreadsToApply;
	CollectThreadIDs(GetCurrentProcess(), ThreadsIds);

	//filtering the threads that BPs has been applied
	for (auto t : ThreadsIds)
	{
		bool IsApplied{ false };
		for (auto oldT : OldThreadIds)
		{
			if (oldT == t)
			{
				IsApplied = true;
				break;
			}
		}
		if (!IsApplied)
		{
			ThreadsToApply.emplace_back(t);
		}
	}

	HwBpUpdate(ThreadsToApply);
	ThreadsToApply.clear();
	ThreadsIds.swap(OldThreadIds);
	ThreadsIds.clear();
}

void SetHwBP_EH(EXCEPTION_POINTERS* pExceptionInfo,PVOID TargetAddrs )
{
	auto dr7 = pExceptionInfo->ContextRecord->Dr7;
	uint32_t regIdx = 0;
	for (uint32_t i = 0; i < 4; ++i)
	{
		bool freeReg{ false };
		for (; regIdx < 4; ++regIdx) {
			if ((dr7 & (1ULL << (regIdx * 2))) == 0) {
				freeReg = true;
				break;
			}
		}
		if (freeReg)
		{
			switch (regIdx)
			{
			case 0:
				pExceptionInfo->ContextRecord->Dr0 = (uintptr_t)TargetAddrs;
				break;
			case 1:
				pExceptionInfo->ContextRecord->Dr1 = (uintptr_t)TargetAddrs;
				break;
			case 2:
				pExceptionInfo->ContextRecord->Dr2 = (uintptr_t)TargetAddrs;
				break;
			case 3:
				pExceptionInfo->ContextRecord->Dr3 = (uintptr_t)TargetAddrs;
				break;
			default:
				break;
			}
			dr7 &= ~(3ULL << (16 + 4 * regIdx)); //00b at 16-17, 20-21, 24-25, 28-29 is execute bp//break condition / execute = 00b / write = 01b / read&write= 11b / I/O reads and writes(only defined if CR4.DE = 1) = 10b
			dr7 &= ~(3ULL << (18 + 4 * regIdx)); // size of 1 (val 0), at 18-19, 22-23, 26-27, 30-31 // 1 byte break point = 00b / 2 byte = 01b / 4byte= 11b / 8byte = 10b
			dr7 |= 1ULL << (2 * regIdx);
			//execute break point throw exception before executing it aka = Rip == Place where it has been thrown
		}
#ifdef DEBUG
		else
		{
			std::cout << "- Index: " << i << "of HwBreakPoints[] isnt set to DebugRegister, BC its in use. \n";
		}
#endif
	}
	pExceptionInfo->ContextRecord->Dr7 = dr7;
}

void RemoveHwBP_EH(EXCEPTION_POINTERS* pExceptionInfo, PVOID TargetAddrs)
{
	auto dr7 = pExceptionInfo->ContextRecord->Dr7;
	uint32_t regIdx = 0;
	for (uint32_t i = 0; i < 4; ++i)
	{
		bool EnabledReg{ false };
		for (; regIdx < 4; ++regIdx) {
			if ((dr7 & (1ULL << (regIdx * 2)))) {
				EnabledReg = true;
				break;
			}
		}
		if (EnabledReg)
		{
			switch (regIdx)
			{
			case 0:
				if (pExceptionInfo->ContextRecord->Dr0 == (uintptr_t)TargetAddrs)
				{
					pExceptionInfo->ContextRecord->Dr0 = (size_t)0;
					dr7 &= ~(1ULL << (2 * regIdx));
				}
				break;
			case 1:
				if (pExceptionInfo->ContextRecord->Dr1 == (uintptr_t)TargetAddrs)
				{
					pExceptionInfo->ContextRecord->Dr1 = (size_t)0;
					dr7 &= ~(1ULL << (2 * regIdx));
				}
				break;
			case 2:
				if (pExceptionInfo->ContextRecord->Dr2 == (uintptr_t)TargetAddrs)
				{
					pExceptionInfo->ContextRecord->Dr2 = (size_t)0;
					dr7 &= ~(1ULL << (2 * regIdx));
				}
				break;
			case 3:
				if (pExceptionInfo->ContextRecord->Dr3 == (uintptr_t)TargetAddrs)
				{
					pExceptionInfo->ContextRecord->Dr3 = (size_t)0;
					dr7 &= ~(1ULL << (2 * regIdx));
				}
				break;
			default:
				break;
			}
		}
	}
	pExceptionInfo->ContextRecord->Dr7 = dr7;
}