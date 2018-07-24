#include "pin.h"
#include <iostream>
#include <fstream>
#include <map>

map<ADDRINT, bool> MallocMap;
ofstream LogFile;
KNOB<string> LogFileName(KNOB_MODE_WRITEONCE, "pintool", "o", "memprofile.out", "Memory trace file name");
KNOB<string> EntryPoint(KNOB_MODE_WRITEONCE, "pintool", "entrypoint", "main", "Guest entry-point function");
KNOB<BOOL> EnumSymbols(KNOB_MODE_WRITEONCE, "pintool", "symbols", "0", "List Symbols");
BOOL start_trace = false;

VOID LogBeforeVirtualAlloc(ADDRINT size)
{
	if (!start_trace)
		return;

	LogFile << "[*] VirtualAllocEx(" << dec << size << ")";
}

VOID LogAfterVirtualAlloc(ADDRINT addr)
{
	if (!start_trace)
		return;

	if (addr == NULL)
	{
		cerr << "[-] Error: VirtualAllocEx() return value was NULL.";
		return;
	}

	map<ADDRINT, bool>::iterator it = MallocMap.find(addr);

	if (it != MallocMap.end())
	{
		if (it->second)
			it->second = false;
		else
			cerr << "[-] Error: allocating memory not freed!?!" << endl;
	}
	else
	{
		MallocMap.insert(pair<ADDRINT, bool>(addr, false));
		LogFile << "\t\t= 0x" << hex << addr << endl;
	}
}

VOID LogBeforeVirtualFree(ADDRINT addr)
{
	if (!start_trace)
		return;

	map<ADDRINT, bool>::iterator it = MallocMap.find(addr);

	if (it != MallocMap.end())
	{
		if (it->second)
			LogFile << "[*] Memory at address 0x" << hex << addr << " has been freed more than once (Double Free)." << endl;
		else
		{
			it->second = true;		// Mark it as freed
			LogFile << "[*] VirtualFreeEx(0x" << hex << addr << ")" << endl;
		}
	}
	else
		LogFile << "[*] Freeing unallocated memory at address 0x" << hex << addr << "." << endl;
}

VOID LogBeforeReAlloc(ADDRINT freed_addr, ADDRINT size)
{
	if (!start_trace)
		return;

	// mark freed_addr as free
	map<ADDRINT, bool>::iterator it = MallocMap.find(freed_addr);

	if (it != MallocMap.end())
	{
		it->second = true;
		LogFile << "[*] RtlHeapfree(0x" << hex << freed_addr << ") from RtlHeapRealloc()" << endl;
	}
	else
		LogFile << "[-] RtlHeapRealloc could not find addr to free??? - " << freed_addr << endl;

	LogFile << "[*] RtlHeapReAlloc(" << dec << size << ")";
}

VOID LogAfterReAlloc(ADDRINT addr)
{
	if (!start_trace)
		return;

	if (addr == NULL)
		return;

	map<ADDRINT, bool>::iterator it = MallocMap.find(addr);

	if (it != MallocMap.end())
	{
		if (it->second)
			it->second = false;
		else
			// it already exists because of the HeapAlloc, we don't need to insert... just log it
			LogFile << "\t\t= 0x" << hex << addr << endl;
	}
}

VOID LogBeforeMalloc(ADDRINT size)
{
	if (!start_trace)
		return;

	LogFile << "[*] RtlAllocateHeap(" << dec << size << ")";
}

VOID LogAfterMalloc(ADDRINT addr)
{
	if (!start_trace)
		return;

	if (addr == NULL)
	{
		cerr << "[-] Error: RtlAllocateHeap() return value was NULL.";
		return;
	}

	map<ADDRINT, bool>::iterator it = MallocMap.find(addr);

	if (it != MallocMap.end())
	{
		if (it->second)
			it->second = false;
		else
			cerr << "[-] Error: allocating memory not freed!?!" << endl;
	}
	else
	{
		MallocMap.insert(pair<ADDRINT, bool>(addr, false));
		LogFile << "\t\t= 0x" << hex << addr << endl;
	}
}

VOID LogFree(ADDRINT addr)
{
	if (!start_trace)
		return;

	map<ADDRINT, bool>::iterator it = MallocMap.find(addr);

	if (it != MallocMap.end())
	{
		if (it->second)
			LogFile << "[*] Memory at address 0x" << hex << addr << " has been freed more than once (Double Free)." << endl;
		else
		{
			it->second = true;		// Mark it as freed
			LogFile << "[*] RtlFreeHeap(0x" << hex << addr << ")" << endl;
		}
	}
	else
		LogFile << "[*] Freeing unallocated memory at address 0x" << hex << addr << "." << endl;
}

VOID BeforeMain() {
	start_trace = true;
}
VOID AfterMain() {
	start_trace = false;
}

VOID CustomInstrumentation(IMG img, VOID *v)
{
	for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
	{
		string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);

		if(EnumSymbols.Value())
		{
			LogFile << "" << undFuncName << "" << endl;
			continue;
		}

		if (undFuncName == EntryPoint.Value().c_str())
		{
			RTN allocRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

			if (RTN_Valid(allocRtn))
			{
				RTN_Open(allocRtn);

				RTN_InsertCall(allocRtn, IPOINT_BEFORE, (AFUNPTR)BeforeMain, IARG_END);
				RTN_InsertCall(allocRtn, IPOINT_AFTER, (AFUNPTR)AfterMain, IARG_END);

				RTN_Close(allocRtn);
			}
		}
		if (undFuncName == "RtlAllocateHeap")
		{
			RTN allocRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

			if (RTN_Valid(allocRtn))
			{
				RTN_Open(allocRtn);
				
				// Record RtlAllocateHeap size
				RTN_InsertCall(allocRtn, IPOINT_BEFORE, (AFUNPTR)LogBeforeMalloc,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);

				// Record RtlAllocateHeap return address
				RTN_InsertCall(allocRtn, IPOINT_AFTER, (AFUNPTR)LogAfterMalloc,
					IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
				
				RTN_Close(allocRtn);
			}
		}
		if (undFuncName == "RtlReAllocateHeap")
		{
			RTN reallocRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

			if (RTN_Valid(reallocRtn))
			{
				RTN_Open(reallocRtn);

				// Record RtlReAllocateHeap freed_addr, size
				RTN_InsertCall(reallocRtn, IPOINT_BEFORE, (AFUNPTR)LogBeforeReAlloc,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_END);

				// Record RtlReAllocateHeap return address
				RTN_InsertCall(reallocRtn, IPOINT_AFTER, (AFUNPTR)LogAfterReAlloc,
					IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

				RTN_Close(reallocRtn);
			}
		}
		else if (undFuncName == "RtlFreeHeap")
		{
			RTN freeRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

			if (RTN_Valid(freeRtn))
			{
				RTN_Open(freeRtn);

				RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)LogFree,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
					IARG_END);

				RTN_Close(freeRtn);
			}
		}
		if (undFuncName == "VirtualAllocEx")
		{
			RTN vrallocRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

			if (RTN_Valid(vrallocRtn))
			{
				RTN_Open(vrallocRtn);

				RTN_InsertCall(vrallocRtn, IPOINT_BEFORE, (AFUNPTR)LogBeforeVirtualAlloc,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);

				RTN_InsertCall(vrallocRtn, IPOINT_AFTER, (AFUNPTR)LogAfterVirtualAlloc,
					IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

				RTN_Close(vrallocRtn);
			}
		}
		if (undFuncName == "VirtualFreeEx")
		{
			RTN vrfreeRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

			if (RTN_Valid(vrfreeRtn))
			{
				RTN_Open(vrfreeRtn);

				RTN_InsertCall(vrfreeRtn, IPOINT_BEFORE, (AFUNPTR)LogBeforeVirtualFree,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);

				RTN_Close(vrfreeRtn);
			}
		}
	}
}

VOID FinalFunc(INT32 code, VOID *v)
{
	for (pair<ADDRINT, bool> p : MallocMap)
	{
		if (!p.second)
			LogFile << "[*] Memory at address 0x" << hex << p.first << " allocated but not freed" << endl;
	}

	LogFile.close();
}

int main(int argc, char *argv[])
{
	PIN_InitSymbols();
	PIN_Init(argc, argv);

	LogFile.open(LogFileName.Value().c_str());
	LogFile << "## Memory tracing for PID = " << PIN_GetPid() << " started" << endl;

	if (EnumSymbols.Value())
		LogFile << "### Listing Symbols" << endl;
	else
		LogFile << "### Started tracing after '" << EntryPoint.Value().c_str() << "()' call" << endl;
	
	IMG_AddInstrumentFunction(CustomInstrumentation, NULL);
	PIN_AddFiniFunction(FinalFunc, NULL);
	PIN_StartProgram();

	return 0;
}
