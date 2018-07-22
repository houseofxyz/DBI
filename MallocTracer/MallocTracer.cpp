// Built on top of https://software.intel.com/sites/default/files/managed/62/f4/cgo2013.pdf (slide 33)

#include "pin.h"
#include <iostream>
#include <fstream>
#include <map>

map<ADDRINT, bool> MallocMap;
ofstream LogFile;
KNOB<string> LogFileName(KNOB_MODE_WRITEONCE, "pintool", "o", "memprofile.out", "Memory trace file name");

VOID LogAfterMalloc(ADDRINT addr)
{
	if (addr == NULL)
	{
		cerr << "[-] Error: malloc() return value was NULL.";
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

VOID LogBeforeMalloc(ADDRINT size)
{
	LogFile << "[*] malloc(" << dec << size << ")";
}

VOID LogFree(ADDRINT addr) 
{
	map<ADDRINT, bool>::iterator it = MallocMap.find(addr);

	if (it != MallocMap.end()) 
	{
		if (it->second) 
			LogFile << "[*] Memory at address 0x" << hex << addr << " has been freed more than once (Double Free)."  << endl;
		else 
		{
			it->second = true;		// Mark it as freed
			LogFile << "[*] free(0x" << hex << addr << ")" << endl;
		}
	}
	else 
		LogFile << "[*] Freeing unallocated memory at address 0x"	<< hex << addr << "." << endl;
}

VOID CustomInstrumentation(IMG img, VOID *v)
{
	for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
	{
		string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);

		if (undFuncName == "malloc")
		{
			RTN allocRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
			
			if (RTN_Valid(allocRtn))
			{
				RTN_Open(allocRtn);

				// Record Malloc size
				RTN_InsertCall(allocRtn, IPOINT_BEFORE, (AFUNPTR)LogBeforeMalloc,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);

				// Record Malloc return address
				RTN_InsertCall(allocRtn, IPOINT_AFTER, (AFUNPTR)LogAfterMalloc,
					IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

				RTN_Close(allocRtn);
			}
		}
		else if (undFuncName == "free")
		{
			RTN freeRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

			if (RTN_Valid(freeRtn))
			{
				RTN_Open(freeRtn);

				RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)LogFree,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0,	// address
					IARG_END);

				RTN_Close(freeRtn);
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
	IMG_AddInstrumentFunction(CustomInstrumentation, NULL);
	PIN_AddFiniFunction(FinalFunc, NULL);
	PIN_StartProgram();

	return 0;
}
