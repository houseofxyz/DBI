#include <windows.h>
#include <stdio.h>

#define PAGELIMIT 80

int my_heap_functions(char *buf) {
	HLOCAL h1 = 0, h2 = 0, h3 = 0, h4 = 0;

	h1 = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 260);

	h2 = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 260);
	
	HeapFree(GetProcessHeap(), 0, h1);

	h3 = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 520);

	h4 = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, h3, 1040);
	
	HeapFree(GetProcessHeap(), 0, h4);
	return 0;
}

int my_virtual_functions(char *buf) {
	LPVOID lpvBase;
	DWORD dwPageSize;
	BOOL bSuccess;
	SYSTEM_INFO sSysInfo;         // Useful information about the system

	GetSystemInfo(&sSysInfo);     // Initialize the structure.
	dwPageSize = sSysInfo.dwPageSize;

	// Reserve pages in the virtual address space of the process.
	lpvBase = VirtualAlloc(
		NULL,                 // System selects address
		PAGELIMIT*dwPageSize, // Size of allocation
		MEM_RESERVE,          // Allocate reserved pages
		PAGE_NOACCESS);       // Protection = no access

	if (lpvBase == NULL)
		exit("VirtualAlloc reserve failed.");

	bSuccess = VirtualFree(
		lpvBase,       // Base address of block
		0,             // Bytes of committed pages
		MEM_RELEASE);  // Decommit the pages

	return 0;
}

int main(void) {
	my_heap_functions("moo");
	my_virtual_functions("moo");

	return 0;
}