#include "stdafx.h"

VOID MemCopy(VOID* dest, VOID* src, UINTN size)
{
	for (UINT8* d = dest, *s = src; size--; *d++ = *s++)
		;
}

static BOOLEAN CheckMask(unsigned char* base, unsigned char* pattern, unsigned char* mask)
{
	for (; *mask; ++base, ++pattern, ++mask)
		if (*mask == 'x' && *base != *pattern)
			return FALSE;
	return TRUE;
}

VOID* FindPattern(unsigned char* base, UINTN size, unsigned char* pattern, unsigned char* mask)
{
	size -= AsciiStrLen(mask);
	for (UINTN i = 0; i <= size; ++i) {
		VOID* addr = &base[i];
		if (CheckMask(addr, pattern, mask))
			return addr;
	}
	return NULL;
}

VOID* TrampolineHook(VOID* dest, VOID* src, UINT8 original[JMP_SIZE])
{
	if (original)
		MemCopy(original, src, JMP_SIZE);
	MemCopy(src, "\xFF\x25\x00\x00\x00\x00", 6);
	*(VOID**)((UINT8*)src + 6) = dest;
	return src;
}

VOID TrampolineUnHook(VOID* src, UINT8 original[JMP_SIZE])
{
	MemCopy(src, original, JMP_SIZE);
}

INTN
EFIAPI
StrnCmpA(
	IN      CONST CHAR16* FirstString,
	IN      CONST CHAR16* SecondString,
	IN      UINTN                     Length
)
{
	while ((*FirstString != L'\0') &&
		(*SecondString != L'\0') &&
		(AsciiCharToUpper((CHAR8)*FirstString) == AsciiCharToUpper((CHAR8)*SecondString)) &&
		(Length > 1)) {
		FirstString++;
		SecondString++;
		Length--;
	}
	return *FirstString - *SecondString;
}

KLDR_DATA_TABLE_ENTRY* GetModuleEntry(LIST_ENTRY* entry, CHAR16* name)
{
	LIST_ENTRY* list = entry;
	while ((list = list->ForwardLink) != entry) {
		KLDR_DATA_TABLE_ENTRY* module =
			CONTAINING_RECORD(list, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (module && StrnCmpA(name, module->BaseImageName.Buffer,
			module->BaseImageName.Length) == 0) {

			return module;
		}
	}
	return NULL;
}

UINT64 GetExport(QWORD base, CHAR8* export)
{
	QWORD a0;
	DWORD a1[4];

	a0 = base + *(unsigned short*)(base + 0x3C);
	a0 = base + *(DWORD*)(a0 + 0x88);
	a1[0] = *(DWORD*)(a0 + 0x18);
	a1[1] = *(DWORD*)(a0 + 0x1C);
	a1[2] = *(DWORD*)(a0 + 0x20);
	a1[3] = *(DWORD*)(a0 + 0x24);
	while (a1[0]--) {
		a0 = base + *(DWORD*)(base + a1[2] + (a1[0] * 4));
		if (AsciiStrCmp((const CHAR8*)a0, export) == 0) {
			return (base + *(DWORD*)(base + a1[1] +
				(*(unsigned short*)(base + a1[3] + (a1[0] * 2)) * 4)));
		}
	}
	return 0;
}

