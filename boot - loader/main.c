#include "stdafx.h"

const UINT32 _gUefiDriverRevision = 0x200;
CHAR8 *gEfiCallerBaseName = "";
EFI_STATUS LoadWindows(EFI_HANDLE ImageHandle);

enum WinloadContext
{
	ApplicationContext,
	FirmwareContext
};

QWORD ResolveRelativeAddress(
	QWORD Instruction,
	DWORD OffsetOffset,
	DWORD InstructionSize
)
{

	QWORD Instr = (QWORD)Instruction;
	INT32 RipOffset = *(INT32*)(Instr + OffsetOffset);
	QWORD ResolvedAddr = (QWORD)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}

EFI_EXIT_BOOT_SERVICES oExitBootServices;
EFI_STATUS EFIAPI ExitBootServices(EFI_HANDLE ImageHandle, UINTN MapKey)
{
	gBS->ExitBootServices = oExitBootServices;

	BOOLEAN nmi_blocked = 0;

	QWORD returnAddress = (QWORD)_ReturnAddress();
	while (*(unsigned short*)returnAddress != IMAGE_DOS_SIGNATURE)
		returnAddress = returnAddress - 1;

	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)returnAddress;
	IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((char*)dos + dos->e_lfanew);
	DWORD imageSize = nt->OptionalHeader.SizeOfImage;

	QWORD loaderBlockScan = (QWORD)FindPattern((unsigned char*)returnAddress, imageSize,
		"\x48\x8B\x3D\x00\x00\x00\x00\x48\x8B\x8F\x00\x00\x00\x00", "xxx????xxx????");

	if (loaderBlockScan == 0)
	{
		//
		// 1909
		//

		loaderBlockScan = (UINT64)FindPattern((unsigned char*)returnAddress, imageSize,
			"\x0F\x31\x48\x8B\x3D\x00\x00\x00\x00", "xxxxx????");

		//
		// 1809
		//
		if (loaderBlockScan == 0)
			loaderBlockScan = (UINT64)FindPattern((unsigned char*)returnAddress, imageSize,
				"\x48\x8B\x3D\x00\x00\x00\x00\x48\x8B\xCF", "xxx????xxx");

		//
		// 1607
		//
		if (loaderBlockScan == 0)
			loaderBlockScan = (UINT64)FindPattern((unsigned char*)returnAddress, imageSize,
				"\x48\x8B\x35\x00\x00\x00\x00\x48\x8B\x45\xF7", "xxx????xxxx");

	}

	if (loaderBlockScan == 0)
		goto E0;

	QWORD resolvedAddress = *(QWORD*)((loaderBlockScan + 7) + *(int*)(loaderBlockScan + 3));

	typedef void(__stdcall* BlpArchSwitchContext_t)(int target);
	BlpArchSwitchContext_t BlpArchSwitchContext;

	BlpArchSwitchContext = (BlpArchSwitchContext_t)(FindPattern((unsigned char*)returnAddress, imageSize,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\x15", "xxxxxxxxx"));

	if (BlpArchSwitchContext == 0)
		goto E0;

	BlpArchSwitchContext(ApplicationContext);

	LOADER_PARAMETER_BLOCK *loaderBlock = (LOADER_PARAMETER_BLOCK*)(resolvedAddress);
	KLDR_DATA_TABLE_ENTRY* ntosrknl = GetModuleEntry(&loaderBlock->LoadOrderListHead, L"ntoskrnl.exe");

	// E8 ?? ?? ?? ?? 83 CB FF 48 8B D6
	QWORD pattern_idt = (QWORD)FindPattern((unsigned char*)ntosrknl->ImageBase, ntosrknl->SizeOfImage,
		"\xE8\x00\x00\x00\x00\x83\xCB\xFF\x48\x8B\xD6", "x????xxxxxx");

	if (pattern_idt)
	{
		pattern_idt = ResolveRelativeAddress(pattern_idt, 1, 5); //KiInitializeIdt
		pattern_idt += 0x1a;
		pattern_idt = ResolveRelativeAddress(pattern_idt, 3, 7); //KiInterruptInitTable

		//https://xem.github.io/minix86/manual/intel-x86-and-64-manual-vol3/o_fe12b1e2a880e0ce-220.html
		*(QWORD*)(pattern_idt + 0x38) = *(QWORD*)(pattern_idt + 0x1A0); //KiInterruptInitTable[2].Handler = KiInterruptInitTable[11].Handler(#NP)
		*(QWORD*)(pattern_idt + 0x40) = *(QWORD*)(pattern_idt + 0x1A8); //KiInterruptInitTable[2].ShadowHandler = KiInterruptInitTable[11].ShadowHandler(#NP)

		nmi_blocked = 1;
	}

	BlpArchSwitchContext(FirmwareContext);

E0:

	if (nmi_blocked)
	{
		Print(L"[bootx64.efi] NMI is succesfully blocked\n");
	}
	else
	{
		Print(L"[bootx64.efi] failed to find addresses\n");
	}

	PressAnyKey();

	return oExitBootServices(ImageHandle, MapKey);
}

EFI_STATUS EFIAPI UefiMain(EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable)
{
        gST->ConOut->ClearScreen(gST->ConOut);
        gST->ConOut->SetAttribute(gST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLACK);

	oExitBootServices = gBS->ExitBootServices;
	gBS->ExitBootServices = ExitBootServices;

	EFI_STATUS status = LoadWindows(ImageHandle);
	if (EFI_ERROR(status))
	{
		gBS->ExitBootServices = oExitBootServices;
		PressAnyKey();
		return status;
	}

	return status;
}

EFI_STATUS EFIAPI UefiUnload(EFI_HANDLE ImageHandle)
{
	return 0;
}

// Locates the device path for the Windows bootmgr
EFI_DEVICE_PATH* EFIAPI GetWindowsBootmgrDevicePath()
{
	UINTN handleCount;
	EFI_HANDLE* handles;
	EFI_DEVICE_PATH* devicePath = NULL;

	// Retrieve filesystem handles
	EFI_STATUS status =
		gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid,
			NULL, &handleCount, &handles);

	if (EFI_ERROR(status)) {
		return devicePath;
	}

	// Check each FS for the bootmgr
	for (UINTN i = 0; i < handleCount && !devicePath; ++i) {
		EFI_FILE_IO_INTERFACE* fileSystem;
		status = gBS->OpenProtocol(
			handles[i], &gEfiSimpleFileSystemProtocolGuid, (VOID**)&fileSystem,
			gImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);

		if (EFI_ERROR(status)) {
			continue;
		}

		EFI_FILE_HANDLE volume;
		status = fileSystem->OpenVolume(fileSystem, &volume);
		if (!EFI_ERROR(status)) {
			EFI_FILE_HANDLE file;
			status = volume->Open(volume, &file, L"\\efi\\microsoft\\boot\\bootmgfw.efi",
				EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);

			if (!EFI_ERROR(status)) {
				volume->Close(file);

				devicePath = FileDevicePath(handles[i], L"\\efi\\microsoft\\boot\\bootmgfw.efi");
			}
		}

		gBS->CloseProtocol(handles[i], &gEfiSimpleFileSystemProtocolGuid,
			gImageHandle, NULL);
	}

	gBS->FreePool(handles);
	return devicePath;
}

// Sets BootCurrent to Windows bootmgr option
EFI_STATUS EFIAPI SetBootCurrentToWindowsBootmgr()
{
	// Query boot order array
	UINTN bootOrderSize = 0;
	EFI_STATUS status =
		gRT->GetVariable(EFI_BOOT_ORDER_VARIABLE_NAME, &gEfiGlobalVariableGuid,
			NULL, &bootOrderSize, NULL);

	if (status != EFI_BUFFER_TOO_SMALL) {
		return status;
	}

	UINT16* bootOrder = AllocatePool(bootOrderSize);
	if (!bootOrder) {
		return EFI_OUT_OF_RESOURCES;
	}

	status =
		gRT->GetVariable(EFI_BOOT_ORDER_VARIABLE_NAME, &gEfiGlobalVariableGuid,
			NULL, &bootOrderSize, bootOrder);

	if (EFI_ERROR(status)) {
		FreePool(bootOrder);
		return status;
	}

	// Try each boot option to find Windows boot manager
	BOOLEAN found = FALSE;
	for (UINTN i = 0; i < bootOrderSize / sizeof(bootOrder[0]) && !found; ++i) {
		CHAR16 variableName[0xFF];
		UnicodeSPrint(variableName, sizeof(variableName), L"Boot%04x",
			bootOrder[i]);

		UINTN bufferSize = 0;
		status = gRT->GetVariable(variableName, &gEfiGlobalVariableGuid, NULL,
			&bufferSize, NULL);

		if (status != EFI_BUFFER_TOO_SMALL) {
			break;
		}

		UINT8* buffer = AllocatePool(bufferSize);
		if (!buffer) {
			status = EFI_OUT_OF_RESOURCES;
			break;
		}

		status = gRT->GetVariable(variableName, &gEfiGlobalVariableGuid, NULL,
			&bufferSize, buffer);

		if (EFI_ERROR(status)) {
			FreePool(buffer);
			break;
		}

		// Check the option file path list
		EFI_LOAD_OPTION* bootOption = (EFI_LOAD_OPTION*)buffer;
		CHAR16* bootOptionDescription =
			(CHAR16*)(buffer + sizeof(EFI_LOAD_OPTION));

		EFI_DEVICE_PATH_PROTOCOL* bootOptionPaths =
			(EFI_DEVICE_PATH_PROTOCOL*)(bootOptionDescription +
				StrLen(bootOptionDescription) + 1);

		if (bootOption->FilePathListLength) {
			// Only the first path is needed
			CHAR16* bootOptionPath =
				ConvertDevicePathToText(&bootOptionPaths[0], FALSE, TRUE);

			if (bootOptionPath) {
				// Convert it to lowercase
				for (CHAR16* c = bootOptionPath; *c; ++c) {
					if (*c >= 'A' && *c <= 'Z') {
						*c += ('a' - 'A');
					}
				}

				// Check if it contains the bootmgr path
				if (StrStr(bootOptionPath, L"\\efi\\microsoft\\boot\\bootmgfw.efi")) {
					// If so, update BootCurrent to this option
					status = gRT->SetVariable(EFI_BOOT_CURRENT_VARIABLE_NAME,
						&gEfiGlobalVariableGuid,
						EFI_VARIABLE_BOOTSERVICE_ACCESS |
						EFI_VARIABLE_RUNTIME_ACCESS,
						sizeof(UINT16), &bootOrder[i]);

					if (!EFI_ERROR(status)) {
						found = TRUE;
					}
				}

				FreePool(bootOptionPath);
			}
		}

		FreePool(buffer);
	}

	FreePool(bootOrder);

	if (!EFI_ERROR(status) && !found) {
		status = EFI_NOT_FOUND;
	}

	return status;
}

EFI_STATUS LoadWindows(EFI_HANDLE ImageHandle)
{
	EFI_DEVICE_PATH* bootmgrPath = GetWindowsBootmgrDevicePath();
	if (!bootmgrPath)
	{
		Print(L"Windows UEFI loader not found (0x00), pleace install windows as UEFI\n");
		return EFI_NOT_FOUND;
	}

	EFI_STATUS status = SetBootCurrentToWindowsBootmgr();
	if (EFI_ERROR(status))
	{
		Print(L"Windows UEFI loader not found (0x01), pleace install windows as UEFI\n");
		return EFI_NOT_FOUND;
	}

	EFI_HANDLE bootmgrHandle;
	status = gBS->LoadImage(TRUE, ImageHandle, bootmgrPath, NULL, 0, &bootmgrHandle);

	if (EFI_ERROR(status)) {
		Print(L"Failed to load bootmgfw.efi\n");
		return EFI_NOT_FOUND;
	}

	return gBS->StartImage(bootmgrHandle, NULL, NULL);
}
