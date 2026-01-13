#include "PEIMAGE.h"

extern "C" {
	typedef void(*PVFV)();
	void _initterm(PVFV* pfbegin, PVFV* pfend)
	{
		for (PVFV* p = pfbegin; p < pfend; p++)
		{
			if (*p != nullptr)
				(**p)();
		}
	}
}

PEIMAGE::PEIMAGE(const std::vector<BYTE>& content) 
{
	Params.dos_header = (PIMAGE_DOS_HEADER)content.data();
	Params.nt_headers = (PIMAGE_NT_HEADERS)(content.data()+Params.dos_header->e_lfanew);
	this->is_64bit = Params.nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	auto* nt64 = (PIMAGE_NT_HEADERS)(Params.nt_headers);
	Params.opt_header = &(nt64->OptionalHeader);
	Params.data_directory = Params.opt_header->DataDirectory;
	Params.ImageSize = Params.opt_header->SizeOfImage;
	Params.file_header = &(nt64->FileHeader);
	Params.section_header = IMAGE_FIRST_SECTION(nt64);

	// dll characteristic is the 0x2000 so we AND it with our characteristics variable
	this->is_dll = (Params.file_header->Characteristics & 0x2000) != 0;

}

//void PEIMAGE::PrintExeInfo()
//{
//	printf("%x\n", Params.opt_header64->ImageBase);
//	printf("%x\n",Params.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
//
//}

bool PEIMAGE::AllocateMemory(const std::vector<BYTE>& content)
{
	// need to use thte api allocate function to properly set up the allocation type and protection data
	
	Params.BufferInMemory = VirtualAlloc(
		(LPVOID)Params.opt_header->ImageBase,
		Params.ImageSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	if (Params.BufferInMemory == nullptr) {
		return false;
	}
	// then copy the headers into the newly allocated memory segment
	ZeroMemory(Params.BufferInMemory, Params.opt_header->SizeOfImage);
	memcpy(Params.BufferInMemory, content.data(), Params.opt_header->SizeOfHeaders);
	
	return true;
}

void PEIMAGE::CopySectionHeaders(const std::vector<BYTE>& content)
{
	// now we copy the section data into the apporpriate offsets from the base
	for (uint8 i = 0; i < Params.file_header->NumberOfSections; i++) {
		
		memcpy((BYTE*)Params.BufferInMemory + Params.section_header[i].VirtualAddress, 
			   content.data() + Params.section_header[i].PointerToRawData,
			   Params.section_header[i].SizeOfRawData);
	}
}

bool PEIMAGE::ApplyRelocations()
{
	// first we get the relocation directory from the directory array header
	PIMAGE_DATA_DIRECTORY RelocDir = &(Params.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	// we check if its a valid relocation by checking if the address even exists
	// if not then relocation may not be needed(unlikely), or the binary won't load
	if (RelocDir->VirtualAddress == 0 || RelocDir->Size == 0) {
		printf("Binary doesn't have a relocation table\n");
		return true;
	}
	/* 
	we find where the relocation header is in memory by calculating the address relative to the start of the buffer
	*/
	BYTE* RelocationBase = (BYTE*)Params.BufferInMemory + RelocDir->VirtualAddress;
	/*
	and we get its pointer
	*/
	PIMAGE_BASE_RELOCATION Relocation = PIMAGE_BASE_RELOCATION(RelocationBase);

	DWORD64 ImageBase = Params.opt_header->ImageBase;
	DWORD64 Offset = (DWORD64)Params.BufferInMemory - ImageBase;
	// if the offset is 0 then relocations are not needed since the buffer is in a correct address
	if (Offset == 0) {
		printf("Relocation not needed\n");
		return true;
	}

	while (Relocation && Relocation->SizeOfBlock) {
		PWORD RelocationEntry = reinterpret_cast<PWORD>((BYTE*)Relocation + sizeof(IMAGE_BASE_RELOCATION));
		// we get the number of entires by getting the size of the whole block which contains all entires plus the headers, 
		// we subract the headers, to get the size of entries and divide by the size to get the number
		size_t NumberOfEntries = (Relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_BASE_RELOCATION_ENTRY);
		
		for (size_t i = 0; i < NumberOfEntries; i++) {
			WORD RelocEntry = RelocationEntry[i];
			/*
			first 4 bits is the relocation type(little endian)
			 so we shift 12 times to the right to only get the first 4 bits
			*/
			WORD RelocType = RelocEntry >> 12;
			/*
			 last 12 bits are the offset
			 we care about the rest 12 bits so we mask this WORD with 000000 1111111  to get rid of the first 4 bits
			*/
			WORD RelocOffset = RelocEntry & 0x0FFF;

			BYTE* RelocatedAddress = (BYTE*)Params.BufferInMemory +  Relocation->VirtualAddress + RelocOffset;
			WORD Entry = RelocationEntry[i];

			switch (RelocType) {
			case IMAGE_REL_BASED_HIGH: // 1
				*reinterpret_cast<PWORD>(RelocatedAddress) += HIWORD(Offset);
				break;
			case IMAGE_REL_BASED_LOW: // 2
				*reinterpret_cast<PWORD>(RelocatedAddress) += LOWORD(Offset);
				break;
			case IMAGE_REL_BASED_HIGHLOW: // 4
				*reinterpret_cast<PDWORD>(RelocatedAddress) += (DWORD)(Offset);
				break;
			case IMAGE_REL_BASED_DIR64: // 10
				*reinterpret_cast<PDWORD64>(RelocatedAddress) += (DWORD64)(Offset);
				break;
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			}

		}
		Relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>((BYTE*)Relocation + Relocation->SizeOfBlock);
	}
	return true;
}

bool PEIMAGE::FixImports()
{
	PIMAGE_DATA_DIRECTORY ImportDir = &(Params.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	// we check if its a valid relocation by checking if the address even exists
	// if not then relocation may not be needed(unlikely), or the binary won't load
	if (ImportDir->VirtualAddress == 0 || ImportDir->Size == 0) {
		return false;
	}
	BYTE* ImportBase = (BYTE*)Params.BufferInMemory + ImportDir->VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = PIMAGE_IMPORT_DESCRIPTOR(ImportBase);
	//printf("%i\n", sizeof(ImportDescriptor));

	while (ImportDescriptor->FirstThunk) {
		auto dll = (CHAR*)Params.BufferInMemory + ImportDescriptor->Name;
		HMODULE module = GetModuleHandleA(dll);
		printf("%s\n",dll);
		if (!module) module = LoadLibraryA(dll);

		if (!module) {return false;}


		PIMAGE_THUNK_DATA Lookup = (PIMAGE_THUNK_DATA)((BYTE*)Params.BufferInMemory + ImportDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA IAT = (PIMAGE_THUNK_DATA)((BYTE*)Params.BufferInMemory + ImportDescriptor->FirstThunk);

	

		if (ImportDescriptor->OriginalFirstThunk == 0) Lookup = IAT;

		while (((PIMAGE_THUNK_DATA)Lookup)->u1.AddressOfData) {
			FARPROC FunctionAddress = nullptr;
			if (is_64bit) {
				bool IsOrdinal = (Lookup->u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0;
				if (IsOrdinal)
					FunctionAddress = GetProcAddress(module, MAKEINTRESOURCEA((WORD)IMAGE_ORDINAL(Lookup->u1.Ordinal)));
				else {
					PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)((char*)Params.BufferInMemory + Lookup->u1.AddressOfData);
					FunctionAddress = GetProcAddress(module, (char*)ImportByName->Name);
				}
				IAT->u1.Function = (DWORD64)FunctionAddress;
			}
			Lookup++;
			IAT++;
		}

		ImportDescriptor++;
	}
	return true;
 
}

bool PEIMAGE::RegisterExeptionHandlers()
{
	if (!is_64bit) return true;

	PIMAGE_DATA_DIRECTORY ExceptionDirectory = &Params.data_directory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (ExceptionDirectory && ExceptionDirectory->VirtualAddress != NULL && ExceptionDirectory->Size != 0) {
		PRUNTIME_FUNCTION FunctionTable = (PRUNTIME_FUNCTION)((BYTE*)Params.BufferInMemory + ExceptionDirectory->VirtualAddress);
		printf("%x", FunctionTable);
		if (!RtlAddFunctionTable(
			FunctionTable, // Pointer to exception function table
			(ExceptionDirectory->Size / sizeof(RUNTIME_FUNCTION)), // amount of entires
			(DWORD64)Params.BufferInMemory // Base of the in-mem PE
		)) {
			std::cerr << "Function Table error";
			return false;
		}
		else {
			return true;
		}
	}
	return false;
}


bool PEIMAGE::AssignPagePerms()
{
	DWORD oldProtection = 0;

	// section characteristics are always a 16 bit variable
	for (int i = 0; i < Params.file_header->NumberOfSections; i++) {
		IMAGE_SECTION_HEADER& SectionHeader = Params.section_header[i];

		DWORD newProtection = PAGE_EXECUTE_READWRITE; // default fallback
		DWORD characteristics = SectionHeader.Characteristics;

		if ((characteristics & IMAGE_SCN_MEM_EXECUTE) && (characteristics & IMAGE_SCN_MEM_READ) && (characteristics & IMAGE_SCN_MEM_WRITE))
			newProtection = PAGE_EXECUTE_READWRITE;
		else if ((characteristics & IMAGE_SCN_MEM_EXECUTE) && (characteristics & IMAGE_SCN_MEM_READ))
			newProtection = PAGE_EXECUTE_READ;
		else if ((characteristics & IMAGE_SCN_MEM_EXECUTE))
			newProtection = PAGE_EXECUTE;
		else if ((characteristics & IMAGE_SCN_MEM_READ) && (characteristics & IMAGE_SCN_MEM_WRITE))
			newProtection = PAGE_READWRITE;
		else if ((characteristics & IMAGE_SCN_MEM_READ))
			newProtection = PAGE_READONLY;

		SIZE_T size = SectionHeader.Misc.VirtualSize;
		if (size == 0) size = SectionHeader.SizeOfRawData;

		if (!VirtualProtect((BYTE*)Params.BufferInMemory + SectionHeader.VirtualAddress,
			size,
			newProtection,
			&oldProtection)) {
			std::cerr << "VirtualProtect failed\n";
			return FALSE;
		}
		

	}
	return true;
}

bool PEIMAGE::ProcessTLSCallbacks()
{
	PIMAGE_DATA_DIRECTORY tlsDir = &Params.data_directory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (tlsDir->VirtualAddress == 0 || tlsDir->Size == 0)
		return true;

	BYTE* base = (BYTE*)Params.BufferInMemory;

	if (is_64bit)
	{
		PIMAGE_TLS_DIRECTORY64 tls64 = (PIMAGE_TLS_DIRECTORY64)(base + tlsDir->VirtualAddress);
		auto CallBackArray = (PIMAGE_TLS_CALLBACK*)((BYTE*)base + (tls64->AddressOfCallBacks - Params.opt_header->ImageBase));

		if (!CallBackArray) return true;

		for (int i = 0; CallBackArray[i] != nullptr; i++)
		{
			CallBackArray[i](Params.BufferInMemory, DLL_PROCESS_ATTACH, nullptr);
		}
	}
	return true;
}



bool PEIMAGE::RunCRTInitializers()
{
    BYTE* base = (BYTE*)Params.BufferInMemory;

    for (int i = 0; i < Params.file_header->NumberOfSections; i++)
    {
        IMAGE_SECTION_HEADER& sec = Params.section_header[i];

        // Look for .CRT section
        if (strncmp((char*)sec.Name, ".CRT", 4) == 0)
        {
            PVFV* start = (PVFV*)(base + sec.VirtualAddress);
            PVFV* end = (PVFV*)(base + sec.VirtualAddress + sec.Misc.VirtualSize);
            _initterm(start, end);
        }
    }

    return true;
}

void PEIMAGE::JumpToEntry()
{
	BYTE* Entry = (BYTE*)Params.BufferInMemory + Params.opt_header->AddressOfEntryPoint;
	printf("%x\n", &Entry);

	if (is_dll) {
		// DLL entry: call DllMain
		typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
		DLLMAIN DllEntry = (DLLMAIN)Entry;
		DllEntry((HINSTANCE)Params.BufferInMemory, DLL_PROCESS_ATTACH, NULL);
	}
	else {
		// EXE entry: raw entry point
			typedef void (*EXEENTRY)();
			EXEENTRY ExeEntry = (EXEENTRY)Entry;
			ExeEntry();
	}
}





PEIMAGE::~PEIMAGE() {
	if (Params.BufferInMemory) {
		VirtualFree(Params.BufferInMemory, 0, MEM_RELEASE);
	}
}