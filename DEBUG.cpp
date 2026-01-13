#include "DEBUG.h"



static void PrintHex64(uint64_t v) {
	std::cout << "0x" << std::hex << v << std::dec;
}

void DEBUG::PrintFileHeader(PIMAGE_FILE_HEADER fh) {
	if (!fh) { std::cout << "FileHeader: NULL\n"; return; }
	std::cout << "FileHeader:\n";
	std::cout << "  Machine: 0x" << std::hex << fh->Machine << std::dec << "\n";
	std::cout << "  NumberOfSections: " << fh->NumberOfSections << "\n";
	std::cout << "  TimeDateStamp: 0x" << std::hex << fh->TimeDateStamp << std::dec << "\n";
	std::cout << "  Characteristics: 0x" << std::hex << fh->Characteristics << std::dec << "\n";
}



void DEBUG::PrintOptionalHeader64(PIMAGE_OPTIONAL_HEADER64 oh) {
	if (!oh) { std::cout << "OptionalHeader64: NULL\n"; return; }
	std::cout << "OptionalHeader64:\n";
	std::cout << "  ImageBase: "; PrintHex64(oh->ImageBase); std::cout << "\n";
	std::cout << "  AddressOfEntryPoint: 0x" << std::hex << oh->AddressOfEntryPoint << std::dec << "\n";
	std::cout << "  SizeOfImage: 0x" << std::hex << oh->SizeOfImage << std::dec << "\n";
}

void DEBUG::PrintDataDirectory(const IMAGE_DATA_DIRECTORY* dir, size_t idx) {
	if (!dir) { std::cout << "DataDirectory[" << idx << "] : NULL\n"; return; }
	std::cout << "DataDirectory[" << idx << "] RVA=0x" << std::hex << dir->VirtualAddress
		<< " Size=0x" << dir->Size << std::dec << "\n";
}

void DEBUG::PrintSectionHeader(const IMAGE_SECTION_HEADER* s, int i) {
	if (!s) { std::cout << "Section[" << i << "] NULL\n"; return; }
	std::string name((char*)s->Name, std::min<size_t>(8, strnlen((char*)s->Name, 8)));
	std::cout << "Section[" << i << "] '" << name << "' RVA=0x" << std::hex << s->VirtualAddress
		<< " VSize=0x" << s->Misc.VirtualSize
		<< " RawOff=0x" << s->PointerToRawData
		<< " RawSize=0x" << s->SizeOfRawData
		<< " Char=0x" << s->Characteristics << std::dec << "\n";
}


void DEBUG::PrintExeInfo(PARAMS& Params,bool is_64bit)
{
	std::cout << "=== PrintExeInfo ===\n";
	PrintFileHeader(Params.file_header);
	PrintOptionalHeader64(Params.opt_header);
	// data directories (safe array walk)
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
		PrintDataDirectory(&Params.data_directory[i], i);
	}
	// sections
	for (int i = 0; i < (int)Params.file_header->NumberOfSections; ++i) {
		PrintSectionHeader(&Params.section_header[i], i);
	}

	// print loaded base, preferred base, delta
	uintptr_t loaded = (uintptr_t)Params.BufferInMemory;
	uintptr_t preferred = (uintptr_t)Params.opt_header->ImageBase;
	intptr_t delta = (intptr_t)loaded - (intptr_t)preferred;
	std::cout << "LoadedBase: 0x" << std::hex << loaded
		<< " PreferredBase: 0x" << preferred
		<< " Delta: 0x" << delta << std::dec << "\n";
}
