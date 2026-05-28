#include "DEBUG.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <algorithm>

static void PrintHex64(uint64_t v) {
    std::cout << "0x" << std::hex << v << std::dec;
}

void DEBUG::PrintFileHeader(PIMAGE_FILE_HEADER fh) {
    if (!fh) { std::cout << "FileHeader: NULL\n"; return; }
    std::cout << "FileHeader:\n"
              << "  Machine: 0x"          << std::hex << fh->Machine          << std::dec << "\n"
              << "  NumberOfSections: "   << fh->NumberOfSections   << "\n"
              << "  TimeDateStamp: 0x"    << std::hex << fh->TimeDateStamp    << std::dec << "\n"
              << "  Characteristics: 0x"  << std::hex << fh->Characteristics  << std::dec << "\n";
}

void DEBUG::PrintOptionalHeader32(PIMAGE_OPTIONAL_HEADER32 oh) {
    if (!oh) { std::cout << "OptionalHeader32: NULL\n"; return; }
    std::cout << "OptionalHeader32:\n"
              << "  ImageBase: ";           PrintHex64(oh->ImageBase);           std::cout << "\n"
              << "  AddressOfEntryPoint: 0x" << std::hex << oh->AddressOfEntryPoint << std::dec << "\n"
              << "  SizeOfImage: 0x"        << std::hex << oh->SizeOfImage        << std::dec << "\n";
}

void DEBUG::PrintOptionalHeader64(PIMAGE_OPTIONAL_HEADER64 oh) {
    if (!oh) { std::cout << "OptionalHeader64: NULL\n"; return; }
    std::cout << "OptionalHeader64:\n"
              << "  ImageBase: ";           PrintHex64(oh->ImageBase);           std::cout << "\n"
              << "  AddressOfEntryPoint: 0x" << std::hex << oh->AddressOfEntryPoint << std::dec << "\n"
              << "  SizeOfImage: 0x"        << std::hex << oh->SizeOfImage        << std::dec << "\n";
}

void DEBUG::PrintDataDirectory(const IMAGE_DATA_DIRECTORY* dir, size_t idx) {
    if (!dir) { std::cout << "DataDirectory[" << idx << "] : NULL\n"; return; }
    std::cout << "DataDirectory[" << idx << "] RVA=0x" << std::hex << dir->VirtualAddress
              << " Size=0x" << dir->Size << std::dec << "\n";
}

void DEBUG::PrintSectionHeader(const IMAGE_SECTION_HEADER* s, int i) {
    if (!s) { std::cout << "Section[" << i << "] NULL\n"; return; }
    std::string name(reinterpret_cast<const char*>(s->Name),
                     std::min<size_t>(8, strnlen(reinterpret_cast<const char*>(s->Name), 8)));
    std::cout << "Section[" << i << "] '" << name << "' RVA=0x" << std::hex << s->VirtualAddress
              << " VSize=0x"   << s->Misc.VirtualSize
              << " RawOff=0x"  << s->PointerToRawData
              << " RawSize=0x" << s->SizeOfRawData
              << " Char=0x"    << s->Characteristics << std::dec << "\n";
}

void DEBUG::PrintExeInfo(PARAMS& Params, bool is_64bit) {
    std::cout << "=== PrintExeInfo (" << (is_64bit ? "PE32+" : "PE32") << ") ===\n";
    PrintFileHeader(Params.file_header);

    if (is_64bit) {
        auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(Params.nt_headers);
        PrintOptionalHeader64(&nt->OptionalHeader);
    } else {
        auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS32>(Params.nt_headers);
        PrintOptionalHeader32(&nt->OptionalHeader);
    }

    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
        PrintDataDirectory(&Params.data_directory[i], i);
    }
    for (int i = 0; i < static_cast<int>(Params.NumberOfSections); ++i) {
        PrintSectionHeader(&Params.section_header[i], i);
    }

    uintptr_t loaded    = reinterpret_cast<uintptr_t>(Params.BufferInMemory);
    uintptr_t preferred = static_cast<uintptr_t>(Params.ImageBase);
    intptr_t  delta     = static_cast<intptr_t>(loaded) - static_cast<intptr_t>(preferred);
    std::cout << "LoadedBase: 0x" << std::hex << loaded
              << " PreferredBase: 0x" << preferred
              << " Delta: 0x" << delta << std::dec << "\n";
}
