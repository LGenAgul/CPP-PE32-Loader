#include "PEIMAGE.h"
#include <cstdio>
#include <cstring>



PEIMAGE::PEIMAGE(const std::vector<BYTE>& content) {
    if (content.size() < sizeof(IMAGE_DOS_HEADER)) return;

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<BYTE*>(content.data()));
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    if (dos->e_lfanew <= 0 ||
        static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > content.size()) return;

    BYTE* base = const_cast<BYTE*>(content.data());
    auto sig  = *reinterpret_cast<DWORD*>(base + dos->e_lfanew);
    if (sig != IMAGE_NT_SIGNATURE) return;

    auto file = reinterpret_cast<PIMAGE_FILE_HEADER>(base + dos->e_lfanew + sizeof(DWORD));
    WORD magic = *reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(file) + sizeof(IMAGE_FILE_HEADER));

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)      is_64bit = true;
    else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) is_64bit = false;
    else return;  // unknown optional header

    Params.dos_header     = dos;
    Params.nt_headers     = base + dos->e_lfanew;
    Params.file_header    = file;

    if (is_64bit) {
        auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(Params.nt_headers);
        Params.data_directory      = nt->OptionalHeader.DataDirectory;
        Params.ImageBase           = nt->OptionalHeader.ImageBase;
        Params.SizeOfImage         = nt->OptionalHeader.SizeOfImage;
        Params.SizeOfHeaders       = nt->OptionalHeader.SizeOfHeaders;
        Params.AddressOfEntryPoint = nt->OptionalHeader.AddressOfEntryPoint;
        Params.section_header      = IMAGE_FIRST_SECTION(nt);
    } else {
        auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS32>(Params.nt_headers);
        Params.data_directory      = nt->OptionalHeader.DataDirectory;
        Params.ImageBase           = nt->OptionalHeader.ImageBase;
        Params.SizeOfImage         = nt->OptionalHeader.SizeOfImage;
        Params.SizeOfHeaders       = nt->OptionalHeader.SizeOfHeaders;
        Params.AddressOfEntryPoint = nt->OptionalHeader.AddressOfEntryPoint;
        Params.section_header      = IMAGE_FIRST_SECTION(nt);
    }

    Params.NumberOfSections = Params.file_header->NumberOfSections;
    is_dll   = (Params.file_header->Characteristics & IMAGE_FILE_DLL) != 0;
    is_valid = true;
}

bool PEIMAGE::AllocateMemory(const std::vector<BYTE>& content) {
    // Try the preferred ImageBase first so we can skip relocations when lucky.
    Params.BufferInMemory = VirtualAlloc(
        reinterpret_cast<LPVOID>(static_cast<uintptr_t>(Params.ImageBase)),
        Params.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

   
    if (!Params.BufferInMemory) {
        Params.BufferInMemory = VirtualAlloc(
            nullptr,
            Params.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
    }
    if (!Params.BufferInMemory) return false;

    ZeroMemory(Params.BufferInMemory, Params.SizeOfImage);
    std::memcpy(Params.BufferInMemory, content.data(), Params.SizeOfHeaders);

    auto* mapped = reinterpret_cast<BYTE*>(Params.BufferInMemory);
    Params.dos_header  = reinterpret_cast<PIMAGE_DOS_HEADER>(mapped);
    Params.nt_headers  = mapped + Params.dos_header->e_lfanew;
    Params.file_header = reinterpret_cast<PIMAGE_FILE_HEADER>(
        static_cast<BYTE*>(Params.nt_headers) + sizeof(DWORD));

    if (is_64bit) {
        auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(Params.nt_headers);
        Params.data_directory = nt->OptionalHeader.DataDirectory;
        Params.section_header = IMAGE_FIRST_SECTION(nt);
    } else {
        auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS32>(Params.nt_headers);
        Params.data_directory = nt->OptionalHeader.DataDirectory;
        Params.section_header = IMAGE_FIRST_SECTION(nt);
    }
    return true;
}

void PEIMAGE::CopySectionHeaders(const std::vector<BYTE>& content) {
    for (WORD i = 0; i < Params.NumberOfSections; ++i) {
        const IMAGE_SECTION_HEADER& s = Params.section_header[i];
        if (s.SizeOfRawData == 0) continue; // .bss-like, already zeroed by ZeroMemory
        std::memcpy(
            static_cast<BYTE*>(Params.BufferInMemory) + s.VirtualAddress,
            content.data() + s.PointerToRawData,
            s.SizeOfRawData
        );
    }
}

bool PEIMAGE::ApplyRelocations() {
    PIMAGE_DATA_DIRECTORY RelocDir = &Params.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (RelocDir->VirtualAddress == 0 || RelocDir->Size == 0) {
        return reinterpret_cast<uintptr_t>(Params.BufferInMemory) ==
               static_cast<uintptr_t>(Params.ImageBase);
    }

    auto*    base  = static_cast<BYTE*>(Params.BufferInMemory);
    intptr_t delta = static_cast<intptr_t>(
        reinterpret_cast<uintptr_t>(base) - static_cast<uintptr_t>(Params.ImageBase));
    if (delta == 0) return true;  

    BYTE* start = base + RelocDir->VirtualAddress;
    BYTE* end   = start + RelocDir->Size;         

    auto* block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(start);
    while (reinterpret_cast<BYTE*>(block) < end && block->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
        size_t entryCount = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto*  entries    = reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(block) + sizeof(IMAGE_BASE_RELOCATION));

        for (size_t i = 0; i < entryCount; ++i) {
            WORD entry  = entries[i];
            WORD type   = entry >> 12;
            WORD offset = entry & 0x0FFF;
            BYTE* patch = base + block->VirtualAddress + offset;

            switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;  
                case IMAGE_REL_BASED_HIGHLOW:   // 32-bit binaries
                    *reinterpret_cast<DWORD*>(patch) += static_cast<DWORD>(delta);
                    break;
                case IMAGE_REL_BASED_DIR64:     // 64-bit binaries
                    *reinterpret_cast<ULONGLONG*>(patch) += static_cast<ULONGLONG>(delta);
                    break;
                case IMAGE_REL_BASED_HIGH:
                    *reinterpret_cast<WORD*>(patch) += HIWORD(delta);
                    break;
                case IMAGE_REL_BASED_LOW:
                    *reinterpret_cast<WORD*>(patch) += LOWORD(delta);
                    break;
                default:
                    // unknown relocation type - bail rather than corrupt memory
                    std::fprintf(stderr, "Unknown reloc type %u\n", type);
                    return false;
            }
        }
        block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<BYTE*>(block) + block->SizeOfBlock);
    }
    return true;
}

bool PEIMAGE::FixImports() {
    PIMAGE_DATA_DIRECTORY ImportDir = &Params.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (ImportDir->VirtualAddress == 0 || ImportDir->Size == 0) {
        return true;  // legitimately no imports
    }

    auto* base = static_cast<BYTE*>(Params.BufferInMemory);
    auto* desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + ImportDir->VirtualAddress);

    while (desc->Name) {
        const char* dllName = reinterpret_cast<const char*>(base + desc->Name);
        HMODULE mod = GetModuleHandleA(dllName);
        if (!mod) mod = LoadLibraryA(dllName);
        if (!mod) {
            std::fprintf(stderr, "LoadLibrary failed for %s\n", dllName);
            return false;
        }

        DWORD lookupRVA = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;

        if (is_64bit) {
            auto* lookup = reinterpret_cast<PIMAGE_THUNK_DATA64>(base + lookupRVA);
            auto* iat    = reinterpret_cast<PIMAGE_THUNK_DATA64>(base + desc->FirstThunk);
            for (; lookup->u1.AddressOfData; ++lookup, ++iat) {
                FARPROC fn = nullptr;
                if (lookup->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    fn = GetProcAddress(mod,
                        MAKEINTRESOURCEA(static_cast<WORD>(IMAGE_ORDINAL64(lookup->u1.Ordinal))));
                } else {
                    auto* ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(base + lookup->u1.AddressOfData);
                    fn = GetProcAddress(mod, reinterpret_cast<LPCSTR>(ibn->Name));
                }
                if (!fn) { std::fprintf(stderr, "GetProcAddress failed in %s\n", dllName); return false; }
                iat->u1.Function = reinterpret_cast<ULONGLONG>(fn);
            }
        } else {
           
            auto* lookup = reinterpret_cast<PIMAGE_THUNK_DATA32>(base + lookupRVA);
            auto* iat    = reinterpret_cast<PIMAGE_THUNK_DATA32>(base + desc->FirstThunk);
            for (; lookup->u1.AddressOfData; ++lookup, ++iat) {
                FARPROC fn = nullptr;
                if (lookup->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                    fn = GetProcAddress(mod,
                        MAKEINTRESOURCEA(static_cast<WORD>(IMAGE_ORDINAL32(lookup->u1.Ordinal))));
                } else {
                    auto* ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(base + lookup->u1.AddressOfData);
                    fn = GetProcAddress(mod, reinterpret_cast<LPCSTR>(ibn->Name));
                }
                if (!fn) { std::fprintf(stderr, "GetProcAddress failed in %s\n", dllName); return false; }
               
                iat->u1.Function = static_cast<DWORD>(reinterpret_cast<uintptr_t>(fn));
            }
        }
        ++desc;
    }
    return true;
}

bool PEIMAGE::RegisterExceptionHandlers() {
    if (!is_64bit) return true;
    PIMAGE_DATA_DIRECTORY ExceptionDir = &Params.data_directory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (ExceptionDir->VirtualAddress == 0 || ExceptionDir->Size == 0) {
        return true;  // perfectly normal for many x64 binaries
    }

#ifdef _WIN64
    auto* fnTable = reinterpret_cast<PRUNTIME_FUNCTION>(
        static_cast<BYTE*>(Params.BufferInMemory) + ExceptionDir->VirtualAddress);
    DWORD entries = ExceptionDir->Size / sizeof(RUNTIME_FUNCTION);
    if (!RtlAddFunctionTable(fnTable, entries,
            reinterpret_cast<DWORD64>(Params.BufferInMemory))) {
        std::fprintf(stderr, "RtlAddFunctionTable failed\n");
        return false;
    }
#endif
    return true;
}

bool PEIMAGE::AssignPagePerms() {
    DWORD oldProt = 0;
    auto* base = static_cast<BYTE*>(Params.BufferInMemory);

    for (WORD i = 0; i < Params.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER& s = Params.section_header[i];
        DWORD c = s.Characteristics;
        bool  R = (c & IMAGE_SCN_MEM_READ)    != 0;
        bool  W = (c & IMAGE_SCN_MEM_WRITE)   != 0;
        bool  X = (c & IMAGE_SCN_MEM_EXECUTE) != 0;

        DWORD prot = PAGE_NOACCESS;
        if      ( X &&  R &&  W) prot = PAGE_EXECUTE_READWRITE;
        else if ( X &&  R)       prot = PAGE_EXECUTE_READ;
        else if ( X)             prot = PAGE_EXECUTE;
        else if ( R &&  W)       prot = PAGE_READWRITE;
        else if ( R)             prot = PAGE_READONLY;

        SIZE_T size = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
        if (size == 0) continue;

        if (!VirtualProtect(base + s.VirtualAddress, size, prot, &oldProt)) {
            std::fprintf(stderr, "VirtualProtect failed on section %u\n", i);
            return false;
        }
    }

    // CRITICAL on x64: flush the I-cache so the CPU doesn't execute stale bytes.
    FlushInstructionCache(GetCurrentProcess(), base, Params.SizeOfImage);
    return true;
}

bool PEIMAGE::ProcessTLSCallbacks() {
    PIMAGE_DATA_DIRECTORY tlsDir = &Params.data_directory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir->VirtualAddress == 0 || tlsDir->Size == 0) return true;

    auto* base = static_cast<BYTE*>(Params.BufferInMemory);

    if (is_64bit) {
        auto* tls = reinterpret_cast<PIMAGE_TLS_DIRECTORY64>(base + tlsDir->VirtualAddress);
        auto** cb = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
        if (!cb) return true;
        for (; *cb; ++cb) (*cb)(Params.BufferInMemory, DLL_PROCESS_ATTACH, nullptr);
    } else {
        auto* tls = reinterpret_cast<PIMAGE_TLS_DIRECTORY32>(base + tlsDir->VirtualAddress);
        auto** cb = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(
            static_cast<uintptr_t>(tls->AddressOfCallBacks));
        if (!cb) return true;
        for (; *cb; ++cb) (*cb)(Params.BufferInMemory, DLL_PROCESS_ATTACH, nullptr);
    }
    return true;
}

void PEIMAGE::JumpToEntry() {
    auto* entry = static_cast<BYTE*>(Params.BufferInMemory) + Params.AddressOfEntryPoint;
    std::printf("[*] Entry = %p\n", entry);

    if (is_dll) {
        using DllMainFn = BOOL (WINAPI*)(HINSTANCE, DWORD, LPVOID);
        auto fn = reinterpret_cast<DllMainFn>(entry);
        fn(static_cast<HINSTANCE>(Params.BufferInMemory), DLL_PROCESS_ATTACH, nullptr);
    } else {
        using ExeFn = int (*)();
        auto fn = reinterpret_cast<ExeFn>(entry);
        fn();
    }
}

PEIMAGE::~PEIMAGE() {
    if (Params.BufferInMemory) {
        VirtualFree(Params.BufferInMemory, 0, MEM_RELEASE);
        Params.BufferInMemory = nullptr;
    }
}
