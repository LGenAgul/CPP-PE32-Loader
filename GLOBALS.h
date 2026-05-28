#pragma once
#include <cstdint>
#include <windows.h>
#include <winnt.h>
#include <iostream>

using BYTE   = unsigned char;
using uint8  = uint8_t;
using uint16 = uint16_t;
using uint32 = uint32_t;
using uint64 = uint64_t;


#if defined(_WIN64)
    static constexpr bool kHostIs64Bit = true;
#else
    static constexpr bool kHostIs64Bit = false;
#endif


struct PARAMS {
 
    PIMAGE_DOS_HEADER       dos_header     = nullptr;
    void*                   nt_headers     = nullptr;   
    PIMAGE_FILE_HEADER      file_header    = nullptr;
    PIMAGE_DATA_DIRECTORY   data_directory = nullptr;  
    PIMAGE_SECTION_HEADER   section_header = nullptr;

    ULONGLONG ImageBase           = 0;  
    DWORD     SizeOfImage         = 0;
    DWORD     SizeOfHeaders       = 0;
    DWORD     AddressOfEntryPoint = 0;
    WORD      NumberOfSections    = 0;

    void*     BufferInMemory      = nullptr;
};

enum ExitCodes {
    Success,
    BitnessMismatch,        
    FileNotFoundError,
    BadPEFormat,
    MallocError,
    RelocError,
    FixImportError,
    PagePermError,
    ExceptionHandlerError,
    TlsCallbackError
};
