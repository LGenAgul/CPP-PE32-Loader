#pragma once
#include <cstdint>
#include <windows.h>
#include <winnt.h>
#include <iostream>

//type defs

using BYTE = unsigned char;
using uint8 = uint8_t;
using uint16 = uint16_t;
using uint32 = uint32_t;
using uint64 = uint64_t;
// structs



struct PARAMS {
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_headers;
	PIMAGE_DATA_DIRECTORY data_directory;
	PIMAGE_FILE_HEADER file_header;
	PIMAGE_OPTIONAL_HEADER64 opt_header;
	PIMAGE_SECTION_HEADER section_header;

	WORD number_of_sections;
	void* BufferInMemory=nullptr;
	DWORD ImageSize=0;
};


struct IMAGE_BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
};

enum ExitCodes {
	Success,
	NotA64BitExe,
	FileNotFoundError,
	MallocError,
	RelocError,
	FixImportError,
	PagePermError,
	ExceptionHandlerError,
	TlsCallbackError
};


