#pragma once
#include "GLOBALS.h"

class DEBUG
{

public:
	static  void PrintFileHeader(PIMAGE_FILE_HEADER fh);

	static   void PrintOptionalHeader32(PIMAGE_OPTIONAL_HEADER32 oh);

	static   void PrintOptionalHeader64(PIMAGE_OPTIONAL_HEADER64 oh);

	static   void PrintDataDirectory(const IMAGE_DATA_DIRECTORY* dir, size_t idx);

	static   void PrintSectionHeader(const IMAGE_SECTION_HEADER* s, int i);

	static  void PrintExeInfo(PARAMS& Params, bool is_64bit);


};

