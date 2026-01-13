#pragma once
#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include "GLOBALS.h"
#include <vector>

#include <iostream>
#include <iomanip>
#include <algorithm>





class PEIMAGE
{

public:
	
	PARAMS Params = {};
	PEIMAGE(const std::vector<BYTE> &content);
	~PEIMAGE();
	
	bool AllocateMemory(const std::vector<BYTE>& content);
	void CopySectionHeaders(const std::vector<BYTE>& content);
	bool ApplyRelocations();
	bool FixImports();
	bool RegisterExeptionHandlers();
	bool AssignPagePerms();
	bool ProcessTLSCallbacks();
	bool RunCRTInitializers();
	void JumpToEntry();
	/// DEBUG
	bool is_dll = false;
	bool is_64bit = false;
};

