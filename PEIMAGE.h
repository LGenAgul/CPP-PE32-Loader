#pragma once
#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include <vector>
#include "GLOBALS.h"

class PEIMAGE {
public:
    PARAMS Params = {};
    bool   is_dll    = false;
    bool   is_64bit  = false;  
    bool   is_valid  = false;   

    explicit PEIMAGE(const std::vector<BYTE>& content);
    ~PEIMAGE();

    bool AllocateMemory(const std::vector<BYTE>& content);
    void CopySectionHeaders(const std::vector<BYTE>& content);
    bool ApplyRelocations();
    bool FixImports();
    bool RegisterExceptionHandlers();
    bool AssignPagePerms();
    bool ProcessTLSCallbacks();
    void JumpToEntry();

private:
    PIMAGE_OPTIONAL_HEADER32 opt32() const {
        return &reinterpret_cast<PIMAGE_NT_HEADERS32>(Params.nt_headers)->OptionalHeader;
    }
    PIMAGE_OPTIONAL_HEADER64 opt64() const {
        return &reinterpret_cast<PIMAGE_NT_HEADERS64>(Params.nt_headers)->OptionalHeader;
    }
};
