#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include "GLOBALS.h"
#include "HELPERS.h"
#include "PEIMAGE.h"
#include "DEBUG.h"



int main(int argc, char** argv) {
    std::string filename = (argc > 1) ? argv[1] : "test.exe";

    std::vector<BYTE> data;
    if (!GetFileContent(filename, data)) {
        error("File not found / unreadable", ExitCodes::FileNotFoundError);
    }

    PEIMAGE Image(data);
    if (!Image.is_valid) {
        error("Not a valid PE file", ExitCodes::BadPEFormat);
    }

 
    if (Image.is_64bit != kHostIs64Bit) {
        std::cerr << "[!] PE is " << (Image.is_64bit ? "64-bit" : "32-bit")
                  << " but loader is " << (kHostIs64Bit ? "64-bit" : "32-bit")
                  << ". Build the loader for the matching architecture.\n";
        return ExitCodes::BitnessMismatch;
    }

    if (!Image.AllocateMemory(data))      error("VirtualAlloc failed",      ExitCodes::MallocError);
    Image.CopySectionHeaders(data);
    if (!Image.ApplyRelocations())        error("Relocations failed",        ExitCodes::RelocError);
    if (!Image.FixImports())              error("Import resolution failed",  ExitCodes::FixImportError);
    if (!Image.AssignPagePerms())         error("Setting page perms failed", ExitCodes::PagePermError);
    if (!Image.RegisterExceptionHandlers())
        error("Exception handler reg failed", ExitCodes::ExceptionHandlerError);
    if (!Image.ProcessTLSCallbacks())     error("TLS callbacks failed",      ExitCodes::TlsCallbackError);

    DEBUG::PrintExeInfo(Image.Params, Image.is_64bit);

    Image.JumpToEntry();
    return ExitCodes::Success;
}
