#include <iostream>
#include <windows.h>
#include <winnt.h>
#include <fstream>
#include "GLOBALS.h"
#include "HELPERS.h"
#include "PEIMAGE.h"
#include "DEBUG.h"




int main() {
    std::string filename = "powershell.exe";
    std::vector<BYTE> data;

    if (!GetFileContent(filename, data)) {
        error("File not Found",ExitCodes::FileNotFoundError);
    }

    PEIMAGE Image(data);
    if (!Image.is_64bit) {
        return ExitCodes::NotA64BitExe;
    }
    if (!Image.AllocateMemory(data)) {
        error("Could not Allocate Memory",ExitCodes::MallocError);
    };
    Image.CopySectionHeaders(data);

    if (!Image.ApplyRelocations()) {
        error("Failed to apply relocations", ExitCodes::RelocError);
    };
    if (!Image.FixImports()) {
        error("Failed to fix imports", ExitCodes::FixImportError);
    };
    if (!Image.AssignPagePerms()) {
        error("Failed to assign page permissions", ExitCodes::PagePermError);
    };
    if (!Image.RegisterExeptionHandlers()) {
        error("Failed to register exception handlers", ExitCodes::ExceptionHandlerError);
    };

    if (!Image.ProcessTLSCallbacks()) {
        error("Failed to process tls callbacks", ExitCodes::TlsCallbackError);
    };
    Image.RunCRTInitializers();
    DEBUG::PrintExeInfo(Image.Params, Image.is_64bit);

    Image.JumpToEntry();
    return ExitCodes::Success;
}


