# ManualPE: In-Memory PE32+ Loader
 A lightweight, educational C++ implementation of a Windows manual mapper. This tool loads 64-bit (PE32+) executable files directly into memory, bypasses the standard Windows loader (ntdll!LdrLoadDll), and executes the entry point.

#  Features
Manual Mapping: Parses the PE header and maps sections into a newly allocated memory buffer.

Base Relocation: Corrects absolute addresses within the binary if it is not loaded at its preferred ImageBase.

Import Resolution: Manually parses the Import Address Table (IAT) and loads dependent DLLs using LoadLibrary and GetProcAddress.

Fixes DLL imports in case there are any

Thread Execution: Spawns a new thread to execute the binary’s AddressOfEntryPoint.

Simulates CRunTime functinality

64-bit Optimized: Full support for x64 instruction sets and memory addressing.

#  Technical Workflow
The loader follows these primary steps to emulate the Windows OS loader:

File Reading: Reads the raw bytes of the target PE file from disk.

Header Parsing: Validates the IMAGE_DOS_HEADER and IMAGE_NT_HEADERS.

Memory Allocation: Allocates a block of memory in the calling process with VirtualAlloc based on the SizeOfImage.

Section Mapping: Copies the .text, .data, and .rsrc sections to their respective virtual offsets.

Relocation Fixups: Iterates through the .reloc section to adjust pointers for the new memory base.

IAT Patching: Resolves all external function calls required by the binary.

Execution: Adjusts memory protections (VirtualProtect) and jumps to the entry point.

#  Work in Progress: x86 (32-bit) Support
I am currently extending the loader to support 32-bit executables (PE32). This involves:

Implementing logic to handle IMAGE_NT_HEADERS32.

Managing IMAGE_REL_BASED_HIGHLOW relocation types (specific to 32-bit).

Ensuring pointer arithmetic accounts for 4-byte addresses rather than 8-byte.

⚠️ Disclaimer
This project is for educational and research purposes only. Manual mapping is a technique often studied in the context of malware analysis and game cheating. Use this code responsibly and only on systems you own or have permission to test.
