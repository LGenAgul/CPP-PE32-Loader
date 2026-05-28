#pragma once
#include <vector>
#include <string>
#include <fstream>
#include <cstdint>
#include <iostream>
#include "GLOBALS.h"

inline bool GetFileContent(const std::string& filename, std::vector<BYTE>& filestream) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;

    std::streamsize size = file.tellg();
    if (size <= 0) return false;
    file.seekg(0, std::ios::beg);

    filestream.resize(static_cast<size_t>(size));
    return static_cast<bool>(file.read(reinterpret_cast<char*>(filestream.data()), size));
}

[[noreturn]] inline void error(const char* message, int code) {
    std::cerr << "[!] " << message << " (code=" << code << ")\n";
    std::exit(code);
}
