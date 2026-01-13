#pragma once


#include <vector>
#include <string>
#include <fstream>



bool GetFileContent(const std::string &filename, std::vector<BYTE> &filestream) {

	std::ifstream file(filename.data(), std::ios::binary);
	if (!file.is_open()) {
		return false;
	}
	filestream.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
	return true;
}



void error(const char* message, uint8_t code) {
	std::cerr << message << "\n";
	exit(code);
}

// DEBUG


