
#ifndef MAIN_CPP_FILEUTILITIES_H
#define MAIN_CPP_FILEUTILITIES_H

#include "AES.cpp"
#include "sha512.hh"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <sys/statfs.h>

using std::cin;
using std::cout;
using std::endl;
using std::string;
using std::chrono::microseconds;
using std::chrono::milliseconds;
using std::chrono::nanoseconds;
using std::chrono::seconds;
using std::chrono::steady_clock;
using std::filesystem::current_path;
using tp = steady_clock::time_point;

std::vector<string> loadFile(string filepath);

void updateSignatureDatabase(const std::vector<string> filePath);

static void print_time(const tp &start, const tp &stop);

void ReadFile(const std::basic_string<char> &filename,
              std::vector<unsigned char> &data);

std::vector<string> loadHashes();

std::basic_string<char> givePath(const std::string &fileName);

std::vector<string> loadExclusions();

std::vector<string> loadLisOfQuarantinedFiles();

std::basic_string<char> sha512(const std::string &path);

string fileStat(const std::string &f);

bool checkExclusionList(const std::string &file, const std::vector<string> &exclusion);

bool checkSignatureDataBase(const std::string &hash, const std::vector<string> &signature);

void updateContentsOfFile(const std::vector<string> &listOfQuarantinedFiles);

std::vector<unsigned char> decryptFile(const std::basic_string<char> &path,
                                       const std::vector<unsigned char> &key);

std::vector<unsigned char> encryptFile(const std::basic_string<char> &path,
                                       const std::vector<unsigned char> &key);

#endif //MAIN_CPP_FILEUTILITIES_H
