//
// Created by john on 17.05.22.
//

#ifndef MAIN_CPP_ANTIVIRUSUTILITIES_H
#define MAIN_CPP_ANTIVIRUSUTILITIES_H

#include <cstdio>
#include "fileUtilities.h"
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include "AES.h"
#include "sha512.hh"
#include <chrono>
#include <fts.h>
#include <cstring>

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

namespace fs = std::filesystem;

std::vector<unsigned char> encryptFile(const std::basic_string<char> &path, const std::vector<unsigned char> &key);

std::vector<unsigned char> decryptFile(const std::basic_string<char> &path,const std::vector<unsigned char> &key);

void quarantineFile(const std::string &path, const std::vector<unsigned char> &key);

void unQuarantineFile(const std::basic_string<char> &path, const std::vector<unsigned char> &key,std::vector<string> listOfQuarantinedFiles);

void recursiveScan(const std::string &path, const std::vector<string> &signature, const std::vector<string> &exclusions,const std::vector<unsigned char> &key,bool sudo);

void scanSingleFile(const std::string &path, const std::vector<string> &signature, const std::vector<unsigned char> &key,bool sudo);

#endif //MAIN_CPP_ANTIVIRUSUTILITIES_H
