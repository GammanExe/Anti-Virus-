//
// Created by john on 17.05.22.
//


#include <cstdio>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include "sha512.hh"
#include <algorithm>
#include <chrono>
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

namespace fs = std::filesystem;

std::vector<string> loadFile(string filepath) {


    std::ifstream indata(filepath);
    std::vector<string> result = {};
    std::string contents = "";


    while (std::getline(indata, contents)) {
        result.push_back(contents);
    }

    indata.close();
    return result;
}

void updateSignatureDatabase(const std::vector<string> filePath) {


    std::ofstream ofs(givePath("signatureDataBase.txt"), std::ios_base::app);

    for (int i = 0; i < filePath.size(); i++) {
        ofs << "\n" + filePath[i];
    }

    ofs.close();


}

static void print_time(const tp &start, const tp &stop) {
    std::cout << std::chrono::duration_cast<milliseconds>(stop - start).count()
              << "[ms] ";
    std::cout << std::chrono::duration_cast<nanoseconds>(stop - start).count()
              << "[ns]\n";
}

void ReadFile(const std::basic_string<char> &filename,
              std::vector<unsigned char> &data) {
    std::ifstream stream;
    stream.open(filename, std::ios::in | std::ios::binary);

    if (!stream.bad()) {
        const std::streampos start = stream.tellg();
        stream.seekg(0, std::ios::end);

        const std::streampos end = stream.tellg();
        stream.seekg(0, std::ios::beg);

        data.resize(end - start);
        stream.read(reinterpret_cast<char *>(&data.front()),
                    static_cast<std::streamsize>(data.size()));
    }
}

std::basic_string<char> givePath(const std::string &fileName) {
    string file_path = __FILE__;
    string dir_path = file_path.substr(0, file_path.rfind("fileUtilities.cpp"));
    std::string path = dir_path + fileName;
    return path;
}

std::vector<string> loadHashes() {


    std::ifstream indata(givePath("signatureDataBase.txt"));
    std::vector<string> result = {};
    std::string hash = "";


    while (std::getline(indata, hash)) {
        result.push_back(hash);
    }

    indata.close();
    return result;
}

std::vector<string> loadExclusions() {


    std::ifstream indata(givePath("exclusions.txt"));
    std::vector<string> result = {};
    std::string exclusion = "";


    while (getline(indata, exclusion)) {
        result.push_back(exclusion);
    }

    indata.close();
    return result;
}

std::vector<string> loadLisOfQuarantinedFiles() {


    std::ifstream indata(givePath("listOfQuarantinedFiles.txt"));
    std::vector<string> result = {};
    std::string elementOfList;


    while (getline(indata, elementOfList)) {
        result.push_back(elementOfList);
    }

    indata.close();
    return result;
}

std::basic_string<char> sha512(const std::string &path) {
    if ((path == givePath("listOfQuarantinedFiles.txt")) ||
        (path == givePath("signatureDataBase.txt"))) {
        return "";
    } else {
        std::string hash = sw::sha512::file(path);
        return hash;
    }
}

string fileStat(const std::string &f) {
    struct statfs filestats{};
    if (statfs(f.data(), &filestats) == 0) {

        std::ostringstream ss;
        ss << std::hex << filestats.f_type;
        std::string result = ss.str();


        return result;
    } else {
        printf("no file type returned");
        return "";
    }
}


bool checkExclusionList(const std::string &file, const std::vector<string> &exclusion) {
    std::string temp;
    std::ifstream indata;


    for (auto &i: exclusion) {
        if (file == i) {
            return true;
        }
    }
    return false;

}

bool checkSignatureDataBase(const std::string &hash, const std::vector<string> &signature) {
    std::string temp;
    std::ifstream indata;


    for (auto &i: signature) {
        if (hash == i) {
            return true;
        }
    }
    return false;

}

void updateContentsOfFile(const std::vector<string> &listOfQuarantinedFiles) {
    std::ofstream ofs(givePath("listOfQuarantinedFiles.txt"), std::ofstream::trunc);

    for (const string &listOfQuarantinedFile: listOfQuarantinedFiles) {
        ofs << listOfQuarantinedFile + "\n";
    }

    ofs.close();
}
