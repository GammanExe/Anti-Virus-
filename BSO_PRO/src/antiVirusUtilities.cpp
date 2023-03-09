//
// Created by john on 17.05.22.
//


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

std::vector<unsigned char> encryptFile(const std::basic_string<char> &path, const std::vector<unsigned char> &key) {

    tp start, stop;
    start = steady_clock::now();

    AES aes(AESKeyLength::AES_128);

    std::vector<unsigned char> encryptedVector = {};
    std::vector<unsigned char> vector = {};

    ReadFile(path, vector);

    if (vector.size() % 16 != 0) {
        unsigned long rem = vector.size() % 16;
        for (int i = 0; i < (16 - rem); i++) {
            vector.push_back(0x20);
        }
    }

    std::vector<unsigned char> encryptedOutput = {};
    std::vector<unsigned char> temp = {};

    for (int i = 0; i < vector.size() / 16; i++) {
        temp = {};
        for (int j = 0; j < 16; j++) {
            temp.push_back(vector.at(16 * i + j));
        }

        encryptedOutput = aes.EncryptECB(temp, key);
        encryptedVector.insert(encryptedVector.end(), encryptedOutput.begin(),
                               encryptedOutput.end());
    }

    stop = steady_clock::now();
    printf("Encryption time: ");
    print_time(start, stop);
    printf("\n");

    return encryptedVector;
}

std::vector<unsigned char> decryptFile(const std::basic_string<char> &path,
                                       const std::vector<unsigned char> &key) {

    tp start, stop;
    start = steady_clock::now();

    AES aes(AESKeyLength::AES_128);

    std::vector<unsigned char> decryptedVector = {};
    std::vector<unsigned char> vector = {};

    ReadFile(path, vector);

    if (vector.size() % 16 != 0) {
        unsigned long rem = vector.size() % 16;
        for (int i = 0; i < (16 - rem); i++) {
            vector.push_back(0x20);
        }
    }

    std::vector<unsigned char> decryptedOutput = {};
    std::vector<unsigned char> temp = {};

    for (int i = 0; i < vector.size() / 16; i++) {
        temp = {};
        for (int j = 0; j < 16; j++) {
            temp.push_back(vector.at(16 * i + j));
        }

        decryptedOutput = aes.DecryptECB(temp, key);
        decryptedVector.insert(decryptedVector.end(), decryptedOutput.begin(),
                               decryptedOutput.end());
    }
    stop = steady_clock::now();
    printf("Decryption time: ");
    print_time(start, stop);
    printf("\n");

    return decryptedVector;
}

void quarantineFile(const std::string &path, const std::vector<unsigned char> &key) {
    tp start, stop;
    start = steady_clock::now();

    std::ofstream listofQuarantinedFiles;
    listofQuarantinedFiles.open(givePath("listOfQuarantinedFiles.txt"),
                                std::ofstream::out | std::ofstream::app);
    listofQuarantinedFiles << path + "\n";
    listofQuarantinedFiles.close();


    std::vector<unsigned char> encryptedContentsOfFile = encryptFile(path, key);

    std::ofstream file;
    file.open(path, std::ofstream::out | std::ofstream::trunc);
    for (int i = 0; i < encryptedContentsOfFile.size(); ++i) {
        file << encryptedContentsOfFile[i];
    }

    file.close();

    stop = steady_clock::now();
    printf("Putting file into quarantine time: ");
    print_time(start, stop);
    printf("\n");
}

void unQuarantineFile(const std::basic_string<char> &path, const std::vector<unsigned char> &key,
                      std::vector<string> listOfQuarantinedFiles) {

    tp start, stop;
    start = steady_clock::now();

    auto started = std::chrono::high_resolution_clock::now();


    printf("\n");

    for (int i = 0; i < listOfQuarantinedFiles.size(); i++) {

        if (listOfQuarantinedFiles[i] == path) {

            listOfQuarantinedFiles.erase(listOfQuarantinedFiles.begin() + i);

            updateContentsOfFile(listOfQuarantinedFiles);

            std::vector<unsigned char> decryptedContentsOfFile =
                    decryptFile(path, key);

            std::ofstream file;
            file.open(path, std::ofstream::out | std::ofstream::trunc);

            for (int j = 0; j < decryptedContentsOfFile.size(); ++j) {
                file << decryptedContentsOfFile[j];
            }
            file.close();


            printf("The file has been removed from quarantine\n");
            return;
        }
    }

    printf("Given file path is not present in quarantine\n");

    stop = steady_clock::now();
    printf("Removing file from quarantine time: ");
    print_time(start, stop);
    printf("\n");
}

void recursiveScan(const std::string &path, const std::vector<string> &signature, const std::vector<string> &exclusions,
                   const std::vector<unsigned char> &key,
                   bool sudo) {
    tp start, stop;
    start = steady_clock::now();

    int total_counter = 0;
    int quarantined_counter = 0;
    int exclusiosns_Counter = 0;
    std::vector<string> matchList = {};
    printf("Files that will be quarantined:\n");
    if (fs::is_directory(fs::status(path))) {

        char *cstr = new char[path.length() + 1];
        strcpy(cstr, path.c_str());
        char *paths[2] = {cstr, nullptr};

        FTS *tree = fts_open(paths, FTS_NOCHDIR, nullptr);

        if (!tree) {
            perror("fts_open");
        }
        printf("\n");

        FTSENT *node;

        while ((node = fts_read(tree))) {

            if (node->fts_level > 0 && node->fts_name[0] == '.')

                fts_set(tree, node, FTS_SKIP);

            else if (node->fts_info & FTS_F) {
                std::string filePath = node->fts_path;


                printf(" File number %d scanned \n ", total_counter);
                printf(" %s\n", node->fts_path);


                bool check1 = fs::is_regular_file(filePath);
                bool check2 = fs::is_directory(filePath);

                if (checkExclusionList(fileStat(filePath), exclusions)) {
                    printf("File was excluded from scan\n");

                    exclusiosns_Counter++;
                } else if (checkSignatureDataBase(sha512(filePath), signature) && check1 && check2) {
                    printf("File matched signature");
                    matchList.emplace_back(node->fts_path);
                    quarantined_counter++;
                }


                total_counter++;
            }
        }

        printf(" \n");
        printf("Total number of scanned files: %d\n", total_counter);

        printf("Number of files that matched the signature database: %d\n",
               quarantined_counter);
        printf("Number of files that were excluded from the scan: %d\n",
               exclusiosns_Counter);
        printf(" \n");
    } else {
        std::cout << "wrong directory" << std::endl;
    }


    stop = steady_clock::now();
    printf("Recursive scan time: ");
    print_time(start, stop);
    printf("\n");

    if (sudo) {
        for (int i = 0; i < matchList.size(); i++) {
            quarantineFile(matchList.at(i), key);
        }
    }
    if (!matchList.empty()) {
        printf("These files matched with the signature database, to quarantine them use sudo\n ");
        for (int i = 0; i < matchList.size(); i++) {
            printf("%s\n", matchList[i].c_str());
        }

    } else {
        printf("No File Matched the signature database \n");
    }
}


void
scanSingleFile(const std::string &path, const std::vector<string> &signature, const std::vector<unsigned char> &key,
               bool sudo) {

    tp start, stop;
    start = steady_clock::now();

    if (checkSignatureDataBase(sha512(path), signature)) {
        printf(
                "File has been matched with a signature from the signature database\n");

        if (sudo) {
            quarantineFile(path, key);
            printf("The file will be quarantined\n");
        } else {
            printf("To quarantine the file use sudo\n");
        }
    } else {
        printf("\n");
        printf("File has not been matched with a signature from the signature "
               "database\n");
    }
    stop = steady_clock::now();
    printf("Single file scan time: ");
    print_time(start, stop);
    printf("\n");
}