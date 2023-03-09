#include <cstdio>
#include "antiVirusUtilities.h"
#include "antiVirusUtilities.cpp"
#include "fileUtilities.h"
#include "fileUtilities.cpp"
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <bits/getopt_core.h>
#include <unistd.h>
#include <chrono>
#include <cerrno>
#include <poll.h>
#include <cstdlib>
#include <sys/inotify.h>


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


void menu() {
    printf("\n\n");
    printf("AntiVirus by Jan Guziuk\n");
    printf("-S               :Scan here\n");
    printf("-s <path>        :Scan at given directory\n");
    printf("-L               :List names of quarantined files\n");
    printf("-r <path>        :Read contents of given quarantined file\n");
    printf("-q <path>        :Remove a given file from Quarantine\n");
    printf("-D <path>        :Delete given quarantined file \n");
    printf("\n\n");
}

static void handle_events(int fd, const int *wd, int argc, char *argv[]) {
    char buf[4096]
            __attribute__ ((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;
    ssize_t len;

    for (;;) {

        len = read(fd, buf, sizeof(buf));
        if (len == -1 && errno != EAGAIN) {
            exit(EXIT_FAILURE);
        }

        if (len <= 0)
            break;

        for (char *ptr = buf; ptr < buf + len;
             ptr += sizeof(struct inotify_event) + event->len) {
            event = (const struct inotify_event *) ptr;


            if (event->mask & IN_CREATE)
                printf("IN_CREATE: ");
            if (event->mask & IN_MODIFY)
                printf("IN_MODIFY: ");
            if (event->mask & IN_MOVE_SELF)
                printf("IN_MOVE_SELF: ");
            if (event->mask & IN_MOVED_TO)
                printf("IN_MOVED_TO: ");


            for (int i = 1; i < argc; ++i) {
                if (wd[i] == event->wd) {
                    printf("%s/", argv[i]);
                    break;
                }
            }

            if (event->len)
                printf("%s", event->name);

            if (event->mask & IN_ISDIR)
                printf(" [directory]\n");
            else
                printf(" [file]\n");
        }
    }
}


int main(int argc, char *argv[]) {


    std::vector<unsigned char> key = {};
    ReadFile(givePath("AesKey.txt"), key);

    std::vector<string> signature = loadHashes();

    std::vector<string> lisOfQuarantinedFiles = loadLisOfQuarantinedFiles();

    std::vector<string> exclusions = loadExclusions();


    //updateSignatureDatabase(loadFile(givePath("update.txt")));

    //const std::string f = "/sys/kernel/security";
    //printf("%s", fileStat(f).c_str());
    //recursiveScan("/sys",signature,exclusions,key,true);
    //scanSingleFile(givePath("fileToHash.txt"),signature, key);
    //unQuarantineFile(givePath("fileToHash.txt"),key,lisOfQuarantinedFiles);

    std::string argv_str(argv[0]);
    std::string projectDirectory = argv_str.substr(0, argv_str.find_last_of('/'));

    if (argc == 1) {
        menu();

        char buf;
        int fd, i, poll_num;
        int *wd;
        nfds_t nfds;
        struct pollfd fds[2];

        if (argc < 2) {
            exit(EXIT_FAILURE);
        }

        printf("Press ENTER key to terminate.\n");

        fd = inotify_init1(IN_NONBLOCK);
        if (fd == -1) {
            perror("inotify_init1");
            exit(EXIT_FAILURE);
        }


        wd = static_cast<int *>(calloc(argc, sizeof(int)));
        if (wd == nullptr) {
            perror("calloc");
            exit(EXIT_FAILURE);
        }


        nfds = 2;
        fds[0].fd = STDIN_FILENO;
        fds[0].events = POLLIN;
        fds[1].fd = fd;
        fds[1].events = POLLIN;


        printf("Listening for events.\n");
        while (true) {
            poll_num = poll(fds, nfds, -1);
            if (poll_num == -1) {
                if (errno == EINTR)
                    continue;
                perror("poll");
                exit(EXIT_FAILURE);
            }

            if (poll_num > 0) {

                if (fds[0].revents & POLLIN) {

                    while (read(STDIN_FILENO, &buf, 1) > 0 && buf != '\n')
                        continue;
                    break;
                }

                if (fds[1].revents & POLLIN) {

                    handle_events(fd, wd, argc, argv);
                }
            }
        }

        printf("Listening for events stopped.\n");
        close(fd);

        free(wd);
        exit(EXIT_SUCCESS);
        return 0;
    }
    int c;
    opterr = 0;
    while ((c = getopt(argc, argv, "Ss:Lr:q:D:A:")) != -1) {
        switch (c) {
            case 'S': {
                bool sudo = true;
                if (getuid() != 0) {
                    sudo = false;
                }
                char tmp[256];
                getcwd(tmp, 256);

                printf("\n\n");
                recursiveScan(tmp, signature, exclusions, key, sudo);
                printf("\n\n");

                break;
            }
            case 's': {
                bool sudo = true;
                if (getuid() != 0) {
                    sudo = false;
                }

                const fs::path path(optarg);
                std::error_code ec;

                if (fs::is_directory(path, ec)) {
                    printf("\n\n");
                    recursiveScan(path, signature, exclusions, key, sudo);
                    printf("\n\n");
                }
                if (fs::is_regular_file(path, ec)) {

                    printf("\n\n");
                    scanSingleFile(path, signature, key, sudo);
                    printf("\n\n");
                }
                if (ec) {
                    std::cerr << "Error in given path " << ec.message();
                    printf(" \n\n");
                }

                break;
            }
            case 'L': {

                std::ifstream file(givePath("listOfQuarantinedFiles.txt"));
                std::string str;

                printf("\n");

                while (std::getline(file, str)) {
                    printf("\n");
                    printf("%s\n", str.c_str());
                    printf("\n");
                }

                printf("\n");

                break;
            }
            case 'r': {
                if (getuid() != 0) {
                    std::cout << "You have to use \"sudo\" in order to read file contents "
                              << std::endl;
                    break;
                }
                const fs::path path(optarg);

                printf("\n\n");
                std::vector<unsigned char> fileContents = decryptFile(path, key);
                for (unsigned char x: fileContents) {
                    printf("%c", x);
                }
                printf("\n\n");

                break;
            }
            case 'q': {
                if (getuid() != 0) {
                    std::cout << "You have to use \"sudo\" in order to remove a given file "
                                 "from quarantine"
                              << std::endl;
                    break;
                }
                printf("\n\n");
                unQuarantineFile(optarg, key, lisOfQuarantinedFiles);
                printf("\n\n");

                break;
            }
            case 'D': {
                if (getuid() != 0) {
                    std::cout << "You have to use \"sudo\" in order to delete a given file"
                              << std::endl;
                    break;
                }
                printf("\n\n");
                {
                    if (remove(optarg) != 0)
                        perror("Error while deleting file");
                    else
                        puts("File successfully deleted");

                    for (int i = 0; i < lisOfQuarantinedFiles.size(); i++) {

                        if (lisOfQuarantinedFiles[i] == optarg) {

                            lisOfQuarantinedFiles.erase(lisOfQuarantinedFiles.begin() + i);

                            updateContentsOfFile(lisOfQuarantinedFiles);


                        }
                    }
                }
            }
            case 'A': {
                if (getuid() != 0) {
                    std::cout << "You have to use \"sudo\" in order to update the signature database"
                              << std::endl;
                    break;
                }

                const fs::path path(optarg);
                updateSignatureDatabase(loadFile(path));
                std::cout << "Database has been updated"
                          << std::endl;
            }
            default: {
                menu();
                break;
            }
        }
    }
}

