#include <algorithm>
#include <cstring>
#include <iostream>
#include <string>
#include <stack>
#include <unordered_map>
#include <list>

#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>

#include "openssl/sha.h"

using std::string;
using std::list;
using std::stack;
using std::unordered_map;

typedef struct entry {
    string path;
    string sha256;
    size_t st_size;
    ino_t st_ino;
    struct timespec st_mtim;
    bool hardlink;
} entry;

typedef struct statistics {
    unsigned long scannedDirs;
    unsigned long scannedFiles;
    unsigned long skippedDirs;
    unsigned long skippedFiles;
    unsigned long reclaimableFiles;
    unsigned long reclaimedFiles;
    unsigned long hardlinks;
    size_t reclaimableBytes;
    size_t reclaimedBytes;
} statistics;

typedef struct options {
    bool removeDuplicates;
    bool verbose;
    string rootDirectory;
} options;

void printUsage();
bool getOptions(int argc, char** argv, options& opts);
void processDirectory(const string& path, stack<string>& directoriesToScan, unordered_map<string, list<entry>>& entries, statistics& stats, options& opts);
string calculateHash(const string& path);
string formatBytes(unsigned long bytes);
bool removeFile(const string& path);

int main(int argc, char** argv) {
    statistics stats = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    options opts = {false, false, ""};

    if ( ! getOptions(argc, argv, opts)) {
        return -1;
    }

    unordered_map<string, list<entry>> duplicates;      // duplicate files keyed by sha256 hash
    stack<string> directoriesToScan;
    directoriesToScan.emplace(opts.rootDirectory);

    // Build list of duplicated files
    while ( ! directoriesToScan.empty()) {
        string directory = directoriesToScan.top();
        directoriesToScan.pop();
        processDirectory(directory, directoriesToScan, duplicates, stats, opts);
    }

    if (opts.verbose) std::cout << std::endl << "Finished scanning, duplicates found: " << std::endl;

    for (const auto& [hash, entries] : duplicates) {
        if (entries.size() <= 1) {
            continue;   // no duplicates for this hash
        }

        if (opts.verbose) {
            std::cout << std::endl << hash << " (" << entries.front().st_size << " bytes per file)" << std::endl;
        }

        // Delete (if requested) any duplicates
        bool first = true;
        for (const auto& entry : entries) {
            if (opts.verbose) std::cout << "  " << entry.path << " mtime: " << entry.st_mtim.tv_sec << (entry.hardlink ? " (hardlink)" : "") << std::endl;
            if ( ! first) {
                // Hardlinks can be deleted, but shouldn't be accounted for saving real space.
                if ( ! entry.hardlink) {
                    stats.reclaimableBytes += entry.st_size;
                }
                stats.reclaimableFiles++;

                if (opts.removeDuplicates /* including hardlinks */) {
                    if (removeFile(entry.path)) {
                        if ( ! entry.hardlink) {
                            stats.reclaimedBytes += entry.st_size;
                        }
                        stats.reclaimedFiles++;
                    }
                }
            }
            first = false;
        }
    }

    std::cout << std::endl;
    std::cout << "Processed: " << stats.scannedDirs << " directories and " << stats.scannedFiles << " files" << std::endl;
    std::cout << "Skipped: " << stats.skippedDirs << " directories and " << stats.skippedFiles << " files" << std::endl;
    std::cout << "Reclaimable: " << formatBytes(stats.reclaimableBytes) << " over " << stats.reclaimableFiles << " files (space from " << stats.hardlinks << " hardlinks is ignored)" << std::endl;
    std::cout << "Reclaimed: " << formatBytes(stats.reclaimedBytes) << " over " << stats.reclaimedFiles << " files" << std::endl;

    return 0;
}

bool removeFile(const string& path) {
    return unlink(path.c_str()) == 0;
}

string formatBytes(unsigned long bytes) {
    char buf[1024];
    unsigned mb = 1024 * 1024;
    unsigned gb = mb * 1024;

    if (bytes >= gb) {
        snprintf(buf, sizeof(buf), "%lu GiB", bytes / gb);
    } else if (bytes >= mb) {
        snprintf(buf, sizeof(buf), "%lu MiB", bytes / mb);
    } else {
        snprintf(buf, sizeof(buf), "%lu bytes", bytes);
    }

    return { buf };
}

bool getOptions(int argc, char** argv, options& opts) {
    if (argc < 2) {
        printUsage();
        return false;
    }

    int opt;
    while ((opt = getopt(argc, argv, "rv")) != -1) {
        switch (opt) {
            case 'r':
                opts.removeDuplicates = true;
                break;
            case 'v':
                opts.verbose = true;
                break;
            case '?':
                printUsage();
                return false;
        }
    }

    if (optind >= argc) {
        printUsage();
        return false;
    }

    opts.rootDirectory = argv[optind];
    return true;
}

void printUsage() {
    std::cout << "Usage: dedupe [-r] [-v] <directoryToScan>" << std::endl;
    std::cout << "Find (and optionally remove) all duplicate files within a directory" << std::endl << std::endl;
    std::cout << "  -r\tRemove all duplicates (leaving one original copy)" << std::endl;
    std::cout << "  -v\tExplain what is being done" << std::endl;
}

void processDirectory(const string& path, stack<string>& directoriesToScan, unordered_map<string, list<entry>>& entries, statistics& stats, options& opts) {
    stats.scannedDirs++;

    if (opts.verbose) {
        std::cout << "Scanning: " << path << std::endl;
    }

    DIR* directory = opendir(path.c_str());
    if (!directory) {
        std::cerr << "Failed to open: " << path << ", skipping" << std::endl;
        stats.skippedDirs++;
        return;
    }

    struct dirent* child;
    while ((child = readdir(directory)) != NULL) {
        string direntPath(path);
        direntPath.append("/");
        direntPath.append(child->d_name);

        if (child->d_type == DT_DIR) {
            if (strcmp(child->d_name, ".") && strcmp(child->d_name, "..")) {
                directoriesToScan.push(direntPath);
            }
        } else if (child->d_type == DT_REG) {
            stats.scannedFiles++;
            entry file = {std::move(direntPath), "", 0, 0, false};

            string hash = calculateHash(file.path);
            if (hash.empty()) {
                std::cerr << "Failed to hash: " << file.path << ", skipping" << std::endl;
                stats.skippedFiles++;
                continue;
            }

            struct stat statbuf;
            if (int staterr = stat(file.path.c_str(), &statbuf)) {
                std::cerr << "Failed to stat: " << file.path << " -- " << strerror(staterr) << ", skipping" << std::endl;
                stats.skippedFiles++;
                continue;
            } else {
                file.st_size = statbuf.st_size;
                file.st_ino = statbuf.st_ino;
                file.st_mtim = statbuf.st_mtim;
            }

            if (entries.find(hash) == entries.end()) {
                entries[hash] = list<entry>{file};
            } else {
                entry top = entries[hash].front();
                if (file.st_size != top.st_size) {
                    std::cerr << "Same hash but different size for: " << file.path << ", skipping" << std::endl;
                    stats.skippedFiles++;
                    continue;
                }

                // If this is a hard link to any other file with the same hash, mark it as such as removing it
                // won't actually reclaim any space.
                auto existing = std::find_if(entries[hash].begin(), entries[hash].end(), [&file](const entry& i) { return i.st_ino == file.st_ino; });
                if (existing != entries[hash].end()) {
                    file.hardlink = true;
                    stats.hardlinks++;
                    if (opts.verbose) {
                        std::cout << file.path << " is a hardlink to an existing file" << std::endl;
                    }
                }

                // If this is the earliest version of the file, put it at the front of the list as we keep the earliest.
                if (file.st_mtim.tv_sec < top.st_mtim.tv_sec) {
                    entries[hash].push_front(file);
                } else {
                    entries[hash].push_back(file);
                }
            }
        }
    }

    closedir(directory);
}

string calculateHash(const string& path) {
    FILE *file = fopen(path.c_str(), "rb");
    if ( ! file) {
        return "";
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    unsigned char fileBuffer[32768];
    while (int bytesRead = fread(fileBuffer, 1, sizeof(fileBuffer), file))
    {
        SHA256_Update(&sha256, fileBuffer, bytesRead);
    }
    fclose(file);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    char outputBuffer[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;

    return outputBuffer;
}
