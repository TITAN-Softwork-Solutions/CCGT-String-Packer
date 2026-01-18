#include "../include/ccgt_runtime.h"

#include <windows.h>

#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

void banner() {
    std::cout << "=== CCGT Demo Target ===\n";
    std::cout << "Build: " << __DATE__ << ' ' << __TIME__ << "\n";
}

void print_block(std::string_view title, const std::vector<std::string_view>& items) {
    std::cout << "\n[" << title << "]\n";
    for (const auto& s : items) {
        std::cout << "  " << s << "\n";
    }
}
}

int main() {
    banner();

    print_block("Basics", {
        "hello world",
        "this is a test string",
        "another sample line of text",
        "short",
        "a longer string that should definitely be detected in .rdata",
    });

    print_block("Paths", {
        "C:\\Windows\\System32\\kernel32.dll",
        "C:\\Program Files\\ExampleApp\\example.exe",
        "C:\\Users\\Public\\Documents\\report.txt",
        "\\\\.\\pipe\\ccgt-demo-pipe",
        "\\??\\C:\\Temp\\payload.bin",
    });

    print_block("URLs", {
        "http://127.0.0.1:8080/api/v1/ping",
        "https://example.com/login",
        "wss://socket.example.com/stream",
        "https://cdn.example.com/assets/app.bundle.js",
    });

    print_block("Errors", {
        "[ERROR] initialization failed",
        "fatal: unable to open resource",
        "warning: config missing, using defaults",
        "access denied",
        "operation timed out",
    });

    print_block("Format", {
        "user=%s token=%s",
        "id=%08X status=%d",
        "recv(%d bytes) from %s:%d",
        "path='%s' size=%llu",
    });

    const std::string a = std::string("runtime ") + "string " + "concat";
    const std::string b = std::string("value=") + std::to_string(1337);

    std::cout << "  " << a << "\n";
    std::cout << "  " << b << "\n";
    
    MessageBoxA(nullptr, "This is a MessageBoxA test string", "CCGT Demo", MB_OK);

    return 0;
}