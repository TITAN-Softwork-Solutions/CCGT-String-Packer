#include "../include/ccgt_runtime.h"

#include <windows.h>

#include <atomic>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <iostream>

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

VOID CALLBACK timer_tick_callback(PVOID param, BOOLEAN) {
    auto* counter = reinterpret_cast<std::atomic<int>*>(param);
    const int tick = counter->fetch_add(1);
    std::cout << "[TIMER] tick #" << (tick + 1) << "\n";
}

std::vector<int> collect_primes(int count) {
    std::vector<int> primes;
    primes.reserve(count);
    int candidate = 2;

    while (static_cast<int>(primes.size()) < count) {
        bool is_prime = true;
        for (int p : primes) {
            if (p * p > candidate) break;
            if ((candidate % p) == 0) {
                is_prime = false;
                break;
            }
        }
        if (is_prime) {
            primes.push_back(candidate);
        }
        ++candidate;
    }

    return primes;
}

uint64_t square_accumulate(const std::vector<int>& values) {
    uint64_t acc = 0;
    for (int v : values) {
        const uint64_t square = static_cast<uint64_t>(v) * static_cast<uint64_t>(v);
        acc += square;
    }
    return acc;
}

void run_runtime_demo() {
    std::atomic<int> timer_ticks{0};
    HANDLE timer = nullptr;

    if (!CreateTimerQueueTimer(&timer, nullptr, timer_tick_callback, &timer_ticks, 500, 750, WT_EXECUTEINTIMERTHREAD)) {
        std::cerr << "unable to start timer queue\n";
    }

    HANDLE worker_done = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    std::vector<int> primes;

    std::thread worker([&]() {
        primes = collect_primes(14);
        if (worker_done) {
            SetEvent(worker_done);
        }
    });

    if (worker_done) {
        const auto wait_status = WaitForSingleObject(worker_done, 3000);
        if (wait_status == WAIT_TIMEOUT) {
            std::cerr << "worker thread timed out\n";
        }
    }

    if (worker.joinable()) {
        worker.join();
    }

    const uint64_t sum_of_squares = square_accumulate(primes);
    const uint64_t average = primes.empty() ? 0 : sum_of_squares / primes.size();

    std::cout << "\n[Runtime Math]\n";
    std::cout << "  primes count: " << primes.size() << "\n";
    std::cout << "  sum of squares: " << sum_of_squares << "\n";
    std::cout << "  average squares: " << average << "\n";
    std::cout << "  timer ticks observed: " << timer_ticks.load() << "\n";

    if (timer) {
        DeleteTimerQueueTimer(nullptr, timer, INVALID_HANDLE_VALUE);
    }

    if (worker_done) {
        CloseHandle(worker_done);
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

    run_runtime_demo();

    return 0;
}
