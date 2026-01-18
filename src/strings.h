#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <filesystem>

struct StringHit {
    uint64_t file_offset;
    uint32_t length;
    bool null_terminated;
    bool is_ascii;
    std::string issues;
};

std::vector<StringHit> scan_strings(const std::filesystem::path& pe_path);