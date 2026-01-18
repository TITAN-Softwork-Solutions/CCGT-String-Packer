#include "strings.h"
#include <fstream>
#include <stdexcept>
#include <cctype>

static constexpr size_t MIN_STRING_LEN = 4;

static bool is_printable_ascii(uint8_t b) {
    return b >= 0x20 && b <= 0x7E;
}

std::vector<StringHit> scan_strings(const std::filesystem::path& pe_path) {
    std::ifstream file(pe_path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("failed to open file");
    }

    file.seekg(0, std::ios::end);
    size_t size = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);

    std::vector<StringHit> hits;

    for (size_t i = 0; i < size; ) {
        size_t start = i;
        size_t len = 0;
        bool ascii = true;
        bool has_null = false;
        bool bad_byte = false;

        while (i < size) {
            uint8_t b = data[i];

            if (b == 0x00) {
                has_null = true;
                break;
            }

            if (!is_printable_ascii(b)) {
                bad_byte = true;
                break;
            }

            len++;
            i++;
        }

        if (len >= MIN_STRING_LEN) {
            StringHit hit{};
            hit.file_offset = start;
            hit.length = static_cast<uint32_t>(len);
            hit.null_terminated = has_null;
            hit.is_ascii = ascii;

            if (!has_null) hit.issues += "no_null;";
            if (bad_byte) hit.issues += "non_ascii;";
            if (start + len >= size) hit.issues += "eof_edge;";

            hits.push_back(std::move(hit));
        }

        i = start + (len ? len + 1 : 1);
    }

    return hits;
}