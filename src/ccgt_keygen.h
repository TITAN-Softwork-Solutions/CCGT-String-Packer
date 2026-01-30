#pragma once

#include <string>

namespace CCGT::Keygen {
    enum class Status {
        AlreadyConfigured,
        Generated,
        Failed
    };

    Status ensure_keys(std::string& out_msg);
    bool private_key_file_exists();
}
