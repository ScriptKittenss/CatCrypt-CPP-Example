// ============================================================
//  skStr.h  —  Compile-time XOR string obfuscation
//  Hides your App ID, version, and server URL from
//  memory scanners and string dumpers.
//  Usage:  skCrypt("hello").decrypt()
// ============================================================
#pragma once
#include <string>
#include <array>

template<size_t N, char K>
struct XorStr {
    std::array<char, N> buf;

    constexpr XorStr(const char(&str)[N]) {
        for (size_t i = 0; i < N; ++i)
            buf[i] = str[i] ^ (K + (char)i);
    }

    std::string decrypt() const {
        std::string out(N - 1, '\0');
        for (size_t i = 0; i < N - 1; ++i)
            out[i] = buf[i] ^ (K + (char)i);
        return out;
    }
};

// Key derived from compile time so it changes every build
#define XOR_KEY ((char)((__TIME__[7] - '0') * 3 + 0x42))

// Usage: skCrypt("my string").decrypt()
#define skCrypt(s) (XorStr<sizeof(s), XOR_KEY>(s))
