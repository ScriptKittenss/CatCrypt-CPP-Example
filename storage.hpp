// ============================================================
//  storage.hpp  —  Save / load credentials to disk
//  Saves username+password or license key so users don't
//  have to type them every time (auto-login on next run).
//  No external libraries — pure WinAPI file I/O.
// ============================================================
#pragma once
#include <windows.h>
#include <string>
#include <fstream>
#include <sstream>
#include <filesystem>

// File where credentials are saved (next to the .exe)
static const char* SAVE_FILE = "session.dat";

// Simple key for XOR-ing saved data (not crypto-secure, just obfuscation)
static constexpr char FILE_KEY = 0x5A;

static std::string XorData(const std::string& in)
{
    std::string out = in;
    for (size_t i = 0; i < out.size(); ++i)
        out[i] ^= FILE_KEY ^ (char)(i % 17);
    return out;
}

// Parse a simple key=value file line
static std::string ParseField(const std::string& data, const std::string& key)
{
    std::string search = key + "=";
    size_t pos = data.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    size_t end = data.find('\n', pos);
    std::string val = data.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
    while (!val.empty() && (val.back() == '\r' || val.back() == '\n'))
        val.pop_back();
    return val;
}

inline void SaveCredentials(const std::string& username, const std::string& password)
{
    std::string raw = "username=" + username + "\npassword=" + password + "\n";
    std::ofstream f(SAVE_FILE, std::ios::binary);
    if (!f.good()) return;
    std::string enc = XorData(raw);
    f.write(enc.data(), enc.size());
}

inline void SaveLicense(const std::string& key)
{
    std::string raw = "license=" + key + "\n";
    std::ofstream f(SAVE_FILE, std::ios::binary);
    if (!f.good()) return;
    std::string enc = XorData(raw);
    f.write(enc.data(), enc.size());
}

inline bool LoadCredentials(std::string& username, std::string& password, std::string& license)
{
    if (!std::filesystem::exists(SAVE_FILE)) return false;
    std::ifstream f(SAVE_FILE, std::ios::binary);
    if (!f.good()) return false;
    std::string enc((std::istreambuf_iterator<char>(f)), {});
    std::string raw = XorData(enc);
    username = ParseField(raw, "username");
    password = ParseField(raw, "password");
    license  = ParseField(raw, "license");
    return !username.empty() || !license.empty();
}

inline void ClearSavedCredentials()
{
    std::filesystem::remove(SAVE_FILE);
}
