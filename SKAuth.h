// ============================================================
//  CatCrypt SDK  —  SKAuth.h
//  NO external dependencies — only Windows SDK (WinHTTP)
//  Works on any Windows C++ project out of the box.
//  Requires: C++17, Windows 10 SDK
//  Docs: https://auth.script-kittens.com  →  Documentation → SDKs
// ============================================================
#pragma once

#pragma comment(lib, "winhttp.lib")

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <algorithm>
#include <cctype>

// ── SHA256 (compact, no dependencies) ─────────────────────────────────────
// Used for the HWID so it matches the Python and C# SDKs:
// same machine => same HWID on all SDKs.
namespace sk_sha256 {
inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
inline std::string Hex(const std::string& data)
{
    uint32_t h[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    uint64_t bitLen = (uint64_t)data.size() * 8;
    std::string msg = data;
    msg.push_back((char)0x80);
    while (msg.size() % 64 != 56) msg.push_back(0);
    for (int i = 7; i >= 0; --i) msg.push_back((char)((bitLen >> (i * 8)) & 0xFF));
    for (size_t off = 0; off < msg.size(); off += 64)
    {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = ((uint32_t)(uint8_t)msg[off+i*4] << 24) | ((uint32_t)(uint8_t)msg[off+i*4+1] << 16)
                 | ((uint32_t)(uint8_t)msg[off+i*4+2] << 8) | (uint32_t)(uint8_t)msg[off+i*4+3];
        for (int i = 16; i < 64; ++i)
        {
            uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i)
        {
            uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    std::ostringstream ss; ss << std::hex;
    for (int i = 0; i < 8; ++i) { ss.width(8); ss.fill('0'); ss << h[i]; }
    return ss.str();
}
} // namespace sk_sha256

class SKAuth
{
    // ── Config ───────────────────────────────────────────────────────────────
    static constexpr const wchar_t* HOST = L"auth.script-kittens.com";

    std::string _appId;
    std::string _version;
    std::string _hwid;

    // ── Simple JSON helpers (no external library needed) ─────────────────────
    static std::string JsonStr(const std::string& json, const std::string& key)
    {
        std::string search = "\"" + key + "\"";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return "";
        pos = json.find(':', pos) + 1;
        while (pos < json.size() && json[pos] == ' ') ++pos;
        if (pos >= json.size()) return "";
        if (json[pos] == '"')
        {
            ++pos;
            size_t end = json.find('"', pos);
            if (end == std::string::npos) return "";
            return json.substr(pos, end - pos);
        }
        size_t end = json.find_first_of(",}", pos);
        std::string val = json.substr(pos, end == std::string::npos ? end : end - pos);
        size_t last = val.find_last_not_of(" \t\r\n");
        if (last != std::string::npos) val.erase(last + 1);
        return val;
    }

    static bool JsonBool(const std::string& json, const std::string& key)
    {
        return JsonStr(json, key) == "true";
    }

    // ── HWID — volume serial hashed with SHA256 (first 32 hex chars) ─────────
    // Matches the Python and C# SDKs: same machine => same HWID on all SDKs.
    static std::string GetHWID()
    {
        DWORD serial = 0;
        GetVolumeInformationA("C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0);
        std::ostringstream ss;
        ss << std::hex << std::uppercase << serial;
        std::string hex = sk_sha256::Hex(ss.str());
        std::transform(hex.begin(), hex.end(), hex.begin(),
                       [](unsigned char c){ return (char)std::tolower(c); });
        return hex.substr(0, 32);
    }

    // ── HTTP via WinHTTP ─────────────────────────────────────────────────────
    static std::string HttpRequest(const std::wstring& method, const std::wstring& path,
                                   const std::string& body, bool* okOut = nullptr)
    {
        std::string fail = R"({"ok":false,"message":"Connection failed"})";
        HINTERNET hSession = WinHttpOpen(L"CatCrypt/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return fail;
        HINTERNET hConnect = WinHttpConnect(hSession, HOST, INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return fail; }
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, method.c_str(), path.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return fail; }

        BOOL sent = FALSE;
        if (method == L"POST")
        {
            std::wstring headers = L"Content-Type: application/json\r\n";
            sent = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1L,
                (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);
        }
        else
        {
            sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        }

        std::string response;
        DWORD status = 0, statusSize = sizeof(status);
        if (sent && WinHttpReceiveResponse(hRequest, nullptr)
            && WinHttpQueryHeaders(hRequest,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize,
                WINHTTP_NO_HEADER_INDEX))
        {
            if (okOut) *okOut = (status == 200);
            DWORD bytesAvail = 0;
            while (WinHttpQueryDataAvailable(hRequest, &bytesAvail) && bytesAvail > 0)
            {
                std::vector<char> buf(bytesAvail + 1, 0);
                DWORD bytesRead = 0;
                WinHttpReadData(hRequest, buf.data(), bytesAvail, &bytesRead);
                response.append(buf.data(), bytesRead);
            }
        }
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return response.empty() ? fail : response;
    }

    static std::string HttpPost(const std::wstring& path, const std::string& body)
    { return HttpRequest(L"POST", path, body); }

    // URL-encode for query strings
    static std::string UrlEncode(const std::string& s)
    {
        std::ostringstream ss;
        for (unsigned char c : s)
        {
            if (isalnum(c) || c=='-' || c=='_' || c=='.' || c=='~') ss << c;
            else { ss << '%'; ss << std::hex << std::uppercase << (int)c; }
        }
        return ss.str();
    }
    static std::wstring ToWide(const std::string& s)
    { return std::wstring(s.begin(), s.end()); }

    // ── Build JSON body ──────────────────────────────────────────────────────
    static std::string BuildJson(std::initializer_list<std::pair<std::string,std::string>> fields)
    {
        std::string json = "{";
        bool first = true;
        for (auto& [k, v] : fields)
        {
            if (!first) json += ",";
            // escape backslash and quote in values
            std::string e;
            for (char c : v) { if (c=='\\'||c=='"') e.push_back('\\'); e.push_back(c); }
            json += "\"" + k + "\":\"" + e + "\"";
            first = false;
        }
        return json + "}";
    }

public:
    // ── User data (populated after login) ────────────────────────────────────
    std::string username;
    std::string plan;
    std::string expires;
    std::string email;
    std::string apiKey;   // needed for Validate() and DownloadFile()
    std::string hwid;

    // ── Constructor ──────────────────────────────────────────────────────────
    SKAuth(const std::string& appId, const std::string& version = "1.0")
        : _appId(appId), _version(version), _hwid(GetHWID()) {}

    std::string GetHWID() const { return _hwid; }

    // ── Login ─────────────────────────────────────────────────────────────────
    // Returns { ok, message }. On success the user fields above are filled.
    // On failure, show message as-is (HWID mismatch, banned, expired,
    // update required, offline...) — don't invent your own.
    struct AuthResult { bool ok; std::string message; };

    AuthResult Login(const std::string& user, const std::string& pass)
    {
        auto body = BuildJson({
            {"appId",    _appId},
            {"username", user},
            {"password", pass},
            {"hwid",     _hwid},
            {"version",  _version}
        });

        auto resp = HttpPost(L"/sdk/login", body);
        bool ok   = JsonBool(resp, "ok");

        if (ok)
        {
            username = JsonStr(resp, "username");
            plan     = JsonStr(resp, "plan");
            expires  = JsonStr(resp, "expires");
            email    = JsonStr(resp, "email");
            apiKey   = JsonStr(resp, "apiKey");
            hwid     = JsonStr(resp, "hwid");
        }
        return { ok, JsonStr(resp, "message") };
    }

    // ── Register (new account — license key optional) ─────────────────────────
    AuthResult Register(const std::string& user, const std::string& pass,
                        const std::string& email = "", const std::string& key = "")
    {
        auto body = BuildJson({
            {"appId",      _appId},
            {"username",   user},
            {"password",   pass},
            {"email",      email},
            {"licenseKey", key}
        });
        auto resp = HttpPost(L"/sdk/register", body);
        return { JsonBool(resp, "ok"), JsonStr(resp, "message") };
    }

    // ── Redeem — apply a license key to an existing account ───────────────────
    AuthResult Redeem(const std::string& user, const std::string& key)
    {
        auto body = BuildJson({
            {"appId",      _appId},
            {"username",   user},
            {"licenseKey", key}
        });
        auto resp = HttpPost(L"/sdk/redeem", body);
        return { JsonBool(resp, "ok"), JsonStr(resp, "message") };
    }

    // ── Validate — heartbeat ──────────────────────────────────────────────────
    // Call every few minutes while your tool runs. Kicks banned / expired
    // users and syncs plan changes without re-login. Needs a login first.
    AuthResult Validate()
    {
        if (apiKey.empty())
            return { false, "Not logged in — call Login() first." };
        auto body = BuildJson({
            {"appId",  _appId},
            {"apiKey", apiKey},
            {"hwid",   _hwid}
        });
        auto resp = HttpPost(L"/sdk/validate", body);
        bool ok = JsonBool(resp, "ok");
        if (ok)
        {
            std::string p = JsonStr(resp, "plan");
            std::string e = JsonStr(resp, "expires");
            if (!p.empty()) plan = p;
            if (!e.empty()) expires = e;
        }
        return { ok, JsonStr(resp, "message") };
    }

    // ── GetVar — fetch a server-side runtime variable by name ─────────────────
    // Set in dashboard → Settings → Variables. No recompile needed to change
    // values (version checks, announcements, download URLs...).
    std::string GetVar(const std::string& name)
    {
        auto body = BuildJson({ {"appId", _appId}, {"name", name} });
        auto resp = HttpPost(L"/sdk/variable", body);
        std::string val = JsonStr(resp, "value");
        return val.empty() ? JsonStr(resp, "message") : val;
    }

    // ── DownloadFile — fetch a file from the Runtime Vault ────────────────────
    // fileId comes from dashboard → Files. Needs a logged-in user.
    // Returns true when the file was saved to savePath.
    bool DownloadFile(const std::string& fileId, const std::string& savePath)
    {
        if (apiKey.empty()) return false;
        std::string path = "/sdk/file?appId=" + UrlEncode(_appId)
                         + "&fileId=" + UrlEncode(fileId)
                         + "&apiKey=" + UrlEncode(apiKey);
        bool ok = false;
        std::string data = HttpRequest(L"GET", ToWide(path), "", &ok);
        if (!ok || data.empty() || data.rfind(R"({"ok":false)", 0) == 0) return false;
        std::ofstream f(savePath, std::ios::binary);
        if (!f) return false;
        f.write(data.data(), (std::streamsize)data.size());
        return (bool)f;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    // Any plan that isn't free counts as paid (starter, pro, ...).
    bool IsPaid() const
    {
        std::string p = plan;
        std::transform(p.begin(), p.end(), p.begin(),
                       [](unsigned char c){ return (char)std::tolower(c); });
        return !p.empty() && p != "free";
    }
};
