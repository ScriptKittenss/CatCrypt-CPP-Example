// ============================================================
//  CatCrypt — C++ Loader Example
//  Build : Open CatCrypt-CPP.sln → Release x64 → Build
//  Needs : Visual Studio 2022, Windows 10 SDK (no other deps)
// ============================================================

// ╔══════════════════════════════════════════════════════════╗
// ║  ONLY CHANGE THESE — paste from your dashboard          ║
// ╚══════════════════════════════════════════════════════════╝
#define APP_ID_RAW      "YOUR_APP_ID_HERE"
#define APP_VERSION_RAW "1.0"

// String obfuscation — hides the above from memory scanners
#include "skStr.h"
static const std::string APP_ID      = skCrypt(APP_ID_RAW).decrypt();
static const std::string APP_VERSION = skCrypt(APP_VERSION_RAW).decrypt();

#include "SKAuth.h"
#include "storage.hpp"

#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <conio.h>
#include <windows.h>
#include <iomanip>

// ── Console helpers ───────────────────────────────────────────────────────────

void Color(int c) { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), c); }

void Banner()
{
    system("cls");
    Color(14); // yellow
    std::cout
        << "\n"
        << "  ====================================================\n"
        << "          Script Kittens  |  Internal Panel\n"
        << "            Powered by CatCrypt Auth\n"
        << "  ====================================================\n\n";
    Color(7);
}

// Read password — shows * instead of characters
std::string ReadPassword(const std::string& prompt)
{
    std::cout << prompt;
    std::string pass;
    char ch;
    while ((ch = static_cast<char>(_getch())) != '\r')
    {
        if (ch == '\b') {
            if (!pass.empty()) { pass.pop_back(); std::cout << "\b \b"; }
        } else {
            pass += ch;
            std::cout << '*';
        }
    }
    std::cout << "\n";
    return pass;
}

// ── Lockout (brute-force protection) ─────────────────────────────────────────

struct Lockout {
    int                                    fails      = 0;
    std::chrono::steady_clock::time_point  lockedUntil{};

    bool IsLocked() const { return std::chrono::steady_clock::now() < lockedUntil; }

    int SecondsLeft() const {
        if (!IsLocked()) return 0;
        return static_cast<int>(
            std::chrono::duration_cast<std::chrono::seconds>(
                lockedUntil - std::chrono::steady_clock::now()).count());
    }

    void RecordFail(int maxFails = 3, int lockSecs = 30) {
        if (IsLocked()) return;
        if (++fails >= maxFails) {
            fails = 0;
            lockedUntil = std::chrono::steady_clock::now() + std::chrono::seconds(lockSecs);
        }
    }

    void Reset() { fails = 0; lockedUntil = {}; }
};

// ── Expiry display ────────────────────────────────────────────────────────────

// Converts an ISO date string to "Xd Xh Xm remaining" or "Never"
std::string ExpiryCountdown(const std::string& expiry)
{
    if (expiry.empty() || expiry == "null" || expiry == "Never") return "Never";

    // Try to parse as unix timestamp
    char* end = nullptr;
    long long ts = std::strtoll(expiry.c_str(), &end, 10);

    // Not a unix timestamp — return as-is
    if (end == expiry.c_str() || ts <= 0) return expiry;

    long long now = static_cast<long long>(std::time(nullptr));
    long long rem = ts - now;
    if (rem <= 0) return "Expired";

    long long d = rem / 86400;
    long long h = (rem % 86400) / 3600;
    long long m = (rem % 3600)  / 60;
    long long s = rem % 60;

    std::string out;
    if (d > 0) out += std::to_string(d) + "d ";
    if (d > 0 || h > 0) out += std::to_string(h) + "h ";
    if (d > 0 || h > 0 || m > 0) out += std::to_string(m) + "m ";
    out += std::to_string(s) + "s";
    return out;
}

// ── Session keep-alive thread ─────────────────────────────────────────────────
// Runs in background — if user gets banned mid-session, app closes

std::atomic<bool> g_sessionValid{ true };

void SessionThread(SKAuth* auth)
{
    // Runs in background during cheat session.
    // Add a /sdk/ping or /sdk/validate call here if you want
    // to kick users the moment they get banned mid-session.
    while (g_sessionValid.load())
    {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        // Example: auto r = auth->Validate(); if (!r.ok) exit(1);
    }
}

// ── Print user info after login ───────────────────────────────────────────────

void PrintUserData(const SKAuth& auth)
{
    std::string expiry = ExpiryCountdown(auth.expires);

    Color(10);
    std::cout << "\n  >> Authentication successful!\n\n";
    Color(11);
    std::cout << "  +----------------------------------------------+\n";
    std::cout << "  |  Username  : " << std::left << std::setw(32) << auth.username << "|\n";
    std::cout << "  |  Plan      : " << std::left << std::setw(32) << auth.plan     << "|\n";
    std::cout << "  |  Expires   : " << std::left << std::setw(32) << expiry        << "|\n";
    if (!auth.email.empty())
    std::cout << "  |  Email     : " << std::left << std::setw(32) << auth.email    << "|\n";
    if (!auth.hwid.empty() && auth.hwid != "null")
    std::cout << "  |  HWID      : " << std::left << std::setw(32) << auth.hwid.substr(0, 16) + "..." << "|\n";
    std::cout << "  +----------------------------------------------+\n\n";
    Color(7);
}

// ── Login ─────────────────────────────────────────────────────────────────────

bool DoLogin(SKAuth& auth, Lockout& lockout)
{
    if (lockout.IsLocked()) {
        Color(12);
        std::cout << "\n  Too many failed attempts.\n";
        std::cout << "  Try again in " << lockout.SecondsLeft() << " seconds.\n";
        Color(7);
        std::cout << "\n  Press any key...";
        _getch();
        return false;
    }

    Banner();
    Color(11);
    std::cout << "  [ LOGIN ]\n\n";
    Color(7);

    std::string username, password;
    std::cout << "  Username : ";
    std::getline(std::cin, username);
    password = ReadPassword("  Password : ");

    std::cout << "\n  Authenticating...\n";
    auto result = auth.Login(username, password);

    if (result.ok) {
        PrintUserData(auth);

        // Ask to save credentials
        std::cout << "  Save credentials for auto-login next time? [y/N] : ";
        char c = static_cast<char>(_getch());
        std::cout << c << "\n";
        if (c == 'y' || c == 'Y') {
            SaveCredentials(username, password);
            Color(10);
            std::cout << "  Credentials saved.\n";
            Color(7);
        } else {
            ClearSavedCredentials();
        }

        lockout.Reset();
        Sleep(1200);
        return true;
    }

    Color(12);
    std::cout << "\n  [X]" << result.message << "\n";
    Color(7);
    lockout.RecordFail();

    if (lockout.IsLocked()) {
        std::cout << "  Too many failures — locked for 30 seconds.\n";
    }

    std::cout << "\n  Press any key...";
    _getch();
    return false;
}

// ── Register ──────────────────────────────────────────────────────────────────

void DoRegister(SKAuth& auth)
{
    Banner();
    Color(11);
    std::cout << "  [ REGISTER — new account with license key ]\n\n";
    Color(7);

    std::string user, pass, email, key;
    std::cout << "  Username    : "; std::getline(std::cin, user);
    pass = ReadPassword("  Password   : ");
    std::cout << "  Email       : "; std::getline(std::cin, email);
    std::cout << "  License Key : "; std::getline(std::cin, key);

    std::cout << "\n  Creating account...\n";
    auto result = auth.Register(user, pass, email, key);

    if (result.ok) {
        Color(10);
        std::cout << "\n  [OK]" << result.message << "\n";
        std::cout << "  You can now login with your username and password.\n";
        Color(7);
    } else {
        Color(12);
        std::cout << "\n  [X]" << result.message << "\n";
        Color(7);
    }

    std::cout << "\n  Press any key...";
    _getch();
}

// ── Upgrade — redeem a key on an existing account ─────────────────────────────

void DoUpgrade(SKAuth& auth)
{
    Banner();
    Color(11);
    std::cout << "  [ UPGRADE — extend or upgrade your plan ]\n\n";
    Color(7);

    std::string user, key;
    std::cout << "  Username    : "; std::getline(std::cin, user);
    std::cout << "  License Key : "; std::getline(std::cin, key);

    std::cout << "\n  Redeeming key...\n";
    auto result = auth.Redeem(user, key);

    if (result.ok) {
        Color(10);
        std::cout << "\n  [OK]" << result.message << "\n";
        Color(7);
    } else {
        Color(12);
        std::cout << "\n  [X]" << result.message << "\n";
        Color(7);
    }

    std::cout << "\n  Press any key...";
    _getch();
}

// ── Auto-login ────────────────────────────────────────────────────────────────

bool TryAutoLogin(SKAuth& auth)
{
    std::string user, pass, license;
    if (!LoadCredentials(user, pass, license)) return false;

    Banner();
    Color(11);
    std::cout << "  Auto-login in progress...\n";
    Color(7);

    // Only username+password auto-login is supported
    // License keys are one-time registration only
    if (user.empty() || pass.empty()) {
        ClearSavedCredentials();
        return false;
    }

    auto result = auth.Login(user, pass);

    if (result.ok) {
        PrintUserData(auth);
        Sleep(1000);
        return true;
    }

    // Saved creds failed — clear them
    Color(12);
    std::cout << "\n  [X]Auto-login failed: " << result.message << "\n";
    std::cout << "  Clearing saved session.\n";
    Color(7);
    ClearSavedCredentials();
    Sleep(1500);
    return false;
}

// ── Cheat menu ────────────────────────────────────────────────────────────────

void CheatMenu(SKAuth& auth)
{
    // Start session keep-alive in background
    std::thread sessionThread(SessionThread, &auth);
    sessionThread.detach();

    while (true)
    {
        Banner();
        Color(14);
        std::cout << "  " << auth.username << "  |  " << auth.plan << "  |  ";

        std::string exp = ExpiryCountdown(auth.expires);
        if (exp == "Never") Color(10); else Color(11);
        std::cout << exp << " remaining\n\n";
        Color(7);

        // Free features
        Color(7);
        std::cout << "  [ FREE ]\n";
        std::cout << "    [1] No Recoil\n";
        std::cout << "    [2] Crosshair\n\n";

        // Paid features
        if (auth.IsPaid()) {
            Color(7);
            std::cout << "  [ PAID ]\n";
            std::cout << "    [3] Aimbot\n";
            std::cout << "    [4] ESP\n";
            std::cout << "    [5] Speed Hack\n\n";
        } else {
            Color(8);
            std::cout << "  [ PAID — upgrade at discord.gg/tWwUSPh5GT ]\n";
            std::cout << "    [3] Aimbot     (locked)\n";
            std::cout << "    [4] ESP        (locked)\n";
            std::cout << "    [5] Speed Hack (locked)\n\n";
            Color(7);
        }

        std::cout << "    [5] Check server message\n\n";
        std::cout << "    [0] Exit\n\n  > ";
        int choice = _getch() - '0';
        std::cout << choice << "\n\n";

        switch (choice)
        {
        case 1: Color(10); std::cout << "  No Recoil enabled.\n";  Color(7); break;
        case 2: Color(10); std::cout << "  Crosshair enabled.\n";  Color(7); break;

        case 3: case 4: case 5:
            if (auth.IsPaid()) {
                Color(10);
                std::cout << "  Feature " << choice << " enabled.\n";
                Color(7);
            } else {
                Color(12);
                std::cout << "  [X]Requires paid plan.\n";
                std::cout << "    Buy at discord.gg/tWwUSPh5GT\n";
                Color(7);
            }
            break;

        case 5: {
            // GetVar — fetch a message/value set in your dashboard
            // Dashboard → Settings → Variables → add "message" key
            std::string msg = auth.GetVar("message");
            Color(11);
            std::cout << "  Server message: " << (msg.empty() ? "(no variable set)" : msg) << "\n";
            Color(7);
            break;
        }
        case 0:
            g_sessionValid = false;
            return;
        }

        Sleep(800);
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

int main()
{
    // Set UTF-8 output + hide blinking cursor
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    CONSOLE_CURSOR_INFO cci{ 1, FALSE };
    SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cci);
    SetConsoleTitleA("Script Kittens Loader");

    // Init auth with XOR-obfuscated strings
    SKAuth auth(APP_ID, APP_VERSION);

    Lockout lockout;

    // Try auto-login from saved session
    if (TryAutoLogin(auth)) {
        CheatMenu(auth);
        return 0;
    }

    // Main menu
    while (true)
    {
        Banner();
        std::cout << "  [1] Login\n";
        std::cout << "  [2] Register        (need a license key)\n";
        std::cout << "  [3] Upgrade         (extend existing account)\n";
        std::cout << "  [4] Exit\n\n";
        std::cout << "  > ";

        int choice = _getch() - '0';
        std::cout << "\n";

        switch (choice)
        {
        case 1:
            if (DoLogin(auth, lockout))
                CheatMenu(auth);
            break;
        case 2:
            DoRegister(auth);
            break;
        case 3:
            DoUpgrade(auth);
            break;
        case 4:
            return 0;
        }
    }
}
