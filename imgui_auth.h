// ============================================================
//  imgui_auth.h  —  Drop-in ImGui auth for internal cheats
//  Copy this + SKAuth.h into your existing ImGui cheat project.
//  Requires: ImGui already set up in your project.
// ============================================================
//
//  HOW TO ADD TO YOUR CHEAT — 3 steps:
//
//  Step 1: In DllMain or your init thread:
//    AuthSystem::Init("YOUR_APP_ID");
//
//  Step 2: In your existing render function, add TWO lines:
//    void Render() {
//        ImGui::NewFrame();
//        AuthSystem::Render();                    // ← ADD THIS
//        if (AuthSystem::IsLoggedIn()) {          // ← ADD THIS
//            YourCheatMenu();
//        }
//        ImGui::Render();
//    }
//
//  Step 3: Gate paid features:
//    if (AuthSystem::IsPaid()) { /* paid only */ }
//
// ============================================================
#pragma once

#include "SKAuth.h"
#include <imgui.h>
#include <thread>
#include <atomic>
#include <string>

namespace AuthSystem
{
    enum class State { Menu, Login, Register, Checking, LoggedIn };

    static SKAuth*              g_auth    = nullptr;
    static std::atomic<State>   g_state   = State::Menu;
    static std::string          g_msg     = "";
    static bool                 g_msgOk   = false;

    static char g_user[64]  = {};
    static char g_pass[64]  = {};
    static char g_email[64] = {};
    static char g_key[64]   = {};

    // ── Call once at DLL attach / startup ─────────────────────────────────────
    inline void Init(const std::string& appId, const std::string& version = "1.0")
    {
        g_auth = new SKAuth(appId, version);
    }

    // ── Call every frame inside your render loop ──────────────────────────────
    inline void Render()
    {
        if (g_state == State::LoggedIn) return;

        // Center window on screen
        ImVec2 center = ImGui::GetMainViewport()->GetCenter();
        ImGui::SetNextWindowPos(center, ImGuiCond_Always, { 0.5f, 0.5f });
        ImGui::SetNextWindowSize({ 360, 300 }, ImGuiCond_Always);
        ImGui::SetNextWindowBgAlpha(0.97f);

        ImGuiWindowFlags flags =
            ImGuiWindowFlags_NoTitleBar  |
            ImGuiWindowFlags_NoResize    |
            ImGuiWindowFlags_NoMove      |
            ImGuiWindowFlags_NoScrollbar;

        ImGui::Begin("##auth", nullptr, flags);

        // Header
        ImGui::SetCursorPosX((360.f - ImGui::CalcTextSize("CATCRYPT AUTH").x) * 0.5f);
        ImGui::TextColored({ 0.87f, 0.55f, 0.30f, 1.f }, "CATCRYPT AUTH");
        ImGui::Separator();
        ImGui::Spacing();

        // Checking spinner
        if (g_state == State::Checking)
        {
            ImGui::SetCursorPosX(100);
            ImGui::TextColored({ 0.6f, 0.6f, 0.6f, 1.f }, "Authenticating...");
            ImGui::End();
            return;
        }

        // Tab bar — Login / Register
        if (ImGui::BeginTabBar("##tabs"))
        {
            // ── LOGIN TAB ─────────────────────────────────────────────────────
            if (ImGui::BeginTabItem("  Login  "))
            {
                if (g_state == State::Register) { g_msg = ""; g_state = State::Login; }
                ImGui::Spacing();

                ImGui::Text("Username");
                ImGui::SetNextItemWidth(300);
                ImGui::InputText("##u", g_user, sizeof(g_user));

                ImGui::Text("Password");
                ImGui::SetNextItemWidth(300);
                ImGui::InputText("##p", g_pass, sizeof(g_pass), ImGuiInputTextFlags_Password);

                ImGui::Spacing();

                // Error message
                if (!g_msg.empty() && !g_msgOk)
                    ImGui::TextColored({ 0.9f, 0.3f, 0.3f, 1.f }, "%s", g_msg.c_str());

                ImGui::Spacing();
                ImGui::SetCursorPosX((360.f - 200.f) * 0.5f);

                if (ImGui::Button("Sign In", { 200, 32 }))
                {
                    g_msg   = "";
                    g_state = State::Checking;

                    // Auth runs in background thread — render loop never freezes
                    std::thread([&]()
                    {
                        auto r = g_auth->Login(g_user, g_pass);
                        if (r.ok)
                        {
                            g_state = State::LoggedIn;
                        }
                        else
                        {
                            g_msg   = r.message;
                            g_msgOk = false;
                            g_state = State::Login;
                        }
                    }).detach();
                }

                ImGui::EndTabItem();
            }

            // ── REGISTER TAB ──────────────────────────────────────────────────
            if (ImGui::BeginTabItem("  Register  "))
            {
                if (g_state == State::Login) { g_msg = ""; g_state = State::Register; }
                ImGui::Spacing();

                ImGui::Text("Username");
                ImGui::SetNextItemWidth(300);
                ImGui::InputText("##ru", g_user, sizeof(g_user));

                ImGui::Text("Password");
                ImGui::SetNextItemWidth(300);
                ImGui::InputText("##rp", g_pass, sizeof(g_pass), ImGuiInputTextFlags_Password);

                ImGui::Text("Email (optional)");
                ImGui::SetNextItemWidth(300);
                ImGui::InputText("##re", g_email, sizeof(g_email));

                ImGui::Text("License Key");
                ImGui::SetNextItemWidth(300);
                ImGui::InputText("##rk", g_key, sizeof(g_key));

                ImGui::Spacing();

                if (!g_msg.empty())
                {
                    auto col = g_msgOk
                        ? ImVec4{ 0.3f, 0.9f, 0.4f, 1.f }
                        : ImVec4{ 0.9f, 0.3f, 0.3f, 1.f };
                    ImGui::TextColored(col, "%s", g_msg.c_str());
                }

                ImGui::Spacing();
                ImGui::SetCursorPosX((360.f - 200.f) * 0.5f);

                if (ImGui::Button("Create Account", { 200, 32 }))
                {
                    g_msg   = "";
                    g_state = State::Checking;

                    std::thread([&]()
                    {
                        auto r = g_auth->Register(g_user, g_pass, g_email, g_key);
                        g_msg   = r.message;
                        g_msgOk = r.ok;
                        g_state = State::Register;
                    }).detach();
                }

                ImGui::EndTabItem();
            }

            ImGui::EndTabBar();
        }

        ImGui::End();
    }

    // ── Query functions — use these in your cheat code ─────────────────────────
    inline bool        IsLoggedIn() { return g_state == State::LoggedIn; }
    inline bool        IsPaid()     { return g_auth && g_auth->IsPaid(); }
    inline std::string GetPlan()    { return g_auth ? g_auth->plan     : "free"; }
    inline std::string GetUser()    { return g_auth ? g_auth->username : ""; }
}
