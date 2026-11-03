<div align="center">

# CatCrypt — C++ SDK Example

**A C++17 SDK for [CatCrypt](https://auth.script-kittens.com). WinHTTP only — zero external dependencies.**

</div>

---

## Files

| File | What it is |
| :--- | :--- |
| `SKAuth.h` | Header-only SDK — `#include` it in any Windows C++ project |

Requires: C++17, Windows 10 SDK. Link `winhttp.lib` (`#pragma comment` already in the header).

## Quick start

```bash
git clone https://github.com/ScriptKittenss/CatCrypt-CPP-Example.git
```

```cpp
#include "SKAuth.h"

SKAuth auth("YOUR_APP_ID", "1.0");

auto res = auth.Login("username", "password");
if (!res.ok) {
    MessageBoxA(NULL, res.message.c_str(), "Login failed", MB_ICONERROR);
    return 1;
}

printf("Welcome %s! Plan: %s\n", auth.username.c_str(), auth.plan.c_str());

if (auth.IsPaid()) {
    // unlock premium features
}

// heartbeat every few minutes while your tool runs
auto v = auth.Validate();
if (!v.ok) {
    // banned / expired / HWID changed — close the tool
    return 1;
}
```

## API reference

| Method | Description |
| :--- | :--- |
| `SKAuth(appId, version = "1.0")` | Create the client. Computes the machine HWID. |
| `Login(user, pass)` → `AuthResult{ok, message}` | Authenticate. On success fills `username`, `plan`, `expires`, `email`, `apiKey`, `hwid`. On failure show `message` as-is. |
| `Register(user, pass, email = "", key = "")` | Create an account. `key` is optional. |
| `Redeem(user, key)` | Apply a license key to an existing account. |
| `Validate()` | Heartbeat — call every few minutes. Kicks banned/expired users, syncs plan changes. Needs a login first. |
| `GetVar(name)` | Read a runtime variable (dashboard → Settings → Variables). Returns the value, or the server message when missing. |
| `DownloadFile(fileId, savePath)` | Download a file from the Runtime Vault (dashboard → Files). Returns `true` on success. Needs a login first. |
| `IsPaid()` | `true` when the plan isn't `free` (starter, pro, …). |
| `GetHWID()` | The machine HWID (SHA256, 32 hex chars). Same machine gives the same HWID in the Python and C# SDKs. |

## Notes

- The App ID is public. Never put your app secret, a password, or a license key in source code.
- `version` must match the version set in your dashboard, or login returns "Update required".
- Logins are rate limited (15/min per IP), registrations 5 per 5 minutes per IP.
- Full endpoint docs: https://auth.script-kittens.com → Documentation.

---

<div align="center">
<sub>Powered by <b>CatCrypt</b> • <a href="https://github.com/ScriptKittenss">ScriptKittenss</a></sub>
</div>
