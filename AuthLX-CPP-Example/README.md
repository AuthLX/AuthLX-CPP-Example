# AuthLX-CPP-Example

Official, production-ready C++ SDK and example application for [AuthLX](https://authlx.com) — the next-generation authentication, licensing, and security platform for desktop software.

Designed for high performance, zero external third-party DLL dependencies, and massive scale.

---

## 🌟 Features

- **Zero-Secret Binary Mode (Ed25519 RFC 8032)**: Asymmetric detached response verification means your client secret is never embedded in the compiled binary.
- **Zero Third-Party DLLs**: Standalone cryptographic verifiers for RFC 8032 Ed25519 and HMAC-SHA256 with pure Win32 / standard library linkage.
- **Anti-Tamper & Memory Integrity**: Real-time executable checksum verification, TLS certificate chain pinning, and memory anti-patching.
- **Hardware ID (HWID) Locking**: Multi-factor machine binding (CPU, motherboard, BIOS, Windows volume GUID).
- **Auto-Updater Engine**: In-place binary self-updating with staging backup and atomic relaunch.
- **Background Ban & Session Monitor**: Background heartbeat polling with instant exit on revocation.
- **Encrypted Remote Variables & In-App Chat**: Access cloud-managed variables and secure real-time customer support chat.

---

## 🚀 Quick Start

### 1. Zero-Secret Configuration

Open `main.cpp` and initialize the SDK with your application details:

```cpp
#include "AuthLX/authlx.hpp"

// Zero-Secret Mode: Leave secret empty and pass the public_key
AuthLX::api authlxapp(
    "MyApp",                                                                    // Application Name
    "YOUR-APP-UUID-HERE",                                                       // App ID / Owner ID from Dashboard
    "",                                                                         // Secret (Empty = Zero-Secret Mode)
    "1.0",                                                                      // Version
    AuthLX::others::get_checksum(),                                             // Executable Checksum
    "https://api.authlx.com/api/v3/client",                                     // API v3 Client Endpoint
    "f1c773b031489f4ae17d08b7aa83b8dc9035cbf73db5c8bd8cb9cfafd234d763"        // Ed25519 Public Key
);

int main() {
    authlxapp.init();

    // Authenticate with user credentials
    if (!authlxapp.login("username", "password")) {
        std::cout << "Login failed: " << authlxapp.last_message << std::endl;
        return 1;
    }

    std::cout << "Authenticated! Welcome, " << authlxapp.user_data.username << std::endl;
    return 0;
}
```

### 2. Building

Open `example Cpp AuthLX.sln` in Visual Studio 2022:
- Select **Release | x64** or **Release | x86**.
- Build Solution (`Ctrl + Shift + B`).

---

## 📁 Repository Structure

```
AuthLX-CPP-Example/
├── AuthLX/
│   ├── authlx.hpp        # Core SDK header
│   ├── authlx.cpp        # SDK implementation (WinINet, Anti-Debug, Memory Checks)
│   ├── ed25519.hpp       # Self-contained RFC 8032 Ed25519 verifier (Zero DLLs)
│   └── json.hpp          # Modern JSON parser
├── main.cpp              # Interactive console test suite
└── example Cpp AuthLX.sln
```

---

## 📜 License

Licensed under the MIT License. Free for commercial and personal use with AuthLX.
