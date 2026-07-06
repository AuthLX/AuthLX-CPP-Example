# AuthLX C++ Integration Example & SDK

[![C++ Version](https://img.shields.io/badge/C%2B%2B-17%2F20-blue.svg?style=flat-square)](https://en.wikipedia.org/wiki/C%2B%2B)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg?style=flat-square)](https://microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE.txt)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg?style=flat-square)](#)

A professional C++ reference implementation demonstrating integration with **AuthLX**, a premium authentication, licensing, and security platform. This repository contains both a console-based SDK wrapper and a complete windowed DirectX 11 + ImGui application demonstrating production-ready integration patterns, anti-reverse engineering techniques, secure cryptography, and structured logging.

---

## Table of Contents

- [Key Features](#key-features)
- [Repository Structure](#repository-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Building the Project](#building-the-project)
- [SDK Architecture & API Guide](#sdk-architecture--api-guide)
  - [Initialization](#initialization)
  - [User Login](#user-login)
  - [User Registration](#user-registration)
- [Structured Logging System](#structured-logging-system)
- [Security Features](#security-features)
  - [HMAC Anti-Tamper Signatures](#hmac-anti-tamper-signatures)
  - [Anti-Debugging & Reverse Engineering](#anti-debugging--reverse-engineering)
  - [Host Whitelisting](#host-whitelisting)
- [Contributing](#contributing)
- [License](#license)

---

## Key Features

* **Dual-Target Implementations**: 
  * A lightweight CLI application (`AuthLX-CPP-Example`) demonstrating raw API operations.
  * A rich, hardware-accelerated DirectX 11 + ImGui menu (`Fake lags IMGUI`) demonstrating asynchronous background operations, interactive loaders, and notification triggers.
* **Modern Thread-Safe Logger**: Integrates a clean, concurrent, multi-level colored logger outputting to both console and log files (`logs/sdk.log`).
* **Non-Blocking Asynchronous Flows**: UI logins run on worker threads to prevent application hangs during slow network roundtrips.
* **Safe Date/Time Parsing**: Custom ISO-8601 validation protecting against CRT standard library crashes on invalid dates/times.
* **Anti-Debugging & Integrity Verification**: Built-in debugger detection and file hash integrity checking.

---

## Repository Structure

```
├── AuthLX-CPP-Example/            # CLI Example Project using AuthLX
│   ├── AuthLX/                    # Core AuthLX SDK files
│   │   ├── authlx.cpp             # API request construction, encryption, and parsing
│   │   ├── authlx.hpp             # Class definition, configuration structures
│   │   ├── Logger.hpp             # Thread-safe logging implementation
│   │   ├── json.hpp               # Modern JSON parser (nlohmann/json)
│   │   └── skCrypter.h            # Compile-time string encryption utility
│   └── main.cpp                   # CLI program entry point and menu
│
├── Fake lags IMGUI/               # DirectX 11 + ImGui GUI Example Project
│   └── examples/
│       └── example_win32_directx11/
│           ├── Auth/              # GUI-Adapted AuthLX wrapper files
│           │   ├── ManualAuth.hpp # Wrapper managing login/register worker threads
│           │   ├── Logger.hpp     # Multi-level structured logger
│           │   └── ...
│           ├── UI/
│           │   └── LoginScreen.h  # ImGui implementation of the Login Screen
│           └── main.cpp           # App lifecycle, rendering thread, and WndProc
│
└── example Cpp AuthLX.sln         # Main Visual Studio 2022 Solution
```

---

## Getting Started

### Prerequisites

* **Operating System**: Windows 10 or Windows 11.
* **IDE**: [Visual Studio 2022](https://visualstudio.microsoft.com/) (Community, Professional, or Enterprise).
* **Workloads**: 
  * "Desktop development with C++"
  * "Game development with C++" (for DirectX 11 libraries/SDK dependencies)
* **Windows SDK**: Version 10.0.19041.0 or newer.

### Building the Project

1. Clone this repository to your local system:
   ```bash
   git clone https://github.com/your-username/AuthLX-CPP-Example.git
   ```
2. Open the solution file `example Cpp AuthLX.sln` inside Visual Studio 2022.
3. Set the active build configuration to **Release** and platform to **x64**.
4. Right-click the solution in Solution Explorer and select **Rebuild Solution**.
5. The compiled executables will be generated in the output directory:
   * CLI: `<root>/x64/Release/AuthLX-CPP-Example.exe`
   * GUI: `<root>/x64/Release/example_win32_directx11.exe`

---

## SDK Architecture & API Guide

The `AuthLX::Api` class manages configuration, session tokens, network requests (via WinHTTP), and local security checks.

### Initialization

Create an instance of `AuthLX::Api` by passing your application configuration parameters. The constructor automatically initializes the WinHTTP session and performs checking on the server:

```cpp
#include "AuthLX/authlx.hpp"

// Setup App Credentials
std::string name = "MyCheatApp";
std::string ownerid = "your-owner-id-uuid";
std::string secret = "your-app-secret-sha256";
std::string version = "1.0";

AuthLX::Api authlx(name, ownerid, version, secret);
```

### User Login

Authenticate the user using username and password credentials:

```cpp
if (authlx.login("username", "password")) {
    LOG_INFO("Login successful. Expiry: " << authlx.user_data.expires);
} else {
    LOG_ERROR("Login failed: " << authlx.last_message);
}
```

### User Registration

Register a new account using a license key (an email is generated automatically on the backend wrapper if not provided):

```cpp
if (authlx.registerAccount("username", "email@domain.com", "password", "LICENSE-KEY-HERE")) {
    LOG_INFO("Account registered successfully!");
} else {
    LOG_ERROR("Registration failed: " << authlx.last_message);
}
```

---

## Structured Logging System

The project includes a robust, thread-safe logging framework (`AuthLX::Logger`) located in `Logger.hpp`.

### Configurations

To initialize the logger to write to a log file and output to the standard console window:

```cpp
#include "Auth/Logger.hpp"

// Write to logs/sdk.log, enable console output, set level to DEBUG
AuthLX::Logger::getInstance().init("logs/sdk.log", true, AuthLX::LogLevel::DebugLevel);
```

### Logging Macros

The logger provides preprocessor macros that automatically capture file path, line number, and function scopes at compile-time:

```cpp
LOG_DEBUG("Constructing packets...");
LOG_INFO("Login successful for user: " << username);
LOG_WARN("Session timeout approaching.");
LOG_ERROR("Database write operation failed.");
```

### Log Levels

1. `DEBUG` (Gray): Useful for detailing granular execution workflows or variable states.
2. `INFO` (Cyan): Primary application milestone logs (network connection, success status).
3. `WARN` (Yellow): Recoverable warnings or threshold alerts.
4. `ERROR` (Red): Fatal errors, exceptions, or security alerts.

---

## Security Features

### HMAC Anti-Tamper Signatures

If a `client_secret` is configured, every request sent to the API endpoint is signed with an HMAC-SHA256 signature containing a hash of the binary, a timestamp, and a random cryptographic nonce. This prevents:
* **Man-In-The-Middle (MITM) attacks**: Captured packets cannot be manipulated and replayed.
* **Replay Attacks**: The server rejects requests containing expired timestamps or duplicate nonces.

### Anti-Debugging & Reverse Engineering

The SDK includes standard Win32 API checks to prevent reverse engineers from attaching tools to analyze your product at runtime:

```cpp
// Throws a warning and shuts down the process if a debugger is attached.
AuthLX::Others::anti_debug();
```

### Host Whitelisting

Prevent DNS spoofing or local hosts file redirection attacks by specifying exactly which domains the SDK is permitted to make requests to:

```cpp
authlx.set_allowed_hosts({ "authlx.com" });
```

---

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/NewFeature`.
3. Commit your changes: `git commit -m 'Add NewFeature'`.
4. Push to your branch: `git push origin feature/NewFeature`.
5. Create a Pull Request.

---

## License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) file for details.
