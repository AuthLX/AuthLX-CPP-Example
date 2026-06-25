#include "authlx.hpp"
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <sddl.h> // For ConvertSidToStringSidW
#include <sstream>
#include <iomanip>
#include <fstream>
#include <random>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace AuthLX {

    // Helper: Convert string to wstring
    static std::wstring to_wstring(const std::string& str) {
        if (str.empty()) return L"";
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
        std::wstring wstrTo(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
        return wstrTo;
    }

    // Helper: Convert wstring to string
    static std::string to_string(const std::wstring& wstr) {
        if (wstr.empty()) return "";
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
        return strTo;
    }

    // Helper: Parse URL into host and path prefix
    static void parse_url(const std::string& url, std::wstring& host, std::wstring& path_prefix, INTERNET_PORT& port) {
        URL_COMPONENTS urlComp = { 0 };
        urlComp.dwStructSize = sizeof(urlComp);

        std::wstring wurl = to_wstring(url);

        urlComp.dwSchemeLength = (DWORD)-1;
        urlComp.dwHostNameLength = (DWORD)-1;
        urlComp.dwUrlPathLength = (DWORD)-1;

        if (WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlComp)) {
            host = std::wstring(urlComp.lpszHostName, urlComp.dwHostNameLength);
            path_prefix = std::wstring(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
            port = urlComp.nPort;
        } else {
            // Default fallback
            host = L"authlx.com";
            path_prefix = L"/api/v1/client";
            port = INTERNET_DEFAULT_HTTPS_PORT;
        }
    }

    static void fatal_error(const std::string& msg) {
        std::cerr << "\n[ERROR] " << msg << std::endl;
        std::cerr << "Press Enter to exit..." << std::endl;
        std::cin.clear();
        std::cin.sync();
        std::cin.get();
        ExitProcess(1);
    }

    // Helper: Generate random hex string of size
    static std::string generate_nonce(size_t len) {
        static const char hex_chars[] = "0123456789abcdef";
        std::random_device rd;
        std::mt19937 generator(rd());
        std::uniform_int_distribution<int> distribution(0, 15);
        std::string nonce;
        nonce.reserve(len);
        for (size_t i = 0; i < len; ++i) {
            nonce += hex_chars[distribution(generator)];
        }
        return nonce;
    }

    // Helper: HMAC-SHA256 using Windows CNG (BCrypt)
    static std::string hmac_sha256(const std::string& key, const std::string& msg) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status = 0;
        DWORD cbHashObject = 0, cbHash = 0, cbData = 0;
        PBYTE pbHashObject = NULL;
        PBYTE pbHash = NULL;

        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (status < 0) return "";

        status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
        if (status < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

        status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
        if (status < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

        pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
        pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);

        status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, (PUCHAR)key.c_str(), (ULONG)key.length(), 0);
        if (status >= 0) {
            status = BCryptHashData(hHash, (PUCHAR)msg.c_str(), (ULONG)msg.length(), 0);
            if (status >= 0) {
                status = BCryptFinishHash(hHash, pbHash, cbHash, 0);
            }
            BCryptDestroyHash(hHash);
        }

        std::stringstream ss;
        if (status >= 0) {
            for (DWORD i = 0; i < cbHash; i++) {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)pbHash[i];
            }
        }

        HeapFree(GetProcessHeap(), 0, pbHashObject);
        HeapFree(GetProcessHeap(), 0, pbHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        return ss.str();
    }

    // Helper: SHA256 of data using CNG
    static std::string sha256(const std::vector<uint8_t>& data) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status = 0;
        DWORD cbHashObject = 0, cbHash = 0, cbData = 0;
        PBYTE pbHashObject = NULL;
        PBYTE pbHash = NULL;

        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (status < 0) return "";

        status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
        if (status < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

        status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
        if (status < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

        pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
        pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);

        status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
        if (status >= 0) {
            status = BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
            if (status >= 0) {
                status = BCryptFinishHash(hHash, pbHash, cbHash, 0);
            }
            BCryptDestroyHash(hHash);
        }

        std::stringstream ss;
        if (status >= 0) {
            for (DWORD i = 0; i < cbHash; i++) {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)pbHash[i];
            }
        }

        HeapFree(GetProcessHeap(), 0, pbHashObject);
        HeapFree(GetProcessHeap(), 0, pbHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        return ss.str();
    }

    // ─── Constructor & Destructor ────────────────────────────────────────────

    Api::Api(std::string name, std::string ownerid, std::string version, std::string client_secret, std::string hash_to_check, std::string api_url)
        : name(name), ownerid(ownerid), version(version), client_secret(client_secret), api_url(api_url) {

        if (this->api_url.empty()) {
            this->api_url = "https://authlx.com/api/v1/client";
        }

        if (hash_to_check.empty()) {
            this->hash_to_check = Others::get_checksum();
        } else {
            this->hash_to_check = hash_to_check;
        }

        // Initialize WinHTTP Session with direct access (ignores system proxy - Anti-MITM)
        hSession = WinHttpOpen(
            L"AuthLX-SDK-CPP/1.0",
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );

        if (!hSession) {
            std::cerr << "AuthLX: Failed to initialize WinHTTP session." << std::endl;
            ExitProcess(1);
        }

        // Set reasonable timeouts (5s each) to fail fast and prevent hanging indefinitely
        WinHttpSetTimeouts(hSession, 5000, 5000, 5000, 5000);

        // Auto-initialize SDK
        init();
    }

    Api::~Api() {
        stop_ban_monitor();
        if (hSession) {
            WinHttpCloseHandle(hSession);
        }
    }

    // ─── Core lifecycle ──────────────────────────────────────────────────────

    void Api::init() {
        Others::anti_debug();

        nlohmann::json payload = {
            {"app_id", ownerid},
            {"name", name},
            {"version", version},
            {"secret", client_secret.empty() ? "NO_SECRET" : client_secret}
        };

        nlohmann::json response = do_request("/init", payload);

        if (!response.is_null() && response.value("status", "") == "success") {
            auto app_info = response.value("app_info", nlohmann::json::object());
            std::string server_version = app_info.value("version", version);
            std::string server_name = app_info.value("name", name);

            if (server_name != name) {
                std::cerr << "\n[SECURITY] Application name mismatch!" << std::endl;
                std::cerr << "  Expected: " << name << "  |  Server reports: " << server_name << std::endl;
                std::cerr << "  Exiting to prevent unauthorized execution." << std::endl;
                Sleep(3000);
                ExitProcess(1);
            }

            if (server_version != version) {
                std::cerr << "\n[UPDATE REQUIRED] Application version is outdated!" << std::endl;
                std::cerr << "  Current: " << version << "  |  Required: " << server_version << std::endl;
                std::string auto_update = app_info.value("auto_update_link", "");
                std::string webloader = app_info.value("webloader_link", "");
                if (!auto_update.empty()) {
                    std::cerr << "  Download: " << auto_update << std::endl;
                }
                if (!webloader.empty()) {
                    std::cerr << "  Webloader: " << webloader << std::endl;
                }
                Sleep(3000);
                ExitProcess(1);
            }

            initialized = true;
            hwid_method = app_info.value("hwid_method", "windows_user");

            if (debug) {
                std::cout << "[DEBUG] Hash mode: " << (client_secret.empty() ? "OFF" : "SECURE") << std::endl;
            }
        } else {
            std::string err_msg = "Failed to initialise. Check ownerid and network connectivity.";
            if (!response.is_null() && response.contains("message")) {
                err_msg = response.value("message", "");
            }
            fatal_error(err_msg);
        }
    }

    // ─── HMAC helper ─────────────────────────────────────────────────────────

    std::tuple<std::string, std::string, std::string> Api::compute_hash_signature() {
        std::string timestamp = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        std::string nonce = generate_nonce(32);
        std::string data_to_sign = hash_to_check + ":" + timestamp + ":" + nonce;
        std::string signature = hmac_sha256(client_secret, data_to_sign);
        return { signature, timestamp, nonce };
    }

    nlohmann::json Api::build_hash_payload() {
        nlohmann::json payload;
        payload["hash"] = hash_to_check;

        if (!client_secret.empty()) {
            std::string sig, ts, nonce;
            std::tie(sig, ts, nonce) = compute_hash_signature();
            payload["hash_signature"] = sig;
            payload["hash_timestamp"] = ts;
            payload["hash_nonce"] = nonce;
        }

        return payload;
    }

    // ─── Authentication ──────────────────────────────────────────────────────

    bool Api::login(std::string user, std::string password, std::string hwid) {
        checkinit();

        if (hwid.empty()) {
            hwid = Others::get_hwid(hwid_method);
        }

        nlohmann::json payload = {
            {"app_id", ownerid},
            {"username", user},
            {"password", password},
            {"hwid", hwid},
            {"version", version}
        };

        nlohmann::json hash_payload = build_hash_payload();
        for (auto& el : hash_payload.items()) {
            payload[el.key()] = el.value();
        }

        if (debug) {
            std::cout << "[DEBUG] login() hash mode: " << (client_secret.empty() ? "OFF" : "SECURE")
                      << ", hash: " << hash_to_check.substr(0, 16) << "..." << std::endl;
        }

        nlohmann::json response = do_request("/login", payload);

        if (!response.is_null() && response.value("status", "") == "success") {
            auto data = response.value("data", nlohmann::json::object());
            session_token = data.value("token", "");
            load_user_data(data.value("user", nlohmann::json::object()));

            if (!has_active_subscription()) {
                std::cerr << "Login Failed: Subscription has expired or is paused." << std::endl;
                session_token = "";
                user_data.is_authenticated = false;
                return false;
            }

            mark_authenticated();
            std::cout << "Successfully logged in as '" << user_data.username << "'!" << std::endl;
            return true;
        }

        std::string msg = response.is_null() ? "No server response." : response.value("message", "Login failed.");
        parse_ban_info(msg);
        std::cerr << "Login Failed: " << msg << std::endl;
        login_hint(msg);
        return false;
    }

    bool Api::registerAccount(std::string user, std::string email, std::string password, std::string license_key, std::string hwid) {
        checkinit();

        if (hwid.empty()) {
            hwid = Others::get_hwid(hwid_method);
        }

        nlohmann::json payload = {
            {"app_id", ownerid},
            {"username", user},
            {"email", email},
            {"password", password},
            {"license_key", license_key},
            {"hwid", hwid}
        };

        nlohmann::json hash_payload = build_hash_payload();
        for (auto& el : hash_payload.items()) {
            payload[el.key()] = el.value();
        }

        nlohmann::json response = do_request("/register", payload);

        if (!response.is_null() && response.value("status", "") == "success") {
            std::cout << response.value("message", "Registration successful!") << std::endl;
            return true;
        }

        std::string msg = response.is_null() ? "No server response." : response.value("message", "Registration failed.");
        parse_ban_info(msg);
        std::cerr << "Registration Failed: " << msg << std::endl;
        login_hint(msg);
        return false;
    }

    bool Api::webLogin(std::string user, std::string password) {
        checkinit();

        if (lockout_active()) {
            long long secs = lockout_remaining_ms() / 1000;
            std::cerr << "Locked out due to multiple failed attempts. Try again in " << secs << "s." << std::endl;
            return false;
        }

        nlohmann::json payload = {
            {"app_id", ownerid},
            {"username", user},
            {"password", password}
        };

        nlohmann::json response = do_request("/web-login", payload);

        if (!response.is_null() && response.value("status", "") == "success") {
            auto data = response.value("data", nlohmann::json::object());
            session_token = data.value("token", "");
            load_user_data(data.value("user", nlohmann::json::object()));
            reset_lockout();

            if (!has_active_subscription()) {
                std::cerr << "Web Login Failed: Subscription has expired or is paused." << std::endl;
                session_token = "";
                user_data.is_authenticated = false;
                return false;
            }

            mark_authenticated();
            std::cout << "Successfully logged in (Web)!" << std::endl;
            return true;
        }

        record_login_fail();
        Sleep(2000); // 2-second bad input delay
        std::string msg = response.is_null() ? "No server response." : response.value("message", "Web login failed.");
        parse_ban_info(msg);
        std::cerr << "Web Login Failed: " << msg << std::endl;
        return false;
    }

    bool Api::registerWeb(std::string user, std::string email, std::string password, std::string license_key) {
        return registerAccount(user, email, password, license_key, "WEB_REGISTRATION");
    }

    bool Api::logout() {
        checkinit();
        if (session_token.empty()) {
            std::cerr << "Not logged in." << std::endl;
            return false;
        }

        nlohmann::json payload = {
            {"app_id", ownerid},
            {"session_token", session_token}
        };

        nlohmann::json response = do_request("/logout", payload);

        if (!response.is_null() && response.value("status", "") == "success") {
            std::cout << response.value("message", "Logged out.") << std::endl;
            session_token = "";
            user_data = UserData();
            return true;
        }

        std::string msg = response.is_null() ? "No server response." : response.value("message", "Logout failed.");
        std::cerr << msg << std::endl;
        return false;
    }

    // ─── License operations ──────────────────────────────────────────────────

    bool Api::upgrade(std::string user, std::string license_key) {
        checkinit();

        nlohmann::json payload = {
            {"app_id", ownerid},
            {"username", user},
            {"license_key", license_key}
        };

        nlohmann::json response = do_request("/upgrade", payload);

        if (!response.is_null() && response.value("status", "") == "success") {
            std::cout << response.value("message", "License successfully applied!") << std::endl;
            return true;
        }

        std::string msg = response.is_null() ? "No response." : response.value("message", "Upgrade failed.");
        parse_ban_info(msg);
        std::cerr << "Upgrade Failed: " << msg << std::endl;
        return false;
    }

    // ─── Verification ────────────────────────────────────────────────────────

    bool Api::check() {
        checkinit();
        if (session_token.empty()) {
            return false;
        }

        nlohmann::json payload = {
            {"app_id", ownerid},
            {"token", session_token}
        };

        nlohmann::json response = do_request("/verify-session", payload);
        return (!response.is_null() && response.value("status", "") == "success");
    }

    bool Api::verifyToken(std::string standalone_token) {
        checkinit();

        nlohmann::json payload = {
            {"app_id", ownerid},
            {"token", standalone_token}
        };

        nlohmann::json response = do_request("/verify-token", payload);

        if (!response.is_null() && response.value("status", "") == "success") {
            std::cout << "Token is valid!" << std::endl;
            return true;
        }

        std::string msg = response.is_null() ? "No response." : response.value("message", "Invalid or banned token.");
        parse_ban_info(msg);
        std::cerr << msg << std::endl;
        return false;
    }

    // ─── Account management ──────────────────────────────────────────────────

    bool Api::changeUsername(std::string new_username) {
        checkinit();
        if (session_token.empty()) {
            std::cerr << "Must be logged in to change username." << std::endl;
            return false;
        }

        nlohmann::json payload = {
            {"app_id", ownerid},
            {"session_token", session_token},
            {"new_username", new_username}
        };

        nlohmann::json response = do_request("/change-username", payload);

        if (!response.is_null() && response.value("status", "") == "success") {
            std::cout << response.value("message", "Username changed!") << std::endl;
            user_data.username = new_username;
            return true;
        }

        std::string msg = response.is_null() ? "No response." : response.value("message", "Failed.");
        std::cerr << "changeUsername Failed: " << msg << std::endl;
        return false;
    }

    bool Api::forgot(std::string user, std::string new_password, std::string hwid) {
        checkinit();
        if (hwid.empty()) {
            hwid = Others::get_hwid(hwid_method);
        }

        nlohmann::json payload = {
            {"app_id", ownerid},
            {"username", user},
            {"hwid", hwid},
            {"new_password", new_password}
        };

        nlohmann::json response = do_request("/forgot", payload);

        if (!response.is_null() && response.value("status", "") == "success") {
            std::cout << response.value("message", "Password reset!") << std::endl;
            return true;
        }

        std::string msg = response.is_null() ? "No response." : response.value("message", "Failed.");
        std::cerr << "forgot Failed: " << msg << std::endl;
        return false;
    }

    // ─── Subscription & Expiry helpers ───────────────────────────────────────

    bool Api::has_active_subscription() {
        return expiry_remaining() > 0.0;
    }

    double Api::expiry_remaining() {
        if (user_data.expires.empty()) {
            return 0.0;
        }

        // Standard ISO8601 parsing helper
        // Expecting: YYYY-MM-DDTHH:MM:SSZ or YYYY-MM-DDTHH:MM:SS+00:00
        std::string s = user_data.expires;
        if (s.back() == 'Z') {
            s.pop_back();
        } else {
            size_t plus_pos = s.find('+');
            if (plus_pos != std::string::npos) {
                s = s.substr(0, plus_pos);
            }
        }

        std::tm t = {};
        std::stringstream ss(s);
        char sep;
        ss >> t.tm_year >> sep >> t.tm_mon >> sep >> t.tm_mday >> sep >> t.tm_hour >> sep >> t.tm_min >> sep >> t.tm_sec;
        
        t.tm_year -= 1900;
        t.tm_mon -= 1;
        t.tm_isdst = -1;

        // Convert UTC time to epoch
        time_t exp_time = _mkgmtime(&t);
        time_t now = time(nullptr);

        double diff = difftime(exp_time, now);
        return diff > 0.0 ? diff : 0.0;
    }

    // ─── Auth runtime state ──────────────────────────────────────────────────

    void Api::mark_authenticated() {
        user_data.is_authenticated = true;
        user_data.auth_runtime_start = (double)time(nullptr);
    }

    void Api::refresh_auth_runtime() {
        user_data.auth_runtime_start = (double)time(nullptr);
    }

    void Api::reset_auth_runtime() {
        refresh_auth_runtime();
    }

    // ─── Host Locking & Key Pinning ──────────────────────────────────────────

    void Api::set_allowed_hosts(std::vector<std::string> hosts) {
        allowed_hosts = hosts;
    }

    void Api::add_allowed_host(std::string host) {
        if (std::find(allowed_hosts.begin(), allowed_hosts.end(), host) == allowed_hosts.end()) {
            allowed_hosts.push_back(host);
        }
    }

    void Api::clear_allowed_hosts() {
        allowed_hosts.clear();
    }

    void Api::set_pinned_public_keys(std::vector<std::string> keys) {
        pinned_public_keys = keys;
    }

    void Api::add_pinned_public_key(std::string key) {
        if (std::find(pinned_public_keys.begin(), pinned_public_keys.end(), key) == pinned_public_keys.end()) {
            pinned_public_keys.push_back(key);
        }
    }

    void Api::clear_pinned_public_keys() {
        pinned_public_keys.clear();
    }

    // ─── Secure Cryptography (XOR / Seal - from templates) ───────────────────

    void Api::enable_secure_strings() {
        secure_strings_enabled = true;
    }

    void Api::derive_secure_key(std::string material) {
        // Derive key: SHA256 of material
        std::vector<uint8_t> bytes(material.begin(), material.end());
        std::string hex_hash = sha256(bytes);
        
        secure_key.resize(32);
        for (size_t i = 0; i < 32; ++i) {
            std::string hex_byte = hex_hash.substr(i * 2, 2);
            secure_key[i] = (uint8_t)std::stoul(hex_byte, nullptr, 16);
        }
    }

    std::string Api::xor_crypt_field(std::string data, std::string key) {
        std::string result = data;
        for (size_t i = 0; i < data.size(); ++i) {
            result[i] = data[i] ^ key[i % key.size()];
        }
        return result;
    }

    std::string Api::compute_auth_seal(std::string payload) {
        if (secure_key.empty()) return "";
        std::string key_str(secure_key.begin(), secure_key.end());
        return hmac_sha256(key_str, payload);
    }

    // ─── Ban monitor ─────────────────────────────────────────────────────────

    void Api::start_ban_monitor(int interval_seconds) {
        if (ban_monitor_active) {
            return;
        }

        ban_monitor_active = true;
        ban_monitor_thread = std::thread(&Api::ban_monitor_loop, this, interval_seconds);
        
        if (debug) {
            std::cout << "[DEBUG] Ban monitor started." << std::endl;
        }
    }

    void Api::stop_ban_monitor() {
        if (ban_monitor_active) {
            ban_monitor_active = false;
            if (ban_monitor_thread.joinable()) {
                ban_monitor_thread.join();
            }
            if (debug) {
                std::cout << "[DEBUG] Ban monitor stopped." << std::endl;
            }
        }
    }

    bool Api::ban_monitor_running() {
        return ban_monitor_active;
    }

    void Api::ban_monitor_loop(int interval) {
        while (ban_monitor_active) {
            if (session_token.empty()) {
                Sleep(1000);
                continue;
            }

            if (debug) {
                std::cout << "[DEBUG] Ban monitor: checking session..." << std::endl;
            }

            if (!check() || !has_active_subscription()) {
                std::cerr << "\n[SECURITY] Session revoked, expired, or account paused at runtime." << std::endl;
                user_data.is_authenticated = false;
                session_token = "";

#ifdef _WIN32
                HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
                if (hInput != INVALID_HANDLE_VALUE && hInput != nullptr) {
                    INPUT_RECORD ir[2] = { 0 };

                    ir[0].EventType = KEY_EVENT;
                    ir[0].Event.KeyEvent.bKeyDown = TRUE;
                    ir[0].Event.KeyEvent.wRepeatCount = 1;
                    ir[0].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
                    ir[0].Event.KeyEvent.wVirtualScanCode = (WORD)MapVirtualKey(VK_RETURN, 0); // MAPVK_VK_TO_VSC is 0
                    ir[0].Event.KeyEvent.uChar.UnicodeChar = L'\r';

                    ir[1] = ir[0];
                    ir[1].Event.KeyEvent.bKeyDown = FALSE;

                    DWORD written = 0;
                    WriteConsoleInput(hInput, ir, 2, &written);
                }
#endif
                break;
            }

            // Sleep in small increments to respond quickly to shutdown request
            for (int i = 0; i < interval && ban_monitor_active; ++i) {
                Sleep(1000);
            }
        }
    }

    // ─── Rate limiting & lockouts ────────────────────────────────────────────

    void Api::record_login_fail() {
        login_fails++;
        if (login_fails >= 3) {
            lockout_end = (double)time(nullptr) + 300.0; // 5-minute lockout
        }
    }

    bool Api::lockout_active() {
        double now = (double)time(nullptr);
        if (now < lockout_end) {
            return true;
        }
        if (lockout_end > 0.0 && now >= lockout_end) {
            reset_lockout();
        }
        return false;
    }

    long long Api::lockout_remaining_ms() {
        if (!lockout_active()) {
            return 0;
        }
        double now = (double)time(nullptr);
        double diff = lockout_end - now;
        return diff > 0.0 ? (long long)(diff * 1000.0) : 0;
    }

    void Api::reset_lockout() {
        login_fails = 0;
        lockout_end = 0.0;
    }

    // ─── Debug helpers ───────────────────────────────────────────────────────

    void Api::setDebug(bool enable) {
        debug = enable;
    }

    std::map<std::string, std::string> Api::debugInfo() {
        std::map<std::string, std::string> info;
        info["debug_enabled"] = debug ? "true" : "false";
        info["hash_mode"] = client_secret.empty() ? "OFF" : "SECURE";
        info["lockout_active"] = lockout_active() ? "true" : "false";
        info["login_fails"] = std::to_string(login_fails);
        info["session"] = session_token.empty() ? "" : session_token.substr(0, 12) + "...";
        info["hash"] = hash_to_check;
        info["hwid_method"] = hwid_method;
        return info;
    }

    // ─── Private helpers ─────────────────────────────────────────────────────

    void Api::checkinit() {
        if (!initialized) {
            std::cerr << "SDK not initialised. Call api() first." << std::endl;
            Sleep(3000);
            ExitProcess(1);
        }
    }

    nlohmann::json Api::do_request(std::string endpoint, nlohmann::json post_data) {
        std::wstring host, path_prefix;
        INTERNET_PORT port;
        parse_url(api_url, host, path_prefix, port);

        std::wstring wendpoint = to_wstring(endpoint);
        if (!path_prefix.empty() && path_prefix.back() == L'/') {
            path_prefix.pop_back();
        }
        std::wstring full_path = path_prefix + wendpoint;

        // Host Locking Validation
        if (!allowed_hosts.empty()) {
            std::string check_domain = to_string(host);
            if (std::find(allowed_hosts.begin(), allowed_hosts.end(), check_domain) == allowed_hosts.end()) {
                std::cerr << "Security violation: blocked connection to " << check_domain << std::endl;
                Sleep(3000);
                ExitProcess(1);
            }
        }

        HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
        if (!hConnect) {
            std::cerr << "Connection error. Server is unreachable." << std::endl;
            Sleep(3000);
            ExitProcess(1);
        }

        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect,
            L"POST",
            full_path.c_str(),
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE // Always force HTTPS / SSL
        );

        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            std::cerr << "Request initialization failed." << std::endl;
            Sleep(3000);
            ExitProcess(1);
        }

        // Set User-Agent and content-type headers
        std::wstring headers = L"Content-Type: application/json\r\nUser-Agent: AuthLX-SDK-CPP/1.0 (" + to_wstring(name) + L" v" + to_wstring(version) + L")\r\n";
        
        std::string post_data_str = post_data.dump();

        if (debug) {
            nlohmann::json safe_data = post_data;
            if (safe_data.contains("password")) {
                safe_data["password"] = "***";
            }
            std::cout << "→ POST " << endpoint << " " << safe_data.dump() << std::endl;
        }

        BOOL bResults = WinHttpSendRequest(
            hRequest,
            headers.c_str(),
            (DWORD)-1,
            (LPVOID)post_data_str.c_str(),
            (DWORD)post_data_str.length(),
            (DWORD)post_data_str.length(),
            0
        );

        if (bResults) {
            bResults = WinHttpReceiveResponse(hRequest, NULL);
        } else {
            DWORD err = GetLastError();
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            fatal_error("Request timed out or network error. Please check your internet connection. (Error: " + std::to_string(err) + ")");
        }

        nlohmann::json response_json = nullptr;

        if (bResults) {
            std::vector<char> response_data;
            DWORD dwSize = 0;
            do {
                dwSize = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                    break;
                }
                if (dwSize == 0) break;

                std::vector<char> temp_buf(dwSize);
                DWORD dwDownloaded = 0;
                if (WinHttpReadData(hRequest, temp_buf.data(), dwSize, &dwDownloaded)) {
                    response_data.insert(response_data.end(), temp_buf.begin(), temp_buf.begin() + dwDownloaded);
                }
            } while (dwSize > 0);

            if (!response_data.empty()) {
                std::string resp_str(response_data.begin(), response_data.end());
                if (debug) {
                    std::cout << "← " << resp_str.substr(0, 200) << std::endl;
                }
                try {
                    response_json = nlohmann::json::parse(resp_str);
                } catch (const std::exception&) {
                    WinHttpCloseHandle(hRequest);
                    WinHttpCloseHandle(hConnect);
                    fatal_error("Invalid JSON response from server. Server might be offline or undergoing maintenance.\nRaw response: " + resp_str);
                }
            }
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        return response_json;
    }

    void Api::load_user_data(nlohmann::json data) {
        user_data.username = data.value("username", "");
        user_data.hwid = data.value("hwid", "N/A");
        user_data.createdate = data.value("created_at", "");
        user_data.lastlogin = data.value("last_login", "");

        user_data.subscriptions.clear();
        if (data.contains("subscriptions") && data["subscriptions"].is_array()) {
            auto subs = data["subscriptions"];
            for (auto& s : subs) {
                SubscriptionInfo info;
                info.subscription = s.value("subscription", "");
                info.expiry = s.value("expiry", "");
                user_data.subscriptions.push_back(info);
            }
        }

        if (!user_data.subscriptions.empty()) {
            user_data.expires = user_data.subscriptions[0].expiry;
            user_data.subscription = user_data.subscriptions[0].subscription;
        } else {
            user_data.expires = "";
            user_data.subscription = "";
        }
    }

    void Api::parse_ban_info(std::string msg) {
        ban_reason = "";
        ban_revoke_date = "";

        if (msg.find("Account is Banned") == std::string::npos && msg.find("License is Banned") == std::string::npos) {
            return;
        }

        // Parse Reason and Expires using basic string indexing (since C++ regex is heavy/problematic occasionally)
        size_t reason_pos = msg.find("Reason:");
        if (reason_pos != std::string::npos) {
            reason_pos += 7;
            size_t bar_pos = msg.find("|", reason_pos);
            if (bar_pos != std::string::npos) {
                ban_reason = msg.substr(reason_pos, bar_pos - reason_pos);
            } else {
                ban_reason = msg.substr(reason_pos);
            }
            // Trim whitespace
            ban_reason.erase(0, ban_reason.find_first_not_of(" \t\r\n"));
            ban_reason.erase(ban_reason.find_last_not_of(" \t\r\n") + 1);
        }

        size_t expires_pos = msg.find("Expires:");
        if (expires_pos != std::string::npos) {
            expires_pos += 8;
            ban_revoke_date = msg.substr(expires_pos);
            ban_revoke_date.erase(0, ban_revoke_date.find_first_not_of(" \t\r\n"));
            ban_revoke_date.erase(ban_revoke_date.find_last_not_of(" \t\r\n") + 1);
        }
    }

    void Api::login_hint(std::string msg) {
        std::string lmsg = msg;
        std::transform(lmsg.begin(), lmsg.end(), lmsg.begin(), ::tolower);

        if (lmsg.find("signature") != std::string::npos || lmsg.find("hmac") != std::string::npos) {
            std::cerr << "\n[ANTI-TAMPER] HMAC verification failed. Possible causes:\n"
                      << "  1. client_secret is wrong — copy it exactly from the dashboard.\n"
                      << "  2. System clock is more than 5 minutes off — sync your clock.\n" << std::endl;
        } else if (lmsg.find("application not found") != std::string::npos) {
            std::cerr << "\n[SETUP ERROR] ownerid (App ID) is wrong.\n"
                      << "  Resolution: copy the exact App ID from AuthLX Dashboard → App Info.\n" << std::endl;
        } else if (lmsg.find("hardware id mismatch") != std::string::npos) {
            std::cerr << "\n[USER] HWID changed. Admin must reset HWID in the dashboard.\n" << std::endl;
        } else if (lmsg.find("subscription has expired") != std::string::npos) {
            std::cerr << "\n[USER] Subscription expired. Purchase a new license key.\n" << std::endl;
        } else if (lmsg.find("application is currently disabled") != std::string::npos) {
            std::cerr << "\n[SETUP ERROR] App is disabled in the dashboard.\n"
                      << "  Resolution: Dashboard → Select App → Enable.\n" << std::endl;
        } else if (lmsg.find("replay") != std::string::npos || lmsg.find("nonce") != std::string::npos) {
            std::cerr << "\n[SECURITY] Replay attack blocked. Each request must use a fresh nonce.\n"
                      << "  This error means someone is trying to re-use a captured packet.\n" << std::endl;
        }
    }

    // ─── Others static class implementation ──────────────────────────────────

    std::string Others::get_checksum() {
        wchar_t path[MAX_PATH];
        if (GetModuleFileNameW(NULL, path, MAX_PATH) == 0) {
            return "UNKNOWN_HASH";
        }

        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            return "UNKNOWN_HASH";
        }

        std::streamsize size = file.tellg();
        if (size <= 0) {
            return "UNKNOWN_HASH";
        }
        file.seekg(0, std::ios::beg);

        std::vector<uint8_t> buffer((size_t)size);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            return "UNKNOWN_HASH";
        }

        return sha256(buffer);
    }

    void Others::anti_debug() {
        if (IsDebuggerPresent()) {
            std::cerr << "Security violation: Debugger detected. Exiting." << std::endl;
            ExitProcess(1);
        }

        BOOL isDebuggerAttached = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerAttached)) {
            if (isDebuggerAttached) {
                std::cerr << "Security violation: Remote debugger detected. Exiting." << std::endl;
                ExitProcess(1);
            }
        }
    }

    std::string Others::get_hwid(std::string method) {
        if (method == "windows_user") {
            HANDLE hToken = NULL;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                DWORD dwSize = 0;
                GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
                if (dwSize > 0) {
                    std::vector<BYTE> buffer(dwSize);
                    if (GetTokenInformation(hToken, TokenUser, buffer.data(), dwSize, &dwSize)) {
                        PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(buffer.data());
                        LPWSTR lpszSid = NULL;
                        if (ConvertSidToStringSidW(pTokenUser->User.Sid, &lpszSid)) {
                            std::string sid_str = to_string(lpszSid);
                            LocalFree(lpszSid);
                            CloseHandle(hToken);
                            return sid_str;
                        }
                    }
                }
                CloseHandle(hToken);
            }
            return "Unknown-Windows-User-HWID";
        } else {
            // Read Registry MachineGuid
            HKEY hKey;
            std::string guid = "Unknown-Windows-Machine-HWID";
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
                wchar_t szBuffer[256];
                DWORD dwSize = sizeof(szBuffer);
                if (RegQueryValueExW(hKey, L"MachineGuid", NULL, NULL, (LPBYTE)szBuffer, &dwSize) == ERROR_SUCCESS) {
                    guid = to_string(szBuffer);
                }
                RegCloseKey(hKey);
            }
            return guid;
        }
    }

}