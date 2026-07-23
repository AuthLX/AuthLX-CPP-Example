#include "authlx.hpp"
#include "Logger.hpp"
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

    // Helper: Null-safe JSON string getter (prevents nlohmann::json type_error crash on null fields)
    static std::string safe_json_string(const nlohmann::json& j, const std::string& key, const std::string& fallback = "") {
        if (!j.is_object() || !j.contains(key) || j[key].is_null()) return fallback;
        try {
            if (j[key].is_string()) return j[key].get<std::string>();
        } catch (...) {}
        return fallback;
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

        while (!this->api_url.empty() && this->api_url.back() == '/') {
            this->api_url.pop_back();
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
        // Intercept --authlx-update-finish stage before anything else
        handle_update_stage();

        // Cleanup previous .old backup if it exists
        std::wstring current_exe = get_current_executable_path();
        if (!current_exe.empty()) {
            std::wstring old_backup = current_exe + L".old";
            DWORD dwAttrib = GetFileAttributesW(old_backup.c_str());
            if (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
                if (!DeleteFileW(old_backup.c_str())) {
                    MoveFileExW(old_backup.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
                }
            }
        }

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
                LOG_ERROR("[SECURITY] Application name mismatch! Expected: " << name << " | Server reports: " << server_name);
                last_message = "Application name mismatch! Expected: " + name + " | Server reports: " + server_name;
                initialized = false;
                return;
            }

            auto clean_ver = [](std::string v) -> std::string {
                size_t start = v.find_first_not_of(" \t\r\n");
                if (start != std::string::npos) v = v.substr(start);
                if (!v.empty() && (v[0] == 'v' || v[0] == 'V')) {
                    v = v.substr(1);
                }
                return v;
            };

            if (clean_ver(server_version) != clean_ver(version)) {
                LOG_ERROR("[UPDATE REQUIRED] Application version is outdated! Current: " << version << " | Required: " << server_version);
                last_message = "Application version is outdated! Current: " + version + " | Required: " + server_version;
                
                if (auto_update_enabled) {
                    LOG_INFO("[AUTO-UPDATE] Initiating auto-update to " << server_version << "...");
                    LOG_INFO("[AUTO-UPDATE] Calling check_for_updates()...");
                    UpdateInfo info = check_for_updates();
                    LOG_INFO("[AUTO-UPDATE] check_for_updates() returned URL: '" << info.download_url << "' | Available: " << (info.update_available ? "YES" : "NO"));
                    info.update_available = true;
                    LOG_INFO("[AUTO-UPDATE] Calling perform_update()...");
                    bool res = perform_update(info);
                    LOG_INFO("[AUTO-UPDATE] perform_update() completed with result: " << (res ? "SUCCESS" : "FAILED"));
                } else {
                    LOG_WARN("[AUTO-UPDATE] auto_update_enabled is FALSE! Skipping update.");
                }

                initialized = false;
                return;
            }

            initialized = true;
            hwid_method = app_info.value("hwid_method", "windows_user");

            LOG_INFO("SDK Initialized successfully. Name: " << name << ", Version: " << version << ", HWID Method: " << hwid_method);
            if (debug) {
                LOG_DEBUG("Hash mode: " << (client_secret.empty() ? "OFF" : "SECURE"));
            }
        } else {
            std::string err_msg = "Failed to initialise. Check ownerid and network connectivity.";
            if (!response.is_null() && response.contains("message")) {
                err_msg = response.value("message", "");
            }
            LOG_ERROR("Initialization failed: " << err_msg);
            last_message = err_msg;
            initialized = false;
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
        if (!checkinit()) return false;

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
        if (!checkinit()) return false;

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
        if (!checkinit()) return false;

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
        if (!checkinit()) return false;
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
        if (!checkinit()) return false;

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
        if (!checkinit()) return false;
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
        if (!checkinit()) return false;

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
        if (!checkinit()) return false;
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
        if (!checkinit()) return false;
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

    bool Api::checkinit() {
        if (!initialized) {
            LOG_ERROR("SDK not initialised. Ensure API constructor completes successfully.");
            return false;
        }
        return true;
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
                LOG_ERROR("Security violation: blocked connection to " << check_domain);
                last_message = "Security violation: blocked connection to " + check_domain;
                return nullptr;
            }
        }

        HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
        if (!hConnect) {
            LOG_ERROR("Connection error. Server is unreachable.");
            last_message = "Connection error. Server is unreachable.";
            return nullptr;
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
            LOG_ERROR("Request initialization failed.");
            last_message = "Request initialization failed.";
            return nullptr;
        }

        // Set User-Agent and content-type headers
        std::wstring headers = L"Content-Type: application/json\r\nUser-Agent: AuthLX-SDK-CPP/1.0 (" + to_wstring(name) + L" v" + to_wstring(version) + L")\r\n";
        
        std::string post_data_str = post_data.dump();

        if (debug) {
            nlohmann::json safe_data = post_data;
            if (safe_data.contains("password")) {
                safe_data["password"] = "***";
            }
            LOG_DEBUG("→ POST " << endpoint << " " << safe_data.dump());
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
            LOG_ERROR("Request timed out or network error (Error: " << err << ")");
            last_message = "Request timed out or network error (Error: " + std::to_string(err) + ")";
            return nullptr;
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
                    LOG_DEBUG("← " << resp_str.substr(0, 200));
                }
                try {
                    response_json = nlohmann::json::parse(resp_str);
                } catch (const std::exception& e) {
                    WinHttpCloseHandle(hRequest);
                    WinHttpCloseHandle(hConnect);
                    LOG_ERROR("Invalid JSON response from server. Error: " << e.what() << "\nRaw response: " << resp_str);
                    last_message = "Invalid response from server.";
                    return nullptr;
                }
            }
        } else {
            LOG_ERROR("Response reception timed out.");
            last_message = "Response reception timed out.";
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
            LOG_ERROR("Security violation: Debugger detected. Exiting.");
            ExitProcess(1);
        }

        BOOL isDebuggerAttached = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerAttached)) {
            if (isDebuggerAttached) {
                LOG_ERROR("Security violation: Remote debugger detected. Exiting.");
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

    // ─── Auto-Updater ────────────────────────────────────────────────────────

    std::wstring Api::get_current_executable_path() {
        wchar_t path[MAX_PATH];
        DWORD length = GetModuleFileNameW(NULL, path, MAX_PATH);
        if (length == 0 || length == MAX_PATH) {
            return L"";
        }
        return std::wstring(path);
    }

    void Api::handle_update_stage() {
        LPWSTR cmdLine = GetCommandLineW();
        if (!cmdLine) return;

        std::wstring wcmd(cmdLine);
        size_t pos = wcmd.find(L"--authlx-update-finish");
        if (pos == std::wstring::npos) return;

        // Attach console output to parent process window
        AttachConsole(ATTACH_PARENT_PROCESS);

        LOG_INFO("[AUTO-UPDATE-STAGE] Executing process handoff stage...");

        size_t arg_start = wcmd.find_first_not_of(L" \t", pos + wcslen(L"--authlx-update-finish"));
        if (arg_start == std::wstring::npos) {
            LOG_ERROR("[AUTO-UPDATE-STAGE] Missing target_path argument!");
            return;
        }

        std::wstring target_path;
        if (wcmd[arg_start] == L'"') {
            size_t end_quote = wcmd.find(L'"', arg_start + 1);
            if (end_quote != std::wstring::npos) {
                target_path = wcmd.substr(arg_start + 1, end_quote - arg_start - 1);
            }
        } else {
            size_t space_end = wcmd.find_first_of(L" \t", arg_start);
            if (space_end != std::wstring::npos) {
                target_path = wcmd.substr(arg_start, space_end - arg_start);
            } else {
                target_path = wcmd.substr(arg_start);
            }
        }

        if (target_path.empty()) {
            LOG_ERROR("[AUTO-UPDATE-STAGE] Target path is empty!");
            return;
        }

        std::wstring current_path = get_current_executable_path();
        if (current_path.empty()) {
            LOG_ERROR("[AUTO-UPDATE-STAGE] Could not get current executable path!");
            return;
        }

        LOG_INFO("[AUTO-UPDATE-STAGE] Waiting for original process to release file: " << to_string(target_path));
        Sleep(500); // Give old process time to terminate completely

        std::wstring backup_path = target_path + L".old";
        LOG_INFO("[AUTO-UPDATE-STAGE] Replacing old binary (" << to_string(target_path) << ") with new binary (" << to_string(current_path) << ")");

        bool move_ok = false;
        for (int attempt = 1; attempt <= 20; attempt++) {
            MoveFileExW(target_path.c_str(), backup_path.c_str(), MOVEFILE_REPLACE_EXISTING);
            if (MoveFileExW(current_path.c_str(), target_path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
                move_ok = true;
                LOG_INFO("[AUTO-UPDATE-STAGE] File replacement succeeded on attempt " << attempt);
                break;
            }
            Sleep(250);
        }

        if (!move_ok) {
            LOG_ERROR("[AUTO-UPDATE-STAGE] MoveFileExW failed after 20 attempts! Win32 Error: " << GetLastError());
        }

        // Spawn original application path
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        std::wstring launch_cmd = L"\"" + target_path + L"\"";
        std::vector<wchar_t> cmd_buf(launch_cmd.begin(), launch_cmd.end());
        cmd_buf.push_back(L'\0');

        LOG_INFO("[AUTO-UPDATE-STAGE] Launching updated executable: " << to_string(target_path));
        if (CreateProcessW(NULL, cmd_buf.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            LOG_INFO("[AUTO-UPDATE-STAGE] Successfully launched updated executable. Exiting temporary updater.");
        } else {
            LOG_ERROR("[AUTO-UPDATE-STAGE] Failed to launch updated executable. Win32 Error: " << GetLastError());
        }

        ExitProcess(0);
    }

    bool Api::download_file_winhttp(const std::string& url, const std::wstring& target_path) {
        LOG_INFO("[DOWNLOAD] Starting WinHTTP download...");
        LOG_INFO("[DOWNLOAD] URL: " << url);
        LOG_INFO("[DOWNLOAD] Target Path: " << to_string(target_path));
        if (url.empty() || target_path.empty()) {
            LOG_ERROR("[DOWNLOAD] Failed: URL or target_path is empty!");
            return false;
        }

        std::wstring host, path_prefix;
        INTERNET_PORT port;
        parse_url(url, host, path_prefix, port);
        LOG_INFO("[DOWNLOAD] Host: " << to_string(host) << " | Port: " << port << " | Path: " << to_string(path_prefix));

        HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
        if (!hConnect) {
            LOG_ERROR("[DOWNLOAD] WinHttpConnect failed with error: " << GetLastError());
            return false;
        }

        DWORD req_flags = (port == INTERNET_DEFAULT_HTTPS_PORT) ? WINHTTP_FLAG_SECURE : 0;

        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect,
            L"GET",
            path_prefix.c_str(),
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            req_flags
        );

        if (!hRequest) {
            LOG_ERROR("[DOWNLOAD] WinHttpOpenRequest failed with error: " << GetLastError());
            WinHttpCloseHandle(hConnect);
            return false;
        }

        DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy, sizeof(redirect_policy));

        std::wstring headers = L"User-Agent: AuthLX-SDK-CPP/1.0 (" + to_wstring(name) + L" v" + to_wstring(version) + L")\r\n";

        BOOL bResults = WinHttpSendRequest(
            hRequest,
            headers.c_str(),
            (DWORD)-1,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0
        );

        if (bResults) {
            bResults = WinHttpReceiveResponse(hRequest, NULL);
        }

        if (!bResults) {
            LOG_ERROR("[DOWNLOAD] WinHttpSendRequest/ReceiveResponse failed with error: " << GetLastError());
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            return false;
        }

        DWORD dwStatusCode = 0;
        DWORD dwSize = sizeof(dwStatusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
        LOG_INFO("[DOWNLOAD] Server response HTTP status: " << dwStatusCode);

        // Check if redirect response (301/302/307)
        if (dwStatusCode == 301 || dwStatusCode == 302 || dwStatusCode == 307) {
            WCHAR locationHeader[2048] = {};
            DWORD locSize = sizeof(locationHeader);
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX, locationHeader, &locSize, WINHTTP_NO_HEADER_INDEX)) {
                std::string redirectUrl = to_string(locationHeader);
                LOG_INFO("[DOWNLOAD] Following HTTP redirect to: " << redirectUrl);
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                return download_file_winhttp(redirectUrl, target_path);
            }
        }

        if (dwStatusCode != 200) {
            LOG_ERROR("[AUTO-UPDATE] Download request returned HTTP " << dwStatusCode << " for path: " << to_string(path_prefix));
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            return false;
        }

        // Query Content-Length for progress display
        ULONGLONG totalBytes = 0;
        {
            WCHAR contentLen[32] = {};
            DWORD clSize = sizeof(contentLen);
            if (WinHttpQueryHeaders(hRequest,
                                    WINHTTP_QUERY_CONTENT_LENGTH,
                                    WINHTTP_HEADER_NAME_BY_INDEX,
                                    contentLen, &clSize,
                                    WINHTTP_NO_HEADER_INDEX)) {
                totalBytes = _wcstoui64(contentLen, nullptr, 10);
            }
        }

        std::ofstream outFile(target_path, std::ios::binary);
        if (!outFile.is_open()) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            return false;
        }

        ULONGLONG downloaded = 0;
        DWORD dwDownloaded   = 0;
        int   lastPct        = -1;
        std::vector<char> buffer(65536);

        while (true) {
            DWORD dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            if (dwSize == 0) break;

            while (dwSize > 0) {
                DWORD toRead = (dwSize < (DWORD)buffer.size()) ? dwSize : (DWORD)buffer.size();
                if (!WinHttpReadData(hRequest, buffer.data(), toRead, &dwDownloaded)) break;
                if (dwDownloaded == 0) break;
                outFile.write(buffer.data(), dwDownloaded);
                downloaded += dwDownloaded;
                dwSize     -= dwDownloaded;

                if (totalBytes > 0) {
                    int pct = (int)(downloaded * 100ULL / totalBytes);
                    if (pct < 0) pct = 0;
                    if (pct > 100) pct = 100;
                    if (pct != lastPct && (pct % 10 == 0 || pct == 100)) {
                        double mbDone  = (double)downloaded / (1024.0 * 1024.0);
                        double mbTotal = (double)totalBytes  / (1024.0 * 1024.0);
                        LOG_INFO("[AUTO-UPDATE] Downloading... " << pct << "%  (" << mbDone << " / " << mbTotal << " MB)");
                        lastPct = pct;
                    }
                } else {
                    double mbDone = (double)downloaded / (1024.0 * 1024.0);
                    LOG_INFO("[AUTO-UPDATE] Downloading... " << mbDone << " MB");
                }
            }
        }


        outFile.close();
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);

        std::ifstream checkFile(target_path, std::ios::binary | std::ios::ate);
        if (checkFile.is_open() && checkFile.tellg() > 0) {
            return true;
        }
        return false;
    }

    UpdateInfo Api::check_for_updates() {
        UpdateInfo info;
        info.current_version = version;

        try {
            nlohmann::json payload = {
                {"app_id", ownerid},
                {"name", name},
                {"version", version},
                {"secret", client_secret.empty() ? "NO_SECRET" : client_secret}
            };

            std::string latest_ver;
            std::string dl_url;
            std::string file_n;

            // Version comparison helper with leading 'v'/'V' normalization
            auto clean_ver = [](std::string v) -> std::string {
                size_t start = v.find_first_not_of(" \t\r\n");
                if (start != std::string::npos) v = v.substr(start);
                if (!v.empty() && (v[0] == 'v' || v[0] == 'V')) {
                    v = v.substr(1);
                }
                return v;
            };

            // 1. Query /file/latest first — authoritative latest release file info from Files manager
            nlohmann::json file_res = do_request("/file/latest", payload);
            if (!file_res.is_null() && safe_json_string(file_res, "status") == "success") {
                if (file_res.contains("data") && file_res["data"].is_object()) {
                    auto data = file_res["data"];
                    if (data.contains("file") && data["file"].is_object()) {
                        auto file_obj = data["file"];
                        latest_ver = safe_json_string(file_obj, "version_tag");
                        dl_url = safe_json_string(file_obj, "download_url");
                        file_n = safe_json_string(file_obj, "name");
                    }
                }
            }

            // 2. Query /init endpoint as fallback/enrichment
            nlohmann::json response = do_request("/init", payload);
            std::string init_ver;
            if (!response.is_null() && safe_json_string(response, "status") == "success") {
                if (response.contains("app_info") && response["app_info"].is_object()) {
                    auto app_info = response["app_info"];
                    init_ver = safe_json_string(app_info, "version");
                    if (latest_ver.empty() || (!init_ver.empty() && clean_ver(init_ver) != clean_ver(version))) {
                        latest_ver = init_ver;
                    }
                    if (dl_url.empty()) {
                        dl_url = safe_json_string(app_info, "auto_update_link");
                    }
                }
            }

            info.latest_version = latest_ver.empty() ? (init_ver.empty() ? version : init_ver) : latest_ver;
            info.file_name = file_n;

            std::string clean_current = clean_ver(version);
            std::string clean_latest = clean_ver(info.latest_version);
            std::string clean_init = clean_ver(init_ver);

            if ((!info.latest_version.empty() && clean_latest != clean_current) ||
                (!clean_init.empty() && clean_init != clean_current)) {
                info.update_available = true;
            }

            // Always target the Latest Mark release endpoint (/download/latest/:appName) for auto-update
            dl_url = api_url + "/download/latest/" + name;

            info.download_url = dl_url;
        } catch (const std::exception& e) {
            LOG_ERROR("[AUTO-UPDATE] Exception in check_for_updates: " << e.what());
            info.download_url = api_url + "/download/latest/" + name;
            info.update_available = true;
        }

        this->update_info = info;
        return info;
    }

    std::pair<bool, std::string> Api::validate_download_url(const std::string& url) {
        if (url.empty())
            return {false, "No download URL provided. Set the auto_update_link in your AuthLX Dashboard."};

        if (url.substr(0, 7) != "http://" && url.substr(0, 8) != "https://")
            return {false, "Invalid URL format: '" + url + "'. URL must start with http:// or https://."};

        std::wstring host, path_prefix;
        INTERNET_PORT port;
        parse_url(url, host, path_prefix, port);

        HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
        if (!hConnect)
            return {false, "Could not connect to host: " + std::string(host.begin(), host.end()) +
                    "\n  -> Check your internet connection."};

        DWORD req_flags = (port == INTERNET_DEFAULT_HTTPS_PORT) ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect, L"HEAD", path_prefix.c_str(),
            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, req_flags);

        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            return {false, "Could not create HTTP request for validation."};
        }

        DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy, sizeof(redirect_policy));

        std::wstring ua = L"User-Agent: AuthLX-SDK-CPP/1.0 (" + to_wstring(name) + L" v" + to_wstring(version) + L")\r\n";
        bool ok = WinHttpSendRequest(hRequest, ua.c_str(), (DWORD)-1, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
                  && WinHttpReceiveResponse(hRequest, NULL);

        if (!ok) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            return {false, "Could not reach the download URL: " + url +
                    "\n  -> Check your internet connection and verify the URL is reachable."};
        }

        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);

        if (statusCode == 404) {
            WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect);
            return {false, "Download URL returned 404 Not Found.\n"
                    "  URL: " + url + "\n"
                    "  -> The file may have been deleted or the URL is incorrect.\n"
                    "  -> Please upload the update file and set the correct URL in your Dashboard."};
        }
        if (statusCode == 403) {
            WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect);
            return {false, "Download URL returned 403 Forbidden.\n"
                    "  URL: " + url + "\n"
                    "  -> The server is blocking access. Check file permissions or use a public link."};
        }
        if (statusCode >= 400) {
            WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect);
            return {false, "Download URL returned HTTP " + std::to_string(statusCode) + ".\n"
                    "  URL: " + url + "\n"
                    "  -> Please verify the URL is correct and the file is publicly accessible."};
        }

        // Check Content-Type — HTML pages are NOT direct download links
        WCHAR contentType[512] = {};
        DWORD ctSize = sizeof(contentType);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_TYPE,
                                WINHTTP_HEADER_NAME_BY_INDEX,
                                contentType, &ctSize, WINHTTP_NO_HEADER_INDEX)) {
            std::string ct(contentType, contentType + wcslen(contentType));
            std::string ctLower = ct;
            std::transform(ctLower.begin(), ctLower.end(), ctLower.begin(), ::tolower);
            if (ctLower.find("text/html") != std::string::npos) {
                WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect);
                return {false, "The URL does not point to a direct file download.\n"
                        "  URL: " + url + "\n"
                        "  Content-Type: " + ct + "\n"
                        "  [!] Tip: Use a direct download link, not a webpage URL.\n"
                        "      Example: https://example.com/files/myapp-v2.0 (no HTML, no login page)"};
            }
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        return {true, ""};
    }

    bool Api::perform_update(const UpdateInfo& info) {
        if (!info.update_available || info.download_url.empty()) {
            LOG_ERROR("[AUTO-UPDATE] Cannot install update: download URL empty or update not available.");
            return false;
        }

        std::wstring current_exe = get_current_executable_path();
        if (current_exe.empty()) {
            LOG_ERROR("[AUTO-UPDATE] Could not determine current binary path.");
            return false;
        }

        std::wstring backup_exe = current_exe + L".old";

        LOG_INFO("[AUTO-UPDATE] Preparing file update for: " << to_string(current_exe));
        LOG_INFO("[AUTO-UPDATE] Renaming current binary to backup: " << to_string(backup_exe));

        // Windows allows a running executable to rename itself
        if (!MoveFileExW(current_exe.c_str(), backup_exe.c_str(), MOVEFILE_REPLACE_EXISTING)) {
            LOG_WARN("[AUTO-UPDATE] Rename self to .old failed with error: " << GetLastError() << ". Attempting direct overwrite...");
        }

        LOG_INFO("[AUTO-UPDATE] Downloading update from: " << info.download_url);
        bool download_ok = download_file_winhttp(info.download_url, current_exe);

        // If initial download fails or file is not found, wait 10 seconds and retry one last time
        if (!download_ok) {
            LOG_WARN("[AUTO-UPDATE] File download failed or not found! Waiting 10 seconds before final retry attempt...");
            Sleep(10000);

            std::string latest_fallback = api_url + "/download/latest/" + name;
            LOG_INFO("[AUTO-UPDATE] Retrying final download attempt from: " << latest_fallback);
            download_ok = download_file_winhttp(latest_fallback, current_exe);
        }

        if (!download_ok) {
            LOG_ERROR("[AUTO-UPDATE] Final download retry failed! No latest release file available. Restoring backup and exiting...");
            MoveFileExW(backup_exe.c_str(), current_exe.c_str(), MOVEFILE_REPLACE_EXISTING);
            ExitProcess(1);
            return false;
        }

        LOG_INFO("[AUTO-UPDATE] Download completed successfully! Launching updated executable...");

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        std::wstring launch_cmd = L"\"" + current_exe + L"\"";
        std::vector<wchar_t> cmd_buf(launch_cmd.begin(), launch_cmd.end());
        cmd_buf.push_back(L'\0');

        if (CreateProcessW(NULL, cmd_buf.data(), NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            LOG_INFO("[AUTO-UPDATE] Updated executable launched successfully. Exiting old process...");
            ExitProcess(0);
            return true;
        } else {
            LOG_ERROR("[AUTO-UPDATE] Failed to launch updated executable. Win32 Error: " << GetLastError());
            return false;
        }
    }

    // =========================================================================
    // VARIABLES MANAGEMENT (GLOBAL & PER-USER VARIABLES)
    // =========================================================================

    /**
     * @brief Fetches a Global Application Variable by name.
     *        If logged in, session_token is automatically sent for authenticated variables.
     * @param name Name of the global variable set in the AuthLX Dashboard.
     * @return String value of the variable, or empty string on failure.
     */
    std::string Api::var(std::string name) {
        if (!checkinit()) return "";

        nlohmann::json post_data;
        post_data["app_id"] = this->ownerid;
        post_data["secret"] = this->client_secret;
        post_data["variable_name"] = name;
        if (!this->session_token.empty()) {
            post_data["session_token"] = this->session_token;
        }

        nlohmann::json response = do_request("/var", post_data);
        if (!response.is_null() && response.value("status", "") == "success") {
            if (response.contains("data") && response["data"].contains("value")) {
                if (response["data"]["value"].is_string()) {
                    return response["data"]["value"].get<std::string>();
                }
                return response["data"]["value"].dump();
            }
        }
        return "";
    }

    /**
     * @brief Fetches a Per-User Variable for the currently logged in user session.
     * @param key Key/Name of the user variable.
     * @return String value of the user variable, or empty string if not found.
     */
    std::string Api::get_user_var(std::string key) {
        if (!checkinit()) return "";
        if (session_token.empty()) {
            LOG_ERROR("[VARIABLES] Session token required to fetch user variables. Please log in first.");
            return "";
        }

        nlohmann::json post_data;
        post_data["app_id"] = this->ownerid;
        post_data["secret"] = this->client_secret;
        post_data["session_token"] = this->session_token;
        post_data["key"] = key;

        nlohmann::json response = do_request("/vars/user/get", post_data);
        if (!response.is_null() && response.value("status", "") == "success") {
            if (response.contains("data") && response["data"].contains("value")) {
                if (response["data"]["value"].is_string()) {
                    return response["data"]["value"].get<std::string>();
                }
                return response["data"]["value"].dump();
            }
        }
        return "";
    }

    /**
     * @brief Creates or updates a Per-User Variable for the currently logged in user.
     * @param key Key/Name of the user variable.
     * @param value Value to store for the user.
     * @return True if saved successfully, False if failed or read-only.
     */
    bool Api::set_user_var(std::string key, std::string value) {
        if (!checkinit()) return false;
        if (session_token.empty()) {
            LOG_ERROR("[VARIABLES] Session token required to set user variables. Please log in first.");
            return false;
        }

        nlohmann::json post_data;
        post_data["app_id"] = this->ownerid;
        post_data["secret"] = this->client_secret;
        post_data["session_token"] = this->session_token;
        post_data["key"] = key;
        post_data["value"] = value;

        nlohmann::json response = do_request("/vars/user/set", post_data);
        return (!response.is_null() && response.value("status", "") == "success");
    }

}