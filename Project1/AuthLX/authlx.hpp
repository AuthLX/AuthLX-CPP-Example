#pragma once

#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <chrono>
#include <map>
#include <iostream>
#include "json.hpp"

namespace AuthLX {

    struct SubscriptionInfo {
        std::string subscription;
        std::string expiry;
    };

    struct UserData {
        std::string username;
        std::string hwid;
        std::string expires;
        std::string createdate;
        std::string lastlogin;
        std::string subscription;
        std::vector<SubscriptionInfo> subscriptions;
        bool is_authenticated = false;
        double auth_runtime_start = 0.0;
    };

    class Api {
    public:
        std::string name;
        std::string ownerid;
        std::string version;
        std::string client_secret;
        std::string hash_to_check;
        std::string api_url;
        std::string session_token;
        bool initialized = false;
        std::string hwid_method = "windows_user";
        UserData user_data;

        std::string ban_reason;
        std::string ban_revoke_date;

        // Secure String fields (from method1/method2 templates)
        bool secure_strings_enabled = false;
        std::vector<uint8_t> secure_key;

        Api(std::string name,
            std::string ownerid,
            std::string version,
            std::string client_secret = "",
            std::string hash_to_check = "",
            std::string api_url = "");

        ~Api();

        void init();

        // Authentication
        bool login(std::string user, std::string password, std::string hwid = "");
        bool registerAccount(std::string user, std::string email, std::string password, std::string license_key, std::string hwid = "");
        bool webLogin(std::string user, std::string password);
        bool registerWeb(std::string user, std::string email, std::string password, std::string license_key);
        bool logout();

        // License operations
        bool upgrade(std::string user, std::string license_key);

        // Verification
        bool check();
        bool verifyToken(std::string standalone_token);

        // Account management
        bool changeUsername(std::string new_username);
        bool forgot(std::string user, std::string new_password, std::string hwid = "");

        // Subscription & Expiry helpers
        bool has_active_subscription();
        double expiry_remaining();

        // Auth runtime state
        void mark_authenticated();
        void refresh_auth_runtime();
        void reset_auth_runtime();

        // Host Locking & Key Pinning
        void set_allowed_hosts(std::vector<std::string> hosts);
        void add_allowed_host(std::string host);
        void clear_allowed_hosts();
        void set_pinned_public_keys(std::vector<std::string> keys);
        void add_pinned_public_key(std::string key);
        void clear_pinned_public_keys();

        // Secure Cryptography (XOR / Seal - from templates)
        void enable_secure_strings();
        void derive_secure_key(std::string material);
        std::string xor_crypt_field(std::string data, std::string key);
        std::string compute_auth_seal(std::string payload);

        // Ban monitor
        void start_ban_monitor(int interval_seconds = 60);
        void stop_ban_monitor();
        bool ban_monitor_running();

        // Rate limiting & lockouts
        void record_login_fail();
        bool lockout_active();
        long long lockout_remaining_ms();
        void reset_lockout();

        // Debug helpers
        void setDebug(bool enable);
        std::map<std::string, std::string> debugInfo();

    private:
        int login_fails = 0;
        double lockout_end = 0.0;
        bool debug = false;

        std::vector<std::string> allowed_hosts;
        std::vector<std::string> pinned_public_keys;

        std::thread ban_monitor_thread;
        std::atomic<bool> ban_monitor_active{false};

        void checkinit();
        nlohmann::json do_request(std::string endpoint, nlohmann::json post_data);
        void load_user_data(nlohmann::json data);
        void parse_ban_info(std::string msg);
        void login_hint(std::string msg);
        void ban_monitor_loop(int interval);

        // HMAC / Hash signature helpers
        std::tuple<std::string, std::string, std::string> compute_hash_signature();
        nlohmann::json build_hash_payload();

        // WinHTTP session handle and configuration
        void* hSession = nullptr;
    };

    class Others {
    public:
        static std::string get_checksum();
        static void anti_debug();
        static std::string get_hwid(std::string method = "windows_user");
    };

}
