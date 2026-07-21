#include <Windows.h>
#include "AuthLX/authlx.hpp"
#include <iostream>
#include <string>
#include "AuthLX/skCrypter.h"
#include <algorithm>

std::string name = skCrypt("your_application_name").decrypt();
std::string ownerid = skCrypt("your_application_owner_id_from_dashboard").decrypt();
std::string secret = skCrypt("your_application_secret_key_from_dashboard").decrypt();
std::string version = skCrypt("1.0").decrypt();
std::string url = skCrypt("https://authlx.com/api/v1/client/").decrypt();

void clear() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

std::string get_input(const std::string& prompt) {
    std::cout << prompt;
    std::string value;
    std::getline(std::cin, value);
    // Trim whitespace
    value.erase(0, value.find_first_not_of(" \t\r\n"));
    value.erase(value.find_last_not_of(" \t\r\n") + 1);
    return value;
}

void banner(AuthLX::Api& authlxapp) {
    clear();
    std::string mode = authlxapp.client_secret.empty() ? "OFF ⚠" : "SECURE 🔒";
    std::cout << "╔" << std::string(58, '=') << "╗" << std::endl;
    
    std::string title = "║  " + authlxapp.name + "  —  Powered by AuthLX";
    if (title.length() < 60) {
        title += std::string(60 - title.length(), ' ');
    }
    title += "║";
    std::cout << title << std::endl;

    std::string mode_line = "║  Anti-Tamper: " + mode;
    if (mode_line.length() < 60) {
        mode_line += std::string(60 - mode_line.length(), ' ');
    }
    mode_line += "║";
    std::cout << mode_line << std::endl;

    std::cout << "╚" << std::string(58, '=') << "╝" << std::endl;

    if (authlxapp.user_data.is_authenticated && !authlxapp.user_data.username.empty()) {
        std::cout << "\n  Logged in as: " << authlxapp.user_data.username << std::endl;
    }
}

std::string menu_main() {
    std::cout << "\n  MAIN MENU" << std::endl;
    std::cout << "  " << std::string(53, '-') << std::endl;
    std::cout << "  [1]  Login" << std::endl;
    std::cout << "  [2]  Register with License Key" << std::endl;
    std::cout << "  [3]  Web Login  (no HWID)" << std::endl;
    std::cout << "  [4]  Web Register  (no HWID)" << std::endl;
    std::cout << "  [5]  Forgot Password  (HWID-verified reset)" << std::endl;
    std::cout << "  [6]  Verify Standalone API Token" << std::endl;
    std::cout << "  [7]  Show HWID methods" << std::endl;
    std::cout << "  [8]  Debug Info" << std::endl;
    std::cout << "  [9]  Check & Install Updates" << std::endl;
    std::cout << "  [0]  Exit" << std::endl;
    return get_input("\n  › ");
}

std::string menu_account() {
    std::cout << "\n  ACCOUNT MENU" << std::endl;
    std::cout << "  " << std::string(53, '-') << std::endl;
    std::cout << "  [1]  Account Details  (view info & expiry)" << std::endl;
    std::cout << "  [2]  Change Username" << std::endl;
    std::cout << "  [3]  Upgrade Account  (apply another license key)" << std::endl;
    std::cout << "  [4]  Verify Session" << std::endl;
    std::cout << "  [5]  Logout" << std::endl;
    std::cout << "  [0]  Back" << std::endl;
    return get_input("\n  › ");
}

bool example_login(AuthLX::Api& authlxapp) {
    std::cout << "\n── LOGIN ──────────────────────────────────────────────" << std::endl;
    std::string user = get_input("  Username : ");
    std::string password = get_input("  Password : ");

    if (authlxapp.login(user, password)) {
        std::cout << "\n  ✓ Logged in as '" << authlxapp.user_data.username << "'" << std::endl;
        std::cout << "  Subscription : " << (authlxapp.user_data.subscription.empty() ? "N/A" : authlxapp.user_data.subscription) << std::endl;
        std::cout << "  Expires      : " << (authlxapp.user_data.expires.empty() ? "N/A" : authlxapp.user_data.expires) << std::endl;
        std::cout << "  Last Login   : " << (authlxapp.user_data.lastlogin.empty() ? "N/A" : authlxapp.user_data.lastlogin) << std::endl;

        double remaining = authlxapp.expiry_remaining();
        if (remaining > 0.0) {
            int d = (int)(remaining / 86400.0);
            int h = (int)(((long long)remaining % 86400) / 3600);
            std::cout << "  Time left    : " << d << "d " << h << "h" << std::endl;
        } else {
            std::cout << "  Time left    : EXPIRED" << std::endl;
        }

        authlxapp.start_ban_monitor(120);
        std::cout << "  Ban monitor  : Active (120s interval)" << std::endl;
        return true;
    }

    std::cout << "  ✗ Login failed." << std::endl;
    return false;
}

void example_register(AuthLX::Api& authlxapp) {
    std::cout << "\n── REGISTER ────────────────────────────────────────────" << std::endl;
    std::string user = get_input("  Username    : ");
    std::string email = get_input("  Email       : ");
    std::string password = get_input("  Password    : ");
    std::string key = get_input("  License Key : ");

    if (authlxapp.registerAccount(user, email, password, key)) {
        std::cout << "  ✓ Registered! You can now log in." << std::endl;
    } else {
        std::cout << "  ✗ Registration failed. Check the license key." << std::endl;
    }
}

bool example_web_login(AuthLX::Api& authlxapp) {
    std::cout << "\n── WEB LOGIN (no HWID) ─────────────────────────────────" << std::endl;
    std::string user = get_input("  Username : ");
    std::string password = get_input("  Password : ");

    if (authlxapp.webLogin(user, password)) {
        std::cout << "\n  ✓ Authenticated as '" << authlxapp.user_data.username << "'" << std::endl;
        std::cout << "  Subscription : " << (authlxapp.user_data.subscription.empty() ? "N/A" : authlxapp.user_data.subscription) << std::endl;
        std::cout << "  Expires      : " << (authlxapp.user_data.expires.empty() ? "N/A" : authlxapp.user_data.expires) << std::endl;
        std::cout << "  Last Login   : " << (authlxapp.user_data.lastlogin.empty() ? "N/A" : authlxapp.user_data.lastlogin) << std::endl;

        authlxapp.start_ban_monitor(120);
        std::cout << "  Ban monitor  : Active (120s interval)" << std::endl;
        return true;
    } else {
        if (authlxapp.lockout_active()) {
            long long secs = authlxapp.lockout_remaining_ms() / 1000;
            std::cout << "  ✗ Locked out for " << secs << " seconds." << std::endl;
        } else {
            std::cout << "  ✗ Web login failed." << std::endl;
        }
        return false;
    }
}

void example_register_web(AuthLX::Api& authlxapp) {
    std::cout << "\n── WEB REGISTER (no HWID) ──────────────────────────────" << std::endl;
    std::string user = get_input("  Username    : ");
    std::string email = get_input("  Email       : ");
    std::string password = get_input("  Password    : ");
    std::string key = get_input("  License Key : ");

    if (authlxapp.registerWeb(user, email, password, key)) {
        std::cout << "  ✓ Registered via web flow!" << std::endl;
    } else {
        std::cout << "  ✗ Registration failed." << std::endl;
    }
}

void example_upgrade(AuthLX::Api& authlxapp) {
    std::cout << "\n── UPGRADE ACCOUNT ─────────────────────────────────────" << std::endl;
    std::string user = get_input("  Username    : ");
    if (user.empty()) {
        user = authlxapp.user_data.username;
    }
    std::string key = get_input("  License Key : ");

    if (authlxapp.upgrade(user, key)) {
        std::cout << "  ✓ Account upgraded!" << std::endl;
    } else {
        std::cout << "  ✗ Upgrade failed. Check the license key." << std::endl;
    }
}

void example_change_username(AuthLX::Api& authlxapp) {
    std::cout << "\n── CHANGE USERNAME ─────────────────────────────────────" << std::endl;
    std::string new_name = get_input("  New Username : ");

    if (authlxapp.changeUsername(new_name)) {
        std::cout << "  ✓ Username changed to '" << authlxapp.user_data.username << "'" << std::endl;
    } else {
        std::cout << "  ✗ Username change failed." << std::endl;
    }
}

void example_forgot_password(AuthLX::Api& authlxapp) {
    std::cout << "\n── FORGOT PASSWORD (HWID-verified reset) ───────────────" << std::endl;
    std::cout << "  Your current Hardware ID will be used to verify your identity." << std::endl;
    std::string user = get_input("  Username     : ");
    std::string new_pass = get_input("  New Password : ");

    std::string hwid = AuthLX::Others::get_hwid(authlxapp.hwid_method);
    std::cout << "  Using HWID   : " << (hwid.length() > 20 ? hwid.substr(0, 20) + "..." : hwid) << std::endl;

    if (authlxapp.forgot(user, new_pass, hwid)) {
        std::cout << "  ✓ Password reset! You can now log in with your new password." << std::endl;
    } else {
        std::cout << "  ✗ Reset failed. Is this HWID bound to the account?" << std::endl;
    }
}

void example_verify_session(AuthLX::Api& authlxapp) {
    std::cout << "\n── VERIFY SESSION ──────────────────────────────────────" << std::endl;
    if (authlxapp.session_token.empty()) {
        std::cout << "  Not logged in." << std::endl;
        return;
    }
    if (authlxapp.check()) {
        std::cout << "  ✓ Session is valid." << std::endl;
    } else {
        std::cout << "  ✗ Session has expired or been revoked." << std::endl;
    }
}

void example_verify_token(AuthLX::Api& authlxapp) {
    std::cout << "\n── VERIFY STANDALONE TOKEN ─────────────────────────────" << std::endl;
    std::string token = get_input("  Token : ");

    if (authlxapp.verifyToken(token)) {
        std::cout << "  ✓ Token is valid." << std::endl;
    } else {
        std::cout << "  ✗ Token is invalid or banned." << std::endl;
    }
}

void example_logout(AuthLX::Api& authlxapp) {
    std::cout << "\n── LOGOUT ──────────────────────────────────────────────" << std::endl;
    authlxapp.stop_ban_monitor();
    if (authlxapp.logout()) {
        std::cout << "  ✓ Logged out successfully." << std::endl;
    } else {
        std::cout << "  ✗ Logout failed." << std::endl;
    }
}

void example_debug_info(AuthLX::Api& authlxapp) {
    std::cout << "\n── DEBUG INFO ──────────────────────────────────────────" << std::endl;
    auto info = authlxapp.debugInfo();
    for (auto const& pair : info) {
        const std::string& key = pair.first;
        const std::string& val = pair.second;
        int spaces = 20 - (int)key.length();
        if (spaces < 1) spaces = 1;
        std::cout << "  " << key << std::string(spaces, ' ') << " : " << val << std::endl;
    }
}

void example_hwid(AuthLX::Api& authlxapp) {
    std::cout << "\n── HWID METHODS ────────────────────────────────────────" << std::endl;
    std::cout << "  windows_user (SID)  : " << AuthLX::Others::get_hwid("windows_user") << std::endl;
    std::cout << "  machine (registry)  : " << AuthLX::Others::get_hwid("machine") << std::endl;
}

void example_account_details(AuthLX::Api& authlxapp) {
    std::cout << "\n── ACCOUNT DETAILS ──────────────────────────────────────" << std::endl;
    if (authlxapp.user_data.username.empty()) {
        std::cout << "  Not logged in." << std::endl;
        return;
    }

    std::cout << "  Username       : " << authlxapp.user_data.username << std::endl;
    std::cout << "  HWID Bound     : " << authlxapp.user_data.hwid << std::endl;
    std::cout << "  Subscription   : " << (authlxapp.user_data.subscription.empty() ? "N/A" : authlxapp.user_data.subscription) << std::endl;
    std::cout << "  Expires        : " << (authlxapp.user_data.expires.empty() ? "N/A" : authlxapp.user_data.expires) << std::endl;
    std::cout << "  Last Login     : " << (authlxapp.user_data.lastlogin.empty() ? "N/A" : authlxapp.user_data.lastlogin) << std::endl;
    std::cout << "  Created At     : " << (authlxapp.user_data.createdate.empty() ? "N/A" : authlxapp.user_data.createdate) << std::endl;

    if (!authlxapp.user_data.subscriptions.empty()) {
        std::cout << "  All Subs       : [";
        for (size_t i = 0; i < authlxapp.user_data.subscriptions.size(); ++i) {
            std::cout << "{'" << authlxapp.user_data.subscriptions[i].subscription << "', expiry: '" << authlxapp.user_data.subscriptions[i].expiry << "'}";
            if (i + 1 < authlxapp.user_data.subscriptions.size()) {
                std::cout << ", ";
            }
        }
        std::cout << "]" << std::endl;
    }
}

void example_check_updates(AuthLX::Api& authlxapp) {
    std::cout << "\n── CHECK & INSTALL UPDATES ─────────────────────────────" << std::endl;
    std::cout << "  Current Version : " << authlxapp.version << std::endl;
    std::cout << "  Checking server for latest release..." << std::endl;

    AuthLX::UpdateInfo info = authlxapp.check_for_updates();
    std::cout << "  Latest Version  : " << (info.latest_version.empty() ? "Unknown" : info.latest_version) << std::endl;

    if (info.update_available) {
        std::cout << "  ✓ Update Available! (v" << info.current_version << " → v" << info.latest_version << ")" << std::endl;
        std::cout << "  Download URL    : " << info.download_url << std::endl;
        std::string choice = get_input("\n  Install update now? (y/N): ");
        if (choice == "y" || choice == "Y") {
            authlxapp.perform_update(info);
        } else {
            std::cout << "  Update deferred by user." << std::endl;
        }
    } else {
        std::cout << "  ✓ You are running the latest version." << std::endl;
    }
}

int main() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    std::cout << "Initialising AuthLX security..." << std::endl;
    
    AuthLX::Api authlxapp(
        name,
        ownerid,
        version,
        secret,
        "", // hash_to_check
        url // api_url
    );

    // Optional host locking whitelist
    authlxapp.set_allowed_hosts({ "authlx.com" });

    std::cout << "✓ Initialised in " << (secret.empty() ? "OFF" : "SECURE") << " mode." << std::endl;
    std::cout << "  HWID Method : " << authlxapp.hwid_method << std::endl;
    std::cout << "  HWID        : " << AuthLX::Others::get_hwid(authlxapp.hwid_method) << std::endl;
    std::cout << "  Hash        : " << authlxapp.hash_to_check.substr(0, 24) << "..." << std::endl;
    std::cout << std::endl;
    
    get_input("  Press Enter to continue...");

    bool logged_in = false;

    while (true) {
        if (logged_in && !authlxapp.user_data.is_authenticated) {
            std::cout << "\n[SECURITY] Session revoked or account banned at runtime. Logging out..." << std::endl;
            authlxapp.stop_ban_monitor();
            logged_in = false;
            get_input("\n  Press Enter to continue...");
            continue;
        }

        banner(authlxapp);

        std::string choice;
        if (logged_in) {
            choice = menu_account();
            if (choice == "1") {
                example_account_details(authlxapp);
            } else if (choice == "2") {
                example_change_username(authlxapp);
            } else if (choice == "3") {
                example_upgrade(authlxapp);
            } else if (choice == "4") {
                example_verify_session(authlxapp);
            } else if (choice == "5") {
                example_logout(authlxapp);
                logged_in = false;
            } else if (choice == "0") {
                break;
            }
        } else {
            choice = menu_main();
            if (choice == "1") {
                logged_in = example_login(authlxapp);
            } else if (choice == "2") {
                example_register(authlxapp);
            } else if (choice == "3") {
                logged_in = example_web_login(authlxapp);
            } else if (choice == "4") {
                example_register_web(authlxapp);
            } else if (choice == "5") {
                example_forgot_password(authlxapp);
            } else if (choice == "6") {
                example_verify_token(authlxapp);
            } else if (choice == "7") {
                example_hwid(authlxapp);
            } else if (choice == "8") {
                example_debug_info(authlxapp);
            } else if (choice == "9") {
                example_check_updates(authlxapp);
            } else if (choice == "0") {
                std::cout << "\nGoodbye." << std::endl;
                break;
            }
        }

        if (choice != "0") {
            get_input("\n  Press Enter to continue...");
        }
    }

    return 0;
}
