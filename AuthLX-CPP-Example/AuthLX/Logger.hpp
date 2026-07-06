#pragma once
#include <string>
#include <fstream>
#include <iostream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <Windows.h>

namespace AuthLX {

enum class LogLevel {
    DebugLevel,
    InfoLevel,
    WarnLevel,
    ErrorLevel
};

class Logger {
public:
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }

    void init(const std::string& logFilePath, bool enableConsole = true, LogLevel level = LogLevel::InfoLevel) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_logFilePath = logFilePath;
        m_enableConsole = enableConsole;
        m_minLevel = level;

        if (!m_logFilePath.empty()) {
            std::filesystem::path path(m_logFilePath);
            std::filesystem::path dir = path.parent_path();
            if (!dir.empty() && !std::filesystem::exists(dir)) {
                std::filesystem::create_directories(dir);
            }
            m_fileStream.open(m_logFilePath, std::ios::out | std::ios::app);
        }
    }

    void setLevel(LogLevel level) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_minLevel = level;
    }

    void enableConsole(bool enable) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableConsole = enable;
    }

    void log(LogLevel level, const std::string& file, int line, const std::string& func, const std::string& message) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (level < m_minLevel) return;

        std::string timeStr = getTimestamp();
        std::string levelStr = getLevelString(level);
        
        // Strip path to get filename only
        std::string fileName = file;
        size_t lastSlash = fileName.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            fileName = fileName.substr(lastSlash + 1);
        }

        std::stringstream ss;
        ss << "[" << timeStr << "] [" << levelStr << "] [" << fileName << ":" << line << " " << func << "()] " << message;
        std::string formattedMsg = ss.str();

        // Console output (with Win32 console colors)
        if (m_enableConsole) {
            setConsoleColor(level);
            std::cout << formattedMsg << std::endl;
            resetConsoleColor();
        }

        // File output
        if (m_fileStream.is_open()) {
            m_fileStream << formattedMsg << std::endl;
        }
    }

private:
    Logger() : m_minLevel(LogLevel::InfoLevel), m_enableConsole(true) {}
    ~Logger() {
        if (m_fileStream.is_open()) {
            m_fileStream.close();
        }
    }

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    std::string getTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
        
        std::tm buf;
        localtime_s(&buf, &in_time_t);

        std::stringstream ss;
        ss << std::put_time(&buf, "%Y-%m-%d %H:%M:%S") << "." << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }

    std::string getLevelString(LogLevel level) {
        switch (level) {
            case LogLevel::DebugLevel: return "DEBUG";
            case LogLevel::InfoLevel:  return "INFO";
            case LogLevel::WarnLevel:  return "WARN";
            case LogLevel::ErrorLevel: return "ERROR";
        }
        return "LOG";
    }

    void setConsoleColor(LogLevel level) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConsole == INVALID_HANDLE_VALUE || hConsole == nullptr) return;

        switch (level) {
            case LogLevel::DebugLevel:
                SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); // Gray
                break;
            case LogLevel::InfoLevel:
                SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE); // Cyan
                break;
            case LogLevel::WarnLevel:
                SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); // Yellow
                break;
            case LogLevel::ErrorLevel:
                SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED); // Red
                break;
        }
    }

    void resetConsoleColor() {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConsole == INVALID_HANDLE_VALUE || hConsole == nullptr) return;
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); // default white/gray
    }

    std::string m_logFilePath;
    std::ofstream m_fileStream;
    bool m_enableConsole;
    LogLevel m_minLevel;
    std::mutex m_mutex;
};

} // namespace AuthLX

// Helper macros
#define LOG_DEBUG(msg) { std::stringstream ss; ss << msg; AuthLX::Logger::getInstance().log(AuthLX::LogLevel::DebugLevel, __FILE__, __LINE__, __FUNCTION__, ss.str()); }
#define LOG_INFO(msg)  { std::stringstream ss; ss << msg; AuthLX::Logger::getInstance().log(AuthLX::LogLevel::InfoLevel,  __FILE__, __LINE__, __FUNCTION__, ss.str()); }
#define LOG_WARN(msg)  { std::stringstream ss; ss << msg; AuthLX::Logger::getInstance().log(AuthLX::LogLevel::WarnLevel,  __FILE__, __LINE__, __FUNCTION__, ss.str()); }
#define LOG_ERROR(msg) { std::stringstream ss; ss << msg; AuthLX::Logger::getInstance().log(AuthLX::LogLevel::ErrorLevel, __FILE__, __LINE__, __FUNCTION__, ss.str()); }
