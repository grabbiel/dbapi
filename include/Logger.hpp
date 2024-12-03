#pragma once
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

enum class LogLevel { DEBUG, INFO, WARNING, ERROR, FATAL };

class Logger {
public:
  static Logger &getInstance() {
    static Logger instance;
    return instance;
  }

  void setLogFile(const std::string &filename) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (logFile_.is_open()) {
      logFile_.close();
    }
    logFile_.open(filename, std::ios::app);
  }

  void setLogLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    currentLevel_ = level;
  }

  template <typename... Args>
  void log(LogLevel level, const char *file, int line, Args... args) {
    if (level < currentLevel_)
      return;

    std::lock_guard<std::mutex> lock(mutex_);
    std::stringstream message;

    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    auto now_tm = std::localtime(&now_c);

    message << std::put_time(now_tm, "[%Y-%m-%d %H:%M:%S] ");
    message << "[" << getLevelString(level) << "]";

    (message << ... << args);
    message << std::endl;

    std::cout << message.str();

    if (logFile_.is_open()) {
      logFile_ << message.str();
      logFile_.flush();
    }
  }

  ~Logger() {
    if (logFile_.is_open()) {
      logFile_.close();
    }
  }

private:
  Logger() : currentLevel_(LogLevel::INFO) {}
  Logger(const Logger &) = delete;
  Logger &operator=(const Logger &) = delete;

  const char *getLevelString(LogLevel level) {
    switch (level) {
    case LogLevel::DEBUG:
      return "DEBUG";
    case LogLevel::INFO:
      return "INFO";
    case LogLevel::WARNING:
      return "WARNING";
    case LogLevel::ERROR:
      return "ERROR";
    case LogLevel::FATAL:
      return "FATAL";
    default:
      return "UNKNOWN";
    }
  }

  std::ofstream logFile_;
  LogLevel currentLevel_;
  std::mutex mutex_;
};

#define LOG_DEBUG(...)                                                         \
  Logger::getInstance().log(LogLevel::DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...)                                                          \
  Logger::getInstance().log(LogLevel::INFO, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARNING(...)                                                       \
  Logger::getInstance().log(LogLevel::WARNING, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...)                                                         \
  Logger::getInstance().log(LogLevel::ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_FATAL(...)                                                         \
  Logger::getInstance().log(LogLevel::FATAL, __FILE__, __LINE__, __VA_ARGS__)
