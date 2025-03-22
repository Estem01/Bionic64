#ifndef LOGGER_H
#define LOGGER_H

#include <string>

enum class LogLevel {
    INFO,
    DEBUG,
    ERROR
};

class Logger {
public:
    static void Log(LogLevel level, const std::string& message);
};

#endif

