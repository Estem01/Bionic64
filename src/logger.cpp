#include "logger.h"
#include <iostream>

void Logger::Log(LogLevel level, const std::string& message) {
    std::string prefix;
    switch (level) {
        case LogLevel::INFO:  prefix = "[INFO] "; break;
        case LogLevel::DEBUG: prefix = "[DEBUG] "; break;
        case LogLevel::ERROR: prefix = "[ERROR] "; break;
    }
    std::cout << prefix << message << std::endl;
}
