#include "syscall_handler.h"
#include "logger.h"
#include <iostream>
#include <unistd.h>
#include <android/api-level.h>

SyscallHandler::SyscallHandler() {
    MapBionicCalls();
}

void SyscallHandler::MapBionicCalls() {
    Logger::Log(LogLevel::INFO, "Mapeando syscalls para Bionic...");
}

uint64_t SyscallHandler::HandleSyscall(uint64_t syscall_num, uint64_t* args) {
    Logger::Log(LogLevel::DEBUG, "Handling syscall nĂºmero: " + std::to_string(syscall_num));
    if (syscall_num == 1) {
        Logger::Log(LogLevel::INFO, "Executando syscall write...");
        return write(args[0], (void*)args[1], args[2]);
    }
    Logger::Log(LogLevel::ERROR, "Syscall nĂ£o suportada: " + std::to_string(syscall_num));
    return -1;
}
