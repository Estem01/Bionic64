#ifndef SYSCALL_HANDLER_H
#define SYSCALL_HANDLER_H

#include <cstdint>
#include <unordered_map>
#include <functional>

class SyscallHandler {
public:
    SyscallHandler();
    uint64_t HandleSyscall(uint64_t syscall_num, uint64_t* args);

private:
    void MapBionicCalls();
    std::unordered_map<uint64_t, std::function<uint64_t(uint64_t*)>> syscall_table_;
};

#endif
