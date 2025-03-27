#ifndef SYSCALL_HANDLER_H
#define SYSCALL_HANDLER_H

#include <cstdint>
#include <unordered_map>
#include <functional>

class SyscallHandler {
public:
    SyscallHandler();
    uint64_t HandleSyscall(uint64_t syscall_num, uint64_t* args);
    //uint64_t HandleSyscall(uint64_t syscall_num, uint64_t* args, bool is_32bit);

private:
    void MapBionicCalls();
    //std::unordered_map<uint64_t, std::function<uint64_t(uint64_t*, bool)>> syscall_table_32bit;
    //std::unordered_map<uint64_t, std::function<uint64_t(uint64_t*, bool)>> syscall_table_64bit;
};

#endif
