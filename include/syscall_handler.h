#ifndef SYSCALL_HANDLER_H
#define SYSCALL_HANDLER_H

#include <cstdint>

class SyscallHandler {
public:
    SyscallHandler();
    uint64_t HandleSyscall(uint64_t syscall_num, uint64_t* args);

private:
    void MapBionicCalls();
};

#endif
