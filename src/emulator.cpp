#include "emulator.h"
#include "logger.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <unistd.h>

#define ARM64(instr) \
    static_cast<uint8_t>(instr), \
    static_cast<uint8_t>(instr >> 8), \
    static_cast<uint8_t>(instr >> 16), \
    static_cast<uint8_t>(instr >> 24)

// --- Emulator ---
Emulator::Emulator(const std::string& filename) : syscall_handler() {
    Logger::Log(LogLevel::INFO, "Inicializando emulador para " + filename);
    detectAddressSize();
    LoadBinary(filename.c_str());
    if (!mem) {
        Logger::Log(LogLevel::ERROR, "Falha ao inicializar memória para " + filename);
        return;
    }
    jit = new JITCompiler(4096); // Tamanho inicial
    is_running = true;
    rax = rcx = rdx = rbx = rsp = rbp = rsi = rdi = r8 = r9 = 0;
    carry_flag = zero_flag = direction_flag = false;
    interrupt_flag = true;
    esp = mem->stack_pointer;
    initOpcodeTable();
}

Emulator::~Emulator() {
    Logger::Log(LogLevel::INFO, "Desalocando memória do emulador...");
    delete mem;
    delete jit;
    free(memory);
}

void Emulator::detectAddressSize() {
    long page_size = sysconf(_SC_PAGESIZE);
    address_size = (page_size == 4096) ? 64 : (page_size == 512) ? 39 : 48;
    Logger::Log(LogLevel::INFO, "Tamanho de endereço detectado: " + std::to_string(address_size) + " bits");
}

uint64_t Emulator::maskRegister(uint64_t value) {
    if (address_size == 39) return value & 0x7FFFFFFFFF;
    if (address_size == 48) return value & 0xFFFFFFFFFFFF;
    return value; // 64 bits
}

// --- MemoryManager ---
Emulator::MemoryManager::MemoryManager(size_t mem_size) : size(mem_size), rip(0), image_base(0) {
    virtual_memory = static_cast<uint8_t*>(mmap(nullptr, size, PROT_READ | PROT_WRITE,
                                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (virtual_memory == MAP_FAILED) {
        Logger::Log(LogLevel::ERROR, "Falha ao alocar memória virtual");
        throw std::runtime_error("mmap failed");
    }
    stack_base = size - sizeof(uint64_t);
    stack_pointer = stack_base;
    heap_base = sizeof(uint64_t);
    heap_pointer = heap_base;
    Logger::Log(LogLevel::DEBUG, "Memória alocada: " + std::to_string(size) + " bytes");
}

Emulator::MemoryManager::~MemoryManager() {
    munmap(virtual_memory, size);
}

void Emulator::MemoryManager::resize(size_t new_size) {
    if (new_size <= size) return;
    uint8_t* new_memory = static_cast<uint8_t*>(mremap(virtual_memory, size, new_size, MREMAP_MAYMOVE));
    if (new_memory == MAP_FAILED) {
        Logger::Log(LogLevel::ERROR, "Falha ao redimensionar memória");
        return;
    }
    virtual_memory = new_memory;
    stack_base = new_size - sizeof(uint64_t);
    if (stack_pointer > stack_base) stack_pointer = stack_base;
    size = new_size;
    Logger::Log(LogLevel::DEBUG, "Memória redimensionada para: " + std::to_string(new_size) + " bytes");
}

void Emulator::MemoryManager::mapSection(const PEInfo::Section& section, const uint8_t* data, size_t file_size) {
    uint64_t rva = section.virtual_address;
    if (rva + section.size > size) resize(rva + section.size + 4096);
    size_t copy_size = std::min(static_cast<size_t>(section.size), file_size - section.file_offset);
    memcpy(virtual_memory + rva, data + section.file_offset, copy_size);
    Logger::Log(LogLevel::DEBUG, "Mapeando seção em RVA 0x" + std::to_string(rva) + " com tamanho " + std::to_string(copy_size));
}

void Emulator::MemoryManager::write(uint64_t addr, uint64_t value, size_t bytes) {
    if (addr + bytes > size) resize(addr + bytes + 4096);
    memcpy(virtual_memory + addr, &value, bytes);
    Logger::Log(LogLevel::DEBUG, "Escrevendo 0x" + std::to_string(value) + " em 0x" + std::to_string(addr));
}

uint64_t Emulator::MemoryManager::read(uint64_t addr, size_t bytes) {
    if (addr + bytes > size) return 0;
    uint64_t value = 0;
    memcpy(&value, virtual_memory + addr, bytes);
    return value;
}

void Emulator::MemoryManager::push(uint64_t value) {
    if (stack_pointer < heap_pointer + sizeof(uint64_t)) resize(size + 4096);
    stack_pointer -= sizeof(uint64_t);
    write(stack_pointer, value, sizeof(uint64_t));
}

uint64_t Emulator::MemoryManager::pop() {
    if (stack_pointer + sizeof(uint64_t) <= stack_base) {
        uint64_t value = read(stack_pointer, sizeof(uint64_t));
        stack_pointer += sizeof(uint64_t);
        return value;
    }
    return 0;
}

uint64_t Emulator::MemoryManager::allocateHeap(size_t bytes) {
    if (heap_pointer + bytes > stack_pointer) resize(size + bytes + 4096);
    uint64_t addr = heap_pointer;
    heap_pointer += bytes;
    return addr;
}

void Emulator::MemoryManager::initStack(uint64_t return_addr, uint64_t entry_point, uint64_t img_base) {
    image_base = img_base;
    rip = maskRegister(img_base + entry_point);
    push(return_addr);
}

// --- JITCompiler ---
Emulator::JITCompiler::JITCompiler(size_t initial_size) : mem_size(initial_size), offset(0) {
    executable_memory = static_cast<uint8_t*>(mmap(nullptr, mem_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (executable_memory == MAP_FAILED) throw std::runtime_error("mmap failed");
}

Emulator::JITCompiler::~JITCompiler() {
    munmap(executable_memory, mem_size);
}

void Emulator::JITCompiler::resize(size_t new_size) {
    if (new_size <= mem_size) return;
    uint8_t* new_memory = static_cast<uint8_t*>(mremap(executable_memory, mem_size, new_size, MREMAP_MAYMOVE));
    if (new_memory == MAP_FAILED) {
        Logger::Log(LogLevel::ERROR, "Falha ao redimensionar memória JIT");
        return;
    }
    executable_memory = new_memory;
    mem_size = new_size;
}

void Emulator::JITCompiler::write(const std::vector<uint8_t>& code) {
    if (offset + code.size() > mem_size) resize(mem_size + code.size() + 4096);
    memcpy(executable_memory + offset, code.data(), code.size());
    offset += code.size();
}

void Emulator::JITCompiler::execute() {
    using Func = void(*)();
    Func fn = reinterpret_cast<Func>(executable_memory);
    fn();
}

void Emulator::JITCompiler::clear() { offset = 0; }

// --- Opcode Table ---
void Emulator::initOpcodeTable() {
    auto unknown = [](Emulator* emu, uint8_t* code, uint32_t& instr_size, int64_t& jump_offset) {
        Logger::Log(LogLevel::ERROR, "Instrução desconhecida: 0x" + std::to_string(code[0]));
        instr_size = 1;
    };

    for (int i = 0; i < 256; ++i) {
        opcode_table_[i] = OpcodeHandler("UNKNOWN", AddressingMode::NONE, unknown);
    }

    opcode_table_[0x00] = OpcodeHandler(
        "ADD_MEM_AL", AddressingMode::MEMORY,
        [](Emulator* emu, uint8_t* code, uint32_t& instr_size, int64_t& jump_offset) {
            uint64_t addr = emu->rax;
            uint8_t al = emu->rax & 0xFF;
            uint8_t value = emu->mem->read(addr, 1) + al;
            emu->mem->write(addr, value, 1);
            instr_size = 1;
            Logger::Log(LogLevel::INFO, "ADD [RAX], AL");
        },
        [](Emulator* emu, uint8_t* code, uint32_t& instr_size, int64_t& jump_offset) {
            instr_size = 1;
            std::vector<uint8_t> arm64 = {
                ARM64(0xB9400000), // LDRB W0, [X0] (carrega byte de [X0] em W0)
                ARM64(0x11000400), // ADD W0, W0, #1
                ARM64(0xB9000000)  // STRB W0, [X0] (armazena de volta)
            };
            return arm64;
        }
    );

    opcode_table_[0x40] = OpcodeHandler(
        "INC_EAX", AddressingMode::REGISTER,
        [](Emulator* emu, uint8_t* code, uint32_t& instr_size, int64_t& jump_offset) {
            emu->rax = emu->maskRegister(emu->rax + 1);
            emu->zero_flag = !emu->rax;
            instr_size = 1;
            Logger::Log(LogLevel::INFO, "INC RAX");
        },
        [](Emulator* emu, uint8_t* code, uint32_t& instr_size, int64_t& jump_offset) {
            instr_size = 1;
            uint32_t add = 0x91000400; // ADD X0, X0, #1
            return std::vector<uint8_t>{ARM64(add)};
        }
    );

    opcode_table_[0x89] = OpcodeHandler(
        "MOV_REG_MEM_REG", AddressingMode::REGISTER,
        [](Emulator* emu, uint8_t* code, uint32_t& instr_size, int64_t& jump_offset) {
            uint8_t modrm = code[1];
            uint8_t mod = modrm >> 6;
            uint8_t reg = (modrm >> 3) & 7;
            uint8_t rm = modrm & 7;
            if (mod == 3) {
                uint64_t* regs = &emu->rax;
                regs[rm] = regs[reg];
                Logger::Log(LogLevel::INFO, "MOV reg" + std::to_string(rm) + ", reg" + std::to_string(reg));
                instr_size = 2;
            } else {
                instr_size = 1;
            }
        },
        [](Emulator* emu, uint8_t* code, uint32_t& instr_size, int64_t& jump_offset) {
            uint8_t modrm = code[1];
            uint8_t reg = (modrm >> 3) & 7;
            uint8_t rm = modrm & 7;
            instr_size = 2;
            uint32_t mov = 0xAA0003E0 | (rm << 5) | reg; // MOV Xrm, Xreg
            return std::vector<uint8_t>{ARM64(mov)};
        }
    );

    opcode_table_[0xBE] = OpcodeHandler(
        "MOV_RSI_IMM32", AddressingMode::IMMEDIATE,
        [](Emulator* emu, uint8_t* code, uint32_t& instr_size, int64_t& jump_offset) {
            emu->rsi = emu->maskRegister(*(uint32_t*)(code + 1));
            instr_size = 5;
            Logger::Log(LogLevel::INFO, "MOV RSI, " + std::to_string(emu->rsi));
        },
        [](Emulator* emu, uint8_t* code, uint32_t& instr_size, int64_t& jump_offset) {
            uint32_t imm32 = *(uint32_t*)(code + 1);
            instr_size = 5;
            std::vector<uint8_t> arm64;
            uint32_t mov = 0xD2800006 | ((imm32 & 0xFFFF) << 5); // MOV X6, #imm32
            arm64.insert(arm64.end(), {ARM64(mov)});
            if (imm32 > 0xFFFF) {
                uint32_t movk = 0xF2800006 | (((imm32 >> 16) & 0xFFFF) << 5); // MOVK X6, #imm32>>16, LSL #16
                arm64.insert(arm64.end(), {ARM64(movk)});
            }
            return arm64;
        }
    );

    opcode_table_[0xEB] = OpcodeHandler(
        "JMP_REL8", AddressingMode::RELATIVE,
        [](Emulator* emu, uint8_t* code, uint32_t& instr_size, int64_t& jump_offset) {
            jump_offset = (int8_t)code[1];
            instr_size = 2;
            Logger::Log(LogLevel::INFO, "JMP rel8, offset = " + std::to_string(jump_offset));
        },
        [](Emulator* emu, uint8_t* code, uint32_t& instr_size, int64_t& jump_offset) {
            int8_t offset = (int8_t)code[1];
            instr_size = 2;
            jump_offset = offset;
            uint32_t b = 0x14000000 | (offset & 0x03FFFFFF); // B #offset (26-bit)
            return std::vector<uint8_t>{ARM64(b)};
        }
    );

    opcode_table_[0xCD] = OpcodeHandler(
        "INT", AddressingMode::IMMEDIATE,
        [](Emulator* emu, uint8_t* code, uint32_t& instr_size, int64_t& jump_offset) {
            if (code[1] == 0x80 && emu->binary_type == BinaryType::PE_X86) {
                uint64_t args[6] = {emu->rbx, emu->rcx, emu->rdx, emu->rsi, emu->rdi, emu->rbp};
                emu->rax = emu->syscall_handler.HandleSyscall(emu->rax, args, true);
                instr_size = 2;
                Logger::Log(LogLevel::INFO, "INT 0x80, resultado = " + std::to_string(emu->rax));
            } else {
                instr_size = 1;
            }
        },
        [](Emulator* emu, uint8_t* code, uint32_t& instr_size, int64_t& jump_offset) {
            instr_size = 2;
            // Syscall ARM64 (svc #0)
            uint32_t svc = 0xD4000001;
            return std::vector<uint8_t>{ARM64(svc)};
        }
    );
}

void Emulator::executeInstruction(uint8_t opcode, uint8_t* code, uint32_t& instr_size, int64_t& jump_offset) {
    if (opcode == 0x0F && code[1] == 0x05 && binary_type == BinaryType::PE_X64) {
        uint64_t args[6] = {rdi, rsi, rdx, rcx, r8, r9};
        rax = syscall_handler.HandleSyscall(rax, args, false);
        instr_size = 2;
        Logger::Log(LogLevel::INFO, "SYSCALL " + std::to_string(rax));
    } else {
        opcode_table_[opcode].execute(this, code, instr_size, jump_offset);
    }
}

void Emulator::LoadBinary(const char* path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        Logger::Log(LogLevel::ERROR, "Falha ao abrir o arquivo: " + std::string(path));
        return;
    }

    memory_size = file.tellg();
    file.seekg(0, std::ios::beg);
    memory = malloc(memory_size);
    if (!memory) {
        file.close();
        return;
    }
    file.read((char*)memory, memory_size);
    file.close();

    if (DetectBinaryType(pe_info)) {
        mem = new MemoryManager(pe_info.image_size);
        for (const auto& section : pe_info.sections) {
            mem->mapSection(section, (uint8_t*)memory, memory_size);
        }
        ApplyRelocations(pe_info);
        mem->initStack(0xFFFFFFFF, pe_info.entry_point, pe_info.image_base);
        esp = mem->stack_pointer;
        ebp = mem->allocateHeap(0x1000); // 4 KB de heap inicial
    }
}

void Emulator::run() {
    Logger::Log(LogLevel::INFO, "Iniciando execução em RIP: 0x" + std::to_string(mem->rip));
    while (is_running) {
        uint8_t* code = mem->getCodeAt(mem->rip);
        if (!code) break;

        uint32_t instr_size = 1;
        int64_t jump_offset = 0;

        auto it = block_cache.find(mem->rip);
        if (it != block_cache.end()) {
            instr_size = it->second.second;
            jump_offset = it->second.first;
        } else {
            std::vector<uint8_t> arm64_code = opcode_table_[code[0]].translate(this, code, instr_size, jump_offset);
            if (arm64_code.empty()) {
                executeInstruction(code[0], code, instr_size, jump_offset);
            } else {
                jit->write(arm64_code);
                block_cache[mem->rip] = {jump_offset, instr_size};
            }
        }

        mem->rip = maskRegister(mem->rip + instr_size);
        if (jump_offset != 0) {
            if (jump_offset == -1) { // RET
                mem->rip = maskRegister(mem->pop());
                if (mem->rip == 0xFFFFFFFF) is_running = false;
            } else {
                mem->rip = maskRegister(mem->rip + jump_offset);
            }
        }
        jit->execute();
        jit->clear();
    }
    Logger::Log(LogLevel::INFO, "Execução finalizada em RIP: 0x" + std::to_string(mem->rip));
}

// Stubs
bool Emulator::DetectBinaryType(PEInfo& pe_info) {
    pe_info.image_base = 0x400000;
    pe_info.entry_point = 0x1000;
    pe_info.image_size = 0x10000;
    pe_info.sections.push_back({0x1000, 0x1000, 0});
    binary_type = BinaryType::PE_X86; // Default
    return true;
}

void Emulator::ApplyRelocations(PEInfo& pe_info) {
    // Stub
}
