#include "emulator.h"
#include "logger.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <algorithm>

// Macro para empacotar instruções ARM64 em bytes
#define ARM64(instr) \
    static_cast<uint8_t>(instr), \
    static_cast<uint8_t>(instr >> 8), \
    static_cast<uint8_t>(instr >> 16), \
    static_cast<uint8_t>(instr >> 24)

Emulator::Emulator(const std::string& filename) {
    Logger::Log(LogLevel::INFO, "Inicializando emulador para " + filename);
    LoadBinary(filename.c_str());
    if (!mem) {
        Logger::Log(LogLevel::ERROR, "Falha ao inicializar memória para " + filename);
        return;
    }
    is_running = true;
    // Inicializar registradores
    eax = ecx = edx = ebx = esp = ebp = esi = edi = 0;
    carry_flag = zero_flag = direction_flag = false;
    interrupt_flag = true;
    esp = mem->stack_pointer;
}

Emulator::~Emulator() {
    Logger::Log(LogLevel::INFO, "Desalocando memória do emulador...");
    delete mem;
    free(memory);
}

// --- MemoryManager ---
Emulator::MemoryManager::MemoryManager(size_t mem_size) : size(mem_size), virtual_memory(nullptr), rip(0), image_base(0) {
    virtual_memory = new uint8_t[size]();
    stack_base = size - sizeof(uint32_t); // Alinhado ao final da memória
    stack_pointer = stack_base;
    heap_base = sizeof(uint32_t); // Início após o cabeçalho básico
    heap_pointer = heap_base;
    Logger::Log(LogLevel::DEBUG, "Memória alocada: " + std::to_string(size) + " bytes, Stack Base: 0x" + std::to_string(stack_base));
}

Emulator::MemoryManager::~MemoryManager() {
    delete[] virtual_memory;
}

void Emulator::MemoryManager::mapSection(const PEInfo::Section& section, const uint8_t* data, size_t file_size) {
    uint32_t rva = section.virtual_address;
    if (rva + section.size > size) {
        Logger::Log(LogLevel::ERROR, "Seção excede tamanho da memória: RVA 0x" + std::to_string(rva));
        return;
    }
    size_t copy_size = std::min(section.size, static_cast<uint32_t>(file_size - section.file_offset));
    memcpy(virtual_memory + rva, data + section.file_offset, copy_size);
    Logger::Log(LogLevel::DEBUG, "Mapeando seção em RVA 0x" + std::to_string(rva) + " com tamanho " + std::to_string(copy_size));
}

void Emulator::MemoryManager::write(uint32_t addr, uint32_t value, size_t bytes) {
    if (addr + bytes <= size) {
        memcpy(virtual_memory + addr, &value, bytes);
        Logger::Log(LogLevel::DEBUG, "Escrevendo 0x" + std::to_string(value) + " em 0x" + std::to_string(addr) + " (" + std::to_string(bytes) + " bytes)");
    } else {
        Logger::Log(LogLevel::ERROR, "Endereço fora do limite: 0x" + std::to_string(addr));
    }
}

uint32_t Emulator::MemoryManager::read(uint32_t addr, size_t bytes) {
    if (addr + bytes <= size) {
        uint32_t value = 0;
        memcpy(&value, virtual_memory + addr, bytes);
        Logger::Log(LogLevel::DEBUG, "Lendo 0x" + std::to_string(value) + " de 0x" + std::to_string(addr) + " (" + std::to_string(bytes) + " bytes)");
        return value;
    }
    Logger::Log(LogLevel::ERROR, "Endereço fora do limite: 0x" + std::to_string(addr));
    return 0;
}

void Emulator::MemoryManager::push(uint32_t value) {
    if (stack_pointer >= heap_pointer + sizeof(uint32_t)) {
        stack_pointer -= sizeof(uint32_t);
        write(stack_pointer, value, sizeof(uint32_t));
    } else {
        Logger::Log(LogLevel::ERROR, "Stack overflow em ESP: 0x" + std::to_string(stack_pointer));
    }
}

uint32_t Emulator::MemoryManager::pop() {
    if (stack_pointer + sizeof(uint32_t) <= stack_base + sizeof(uint32_t)) { // Evitar underflow
        uint32_t value = read(stack_pointer, sizeof(uint32_t));
        stack_pointer += sizeof(uint32_t);
        return value;
    }
    Logger::Log(LogLevel::ERROR, "Stack underflow em ESP: 0x" + std::to_string(stack_pointer));
    return 0;
}

uint32_t Emulator::MemoryManager::allocateHeap(size_t bytes) {
    if (heap_pointer + bytes <= stack_pointer) {
        uint32_t addr = heap_pointer;
        heap_pointer += bytes;
        Logger::Log(LogLevel::DEBUG, "Heap alocado em 0x" + std::to_string(addr) + " com " + std::to_string(bytes) + " bytes");
        return addr;
    }
    Logger::Log(LogLevel::ERROR, "Heap overflow em 0x" + std::to_string(heap_pointer));
    return 0;
}

void Emulator::MemoryManager::initStack(uint32_t return_addr, uint32_t entry_point, uint32_t img_base) {
    image_base = img_base;
    rip = image_base + entry_point;
    push(0xFFFFFFFF);
    Logger::Log(LogLevel::DEBUG, "Stack inicializado: RIP = 0x" + std::to_string(rip) + ", ESP = 0x" + std::to_string(stack_pointer));
}

uint8_t* Emulator::MemoryManager::getCodeAt(uint64_t addr) const {
    uint64_t offset = addr - image_base;
    if (offset < size) {
        return virtual_memory + offset;
    }
    Logger::Log(LogLevel::ERROR, "Endereço de código fora dos limites: 0x" + std::to_string(addr));
    return virtual_memory;
}

// --- Binary Loading ---
void Emulator::LoadBinary(const char* path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        Logger::Log(LogLevel::ERROR, "Falha ao abrir o arquivo: " + std::string(path));
        return;
    }

    memory_size = file.tellg();
    file.seekg(0, std::ios::beg);
    memory = malloc(memory_size);
    file.read(static_cast<char*>(memory), memory_size);
    file.close();

    if (DetectBinaryType(pe_info)) {
        size_t total_size = pe_info.image_size;
        for (const auto& section : pe_info.sections) {
            total_size = std::max(total_size, static_cast<size_t>(section.virtual_address + section.size));
        }
        if (pe_info.reloc_rva) {
            total_size = std::max(total_size, static_cast<size_t>(pe_info.reloc_rva + pe_info.reloc_size));
        }
        total_size += 0x10000; // Reserva extra para stack/heap

        mem = new MemoryManager(total_size);
        for (const auto& section : pe_info.sections) {
            mem->mapSection(section, static_cast<uint8_t*>(memory), memory_size);
        }
        ApplyRelocations(pe_info);

        uint32_t return_addr = pe_info.image_base + pe_info.entry_point + 0x1000; // Retorno dinâmico
        mem->initStack(return_addr, pe_info.entry_point, pe_info.image_base);
        esp = mem->stack_pointer;
        ebp = mem->allocateHeap(0x1000); // Aloca heap inicial dinamicamente
    }
}

bool Emulator::DetectBinaryType(PEInfo& pe_info) {
    uint8_t* mem_bytes = static_cast<uint8_t*>(memory);
    if (memory_size < 4 || mem_bytes[0] != 0x4D || mem_bytes[1] != 0x5A) {
        return false;
    }

    uint32_t pe_offset = *reinterpret_cast<uint32_t*>(mem_bytes + 0x3C);
    if (pe_offset + 24 >= memory_size || mem_bytes[pe_offset] != 0x50 || mem_bytes[pe_offset + 1] != 0x45) {
        return false;
    }

    uint16_t machine = *reinterpret_cast<uint16_t*>(mem_bytes + pe_offset + 4);
    if (machine == 0x14C) {
        binary_type = BinaryType::PE_X86;
    } else if (machine == 0x8664) {
        binary_type = BinaryType::PE_X64;
    } else {
        return false;
    }

    uint32_t opt_header_offset = pe_offset + 24;
    pe_info.image_base = *reinterpret_cast<uint32_t*>(mem_bytes + opt_header_offset + 28);
    pe_info.entry_point = *reinterpret_cast<uint32_t*>(mem_bytes + opt_header_offset + 16);
    pe_info.image_size = *reinterpret_cast<uint32_t*>(mem_bytes + opt_header_offset + 80);

    uint16_t number_of_sections = *reinterpret_cast<uint16_t*>(mem_bytes + pe_offset + 6);
    uint32_t section_table_offset = opt_header_offset + 224;
    for (uint16_t i = 0; i < number_of_sections && section_table_offset + i * 40 + 40 <= memory_size; i++) {
        PEInfo::Section section;
        uint32_t offset = section_table_offset + i * 40;
        section.virtual_address = *reinterpret_cast<uint32_t*>(mem_bytes + offset + 12);
        section.size = *reinterpret_cast<uint32_t*>(mem_bytes + offset + 8);
        section.file_offset = *reinterpret_cast<uint32_t*>(mem_bytes + offset + 20);
        pe_info.sections.push_back(section);
    }

    uint32_t data_dir_offset = opt_header_offset + 96;
    if (data_dir_offset + 48 <= memory_size) {
        pe_info.reloc_rva = *reinterpret_cast<uint32_t*>(mem_bytes + data_dir_offset + 40);
        pe_info.reloc_size = *reinterpret_cast<uint32_t*>(mem_bytes + data_dir_offset + 44);
    }
    return true;
}

void Emulator::ApplyRelocations(PEInfo& pe_info) {
    if (!pe_info.reloc_rva || !pe_info.reloc_size) {
        return;
    }

    uint32_t delta = mem->image_base - pe_info.image_base;
    if (!delta) {
        return;
    }

    uint8_t* reloc_data = mem->virtual_memory + pe_info.reloc_rva;
    uint32_t offset = 0;
    while (offset + 8 <= pe_info.reloc_size) {
        uint32_t page_rva = *reinterpret_cast<uint32_t*>(reloc_data + offset);
        uint32_t block_size = *reinterpret_cast<uint32_t*>(reloc_data + offset + 4);
        offset += 8;

        if (!block_size) break;

        for (uint32_t i = 0; i < (block_size - 8) / 2 && offset + i * 2 + 2 <= pe_info.reloc_size; i++) {
            uint16_t entry = *reinterpret_cast<uint16_t*>(reloc_data + offset + i * 2);
            if ((entry >> 12) == 3) { // HIGHLOW
                uint32_t addr = page_rva + (entry & 0xFFF);
                uint32_t value = mem->read(addr, 4) + delta;
                mem->write(addr, value, 4);
            }
        }
        offset += block_size - 8;
    }
}

// --- Instruction Handling ---
void Emulator::executeInstruction(uint8_t opcode, uint8_t* code, uint32_t& instr_size, int64_t& jump_offset) {
    uint8_t modrm = (instr_size < mem->size) ? code[1] : 0;
    uint8_t mod = (modrm >> 6) & 0x3;
    uint8_t reg = (modrm >> 3) & 0x7;
    uint8_t rm = modrm & 0x7;
    int32_t disp = 0;

    if (mod == 0x1 && instr_size + 1 < mem->size) {
        disp = static_cast<int8_t>(code[2]);
        instr_size += 2;
    } else if (mod == 0x2 && instr_size + 3 < mem->size) {
        disp = *reinterpret_cast<int32_t*>(code + 2);
        instr_size += 5;
    } else if (modrm) {
        instr_size++;
    }

    std::stringstream ss;
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(opcode);
    Logger::Log(LogLevel::DEBUG, "Executando opcode: 0x" + ss.str());

    switch (opcode) {
        case 0x00: { // ADD [EAX], AL
            uint32_t addr = eax;
            if (addr < mem->size) {
                uint8_t al = eax & 0xFF;
                uint8_t value = mem->read(addr, 1) + al;
                mem->write(addr, value, 1);
                Logger::Log(LogLevel::INFO, "ADD [EAX], AL");
            }
            instr_size = 1;
            break;
        }
        case 0x08: { // OR [mem], reg
            if (mod == 0x0 && rm == 0x4 && instr_size + 1 < mem->size) {
                uint8_t sib = code[2];
                uint8_t scale = (sib >> 6) & 0x3;
                uint8_t index = (sib >> 3) & 0x7;
                uint8_t base = sib & 0x7;
                uint32_t addr = (base == 0) ? eax : (base == 1) ? ecx : (base == 2) ? edx : (base == 3) ? ebx :
                                (base == 4) ? esp : (base == 5) ? ebp : (base == 6) ? esi : edi;
                addr += ((index == 0) ? eax : (index == 1) ? ecx : (index == 2) ? edx : (index == 3) ? ebx :
                         (index == 4) ? 0 : (index == 5) ? ebp : (index == 6) ? esi : edi) << scale;
                if (addr < mem->size) {
                    uint8_t src = (reg == 0) ? (eax & 0xFF) : (reg == 1) ? (ecx & 0xFF) : 
                                  (reg == 2) ? (edx & 0xFF) : (reg == 3) ? (ebx & 0xFF) : 
                                  (reg == 4) ? (esp & 0xFF) : (reg == 5) ? (ebp & 0xFF) : 
                                  (reg == 6) ? (esi & 0xFF) : (edi & 0xFF);
                    uint8_t value = mem->read(addr, 1) | src;
                    mem->write(addr, value, 1);
                    Logger::Log(LogLevel::INFO, "OR [mem], reg" + std::to_string(reg));
                }
                instr_size = 3;
            }
            break;
        }
        case 0x15: { // ADC EAX, imm32
            if (instr_size + 3 < mem->size) {
                uint32_t imm32 = *reinterpret_cast<uint32_t*>(code + 1);
                eax += imm32 + (carry_flag ? 1 : 0);
                carry_flag = (eax < imm32);
                zero_flag = (eax == 0);
                Logger::Log(LogLevel::INFO, "ADC EAX, " + std::to_string(imm32));
                instr_size = 5;
            }
            break;
        }
        case 0x31: { // XOR reg, reg/mem
            if (mod == 0x3) {
                uint32_t& dst = (rm == 0) ? eax : (rm == 1) ? ecx : (rm == 2) ? edx : (rm == 3) ? ebx :
                                (rm == 4) ? esp : (rm == 5) ? ebp : (rm == 6) ? esi : edi;
                uint32_t src = (reg == 0) ? eax : (reg == 1) ? ecx : (reg == 2) ? edx : (reg == 3) ? ebx :
                               (reg == 4) ? esp : (reg == 5) ? ebp : (reg == 6) ? esi : edi;
                dst ^= src;
                zero_flag = (dst == 0);
                Logger::Log(LogLevel::INFO, "XOR reg" + std::to_string(rm) + ", reg" + std::to_string(reg));
            }
            instr_size = 2;
            break;
        }
        case 0x33: { // XOR reg, [mem]
            if (mod == 0x2 && rm == 0x5) {
                uint32_t addr = ebp + disp;
                if (addr < mem->size) {
                    uint32_t value = mem->read(addr, 4);
                    switch (reg) {
                        case 0: eax ^= value; zero_flag = (eax == 0); break;
                        case 1: ecx ^= value; zero_flag = (ecx == 0); break;
                        case 2: edx ^= value; zero_flag = (edx == 0); break;
                        case 3: ebx ^= value; zero_flag = (ebx == 0); break;
                        case 4: esp ^= value; zero_flag = (esp == 0); break;
                        case 5: ebp ^= value; zero_flag = (ebp == 0); break;
                        case 6: esi ^= value; zero_flag = (esi == 0); break;
                        case 7: edi ^= value; zero_flag = (edi == 0); break;
                    }
                    Logger::Log(LogLevel::INFO, "XOR reg" + std::to_string(reg) + ", [EBP + " + std::to_string(disp) + "]");
                }
            }
            break;
        }
	case 0x3B: { // CMP reg, reg/mem
            if (mod == 0x3) {
                uint32_t src = (reg == 0) ? eax : (reg == 1) ? ecx : (reg == 2) ? edx : (reg == 3) ? ebx :
                               (reg == 4) ? esp : (reg == 5) ? ebp : (reg == 6) ? esi : edi;
                uint32_t dst = (rm == 0) ? eax : (rm == 1) ? ecx : (rm == 2) ? edx : (rm == 3) ? ebx :
                               (rm == 4) ? esp : (rm == 5) ? ebp : (rm == 6) ? esi : edi;
                zero_flag = (dst == src);
                carry_flag = (dst < src);
                Logger::Log(LogLevel::INFO, "CMP reg" + std::to_string(rm) + ", reg" + std::to_string(reg));
                instr_size = 2;
            }
            break;
        }
	case 0xBE: { // MOV ESI, imm32
            if (instr_size + 4 < mem->size) {
                esi = *reinterpret_cast<uint32_t*>(code + 1);
                Logger::Log(LogLevel::INFO, "MOV ESI, " + std::to_string(esi));
                instr_size = 5;
            }
            break;
        }
        case 0x40: { // INC EAX
            eax++;
            zero_flag = (eax == 0);
            Logger::Log(LogLevel::INFO, "INC EAX");
            instr_size = 1;
            break;
        }
        case 0x45: { // INC EBP
            ebp++;
            zero_flag = (ebp == 0);
            Logger::Log(LogLevel::INFO, "INC EBP");
            instr_size = 1;
            break;
        }
        case 0x4A: { // DEC EDX
            edx--;
            zero_flag = (edx == 0);
            Logger::Log(LogLevel::INFO, "DEC EDX");
            instr_size = 1;
            break;
        }
        case 0x4D: { // DEC EBP
            ebp--;
            zero_flag = (ebp == 0);
            Logger::Log(LogLevel::INFO, "DEC EBP");
            instr_size = 1;
            break;
        }
        case 0x4E: { // DEC ESI
            esi--;
            zero_flag = (esi == 0);
            Logger::Log(LogLevel::INFO, "DEC ESI");
            instr_size = 1;
            break;
        }
        case 0x50: { // PUSH EAX
            mem->push(eax);
            esp = mem->stack_pointer;
            Logger::Log(LogLevel::INFO, "PUSH EAX");
            instr_size = 1;
            break;
        }
        case 0x51: { // PUSH ECX
            mem->push(ecx);
            esp = mem->stack_pointer;
            Logger::Log(LogLevel::INFO, "PUSH ECX");
            instr_size = 1;
            break;
        }
        case 0x55: { // PUSH EBP
            mem->push(ebp);
            esp = mem->stack_pointer;
            Logger::Log(LogLevel::INFO, "PUSH EBP");
            break;
        }
        case 0x56: { // PUSH ESI
            mem->push(esi);
            esp = mem->stack_pointer;
            Logger::Log(LogLevel::INFO, "PUSH ESI");
            instr_size = 1;
            break;
        }
        case 0x57: { // PUSH EDI
            mem->push(edi);
            esp = mem->stack_pointer;
            Logger::Log(LogLevel::INFO, "PUSH EDI");
            instr_size = 1;
            break;
        }
        case 0x5D: { // POP EBP
            ebp = mem->pop();
            esp = mem->stack_pointer;
            Logger::Log(LogLevel::INFO, "POP EBP");
            instr_size = 1;
            break;
        }
        case 0x5E: { // POP ESI
            esi = mem->pop();
            esp = mem->stack_pointer;
            Logger::Log(LogLevel::INFO, "POP ESI");
            instr_size = 1;
            break;
        }
        case 0x5F: { // POP EDI
            edi = mem->pop();
            esp = mem->stack_pointer;
            Logger::Log(LogLevel::INFO, "POP EDI");
            instr_size = 1;
            break;
        }
        case 0xFA: { // CLI
            interrupt_flag = false;
            Logger::Log(LogLevel::INFO, "CLI");
            instr_size = 1;
            break;
        }
        case 0xBB: { // MOV EBX, imm32
            if (instr_size + 4 < mem->size) {
                ebx = *reinterpret_cast<uint32_t*>(code + 1);
                Logger::Log(LogLevel::INFO, "MOV EBX, " + std::to_string(ebx));
                instr_size = 5;
            }
            break;
        }
        case 0xBF: { // MOV EDI, imm32
            if (instr_size + 4 < mem->size) {
                edi = *reinterpret_cast<uint32_t*>(code + 1);
                Logger::Log(LogLevel::INFO, "MOV EDI, " + std::to_string(edi));
                instr_size = 5;
            }
            break;
        }
	case 0xF7: { // TEST/NEG/MUL/IMUL/DIV/IDIV
            if (instr_size + 1 < mem->size) {
                if (reg == 0 && instr_size + 5 < mem->size) { // TEST reg/mem, imm32
                    uint32_t imm32 = *reinterpret_cast<uint32_t*>(code + 2);
                    uint32_t value = (mod == 0x3) ? ((rm == 0) ? eax : (rm == 1) ? ecx : (rm == 2) ? edx : (rm == 3) ? ebx :
                                                    (rm == 4) ? esp : (rm == 5) ? ebp : (rm == 6) ? esi : edi) :
                                                    mem->read(ebp + disp, 4);
                    uint32_t result = value & imm32;
                    zero_flag = (result == 0);
                    carry_flag = false;
                    Logger::Log(LogLevel::INFO, "TEST " + std::string((mod == 0x3) ? "reg" + std::to_string(rm) : "[mem]") + ", " + std::to_string(imm32));
                    instr_size = (mod == 0x3) ? 6 : 6;
                } else if (reg == 3 && mod == 0x3) { // NEG reg
                    uint32_t& value = (rm == 0) ? eax : (rm == 1) ? ecx : (rm == 2) ? edx : (rm == 3) ? ebx :
                                     (rm == 4) ? esp : (rm == 5) ? ebp : (rm == 6) ? esi : edi;
                    carry_flag = (value != 0);
                    value = -value;
                    zero_flag = (value == 0);
                    Logger::Log(LogLevel::INFO, "NEG reg" + std::to_string(rm));
                    instr_size = 2;
                }
            }
            break;
        }
        
        case 0x74: { // JE rel8
            if (instr_size < mem->size) {
                int8_t rel8 = static_cast<int8_t>(code[1]);
                if (zero_flag) jump_offset = rel8;
                Logger::Log(LogLevel::INFO, "JE rel8, offset = " + std::to_string(rel8));
                instr_size = 2;
            }
            break;
        }
        case 0x75: { // JNZ rel8
            if (instr_size < mem->size) {
                int8_t rel8 = static_cast<int8_t>(code[1]);
                if (!zero_flag) jump_offset = rel8;
                Logger::Log(LogLevel::INFO, "JNZ rel8, offset = " + std::to_string(rel8));
                instr_size = 2;
            }
            break;
        }
        case 0x80: { // CMP [mem], imm8
            if (mod == 0x0 && rm == 0x0 && instr_size + 2 < mem->size) {
                int8_t disp8 = static_cast<int8_t>(code[2]);
                uint8_t imm8 = code[3];
                uint32_t addr = eax + disp8;
                if (addr < mem->size) {
                    uint8_t value = mem->read(addr, 1);
                    zero_flag = (value == imm8);
                    carry_flag = (value < imm8);
                    Logger::Log(LogLevel::INFO, "CMP [EAX + " + std::to_string(disp8) + "], " + std::to_string(imm8));
                    instr_size = 4;
                }
            }
            break;
        }
        case 0x83: { // CMP/SUB/ADD reg/mem, imm8
            if (instr_size + 1 < mem->size) {
                uint8_t op = reg;
                int8_t imm8 = static_cast<int8_t>(code[2]);
                if (mod == 0x3) {
                    uint32_t& dst = (rm == 0) ? eax : (rm == 1) ? ecx : (rm == 2) ? edx : (rm == 3) ? ebx :
                                    (rm == 4) ? esp : (rm == 5) ? ebp : (rm == 6) ? esi : edi;
                    if (op == 7) { // CMP
                        zero_flag = (dst == imm8);
                        carry_flag = (dst < imm8);
                        Logger::Log(LogLevel::INFO, "CMP reg" + std::to_string(rm) + ", " + std::to_string(imm8));
                    } else if (op == 5) { // SUB
                        dst -= imm8;
                        zero_flag = (dst == 0);
                        carry_flag = (dst > imm8);
                        Logger::Log(LogLevel::INFO, "SUB reg" + std::to_string(rm) + ", " + std::to_string(imm8));
                    }
                    instr_size = 3;
                }
            }
            break;
        }
        case 0x85: { // TEST reg, reg/mem
            if (mod == 0x3) {
                uint32_t src = (reg == 0) ? eax : (reg == 1) ? ecx : (reg == 2) ? edx : (reg == 3) ? ebx :
                               (reg == 4) ? esp : (reg == 5) ? ebp : (reg == 6) ? esi : edi;
                uint32_t dst = (rm == 0) ? eax : (rm == 1) ? ecx : (rm == 2) ? edx : (rm == 3) ? ebx :
                               (rm == 4) ? esp : (rm == 5) ? ebp : (rm == 6) ? esi : edi;
                uint32_t result = src & dst;
                zero_flag = (result == 0);
                carry_flag = false;
                Logger::Log(LogLevel::INFO, "TEST reg" + std::to_string(rm) + ", reg" + std::to_string(reg));
                instr_size = 2;
            }
            break;
        }
        case 0x89: { // MOV reg/mem, reg
            if (mod == 0x3) {
                uint32_t src = (reg == 0) ? eax : (reg == 1) ? ecx : (reg == 2) ? edx : (reg == 3) ? ebx :
                               (reg == 4) ? esp : (reg == 5) ? ebp : (reg == 6) ? esi : edi;
                uint32_t& dst = (rm == 0) ? eax : (rm == 1) ? ecx : (rm == 2) ? edx : (rm == 3) ? ebx :
                                (rm == 4) ? esp : (rm == 5) ? ebp : (rm == 6) ? esi : edi;
                dst = src;
                Logger::Log(LogLevel::INFO, "MOV reg" + std::to_string(rm) + ", reg" + std::to_string(reg));
                instr_size = 2;
            }
            break;
        }
        case 0x8B: { // MOV reg, [mem]
            if (mod == 0x2 && rm == 0x5) {
                uint32_t addr = ebp + disp;
                if (addr < mem->size) {
                    uint32_t value = mem->read(addr, 4);
                    switch (reg) {
                        case 0: eax = value; break;
                        case 1: ecx = value; break;
                        case 2: edx = value; break; // Corrigido de "8B" para "2"
                        case 3: ebx = value; break;
                        case 4: esp = value; break;
                        case 5: ebp = value; break;
                        case 6: esi = value; break;
                        case 7: edi = value; break;
                    }
                    Logger::Log(LogLevel::INFO, "MOV reg" + std::to_string(reg) + ", [EBP + " + std::to_string(disp) + "]");
                }
            }
            break;
        }
        case 0x8D: { // LEA reg, [mem]
            if (mod == 0x2 && rm == 0x5) {
                uint32_t addr = ebp + disp;
                switch (reg) {
                    case 0: eax = addr; break;
                    case 1: ecx = addr; break;
                    case 2: edx = addr; break;
                    case 3: ebx = addr; break;
                    case 4: esp = addr; break;
                    case 5: ebp = addr; break;
                    case 6: esi = addr; break;
                    case 7: edi = addr; break;
                }
                Logger::Log(LogLevel::INFO, "LEA reg" + std::to_string(reg) + ", [EBP + " + std::to_string(disp) + "]");
            }
            break;
        }
        case 0xA1: { // MOV EAX, [mem]
            if (instr_size + 3 < mem->size) {
                uint32_t addr = *reinterpret_cast<uint32_t*>(code + 1);
                if (addr < mem->size) {
                    eax = mem->read(addr, 4);
                    Logger::Log(LogLevel::INFO, "MOV EAX, [0x" + std::to_string(addr) + "]");
                }
                instr_size = 5;
            }
            break;
        }
        case 0xC3: { // RET
            uint32_t return_addr = mem->pop();
            jump_offset = return_addr - (mem->rip + 1);
            esp = mem->stack_pointer;
            Logger::Log(LogLevel::INFO, "RET to 0x" + std::to_string(return_addr));
            instr_size = 1;
            break;
        }
        case 0xE8: { // CALL rel32
            if (instr_size + 3 < mem->size) {
                int32_t rel32 = *reinterpret_cast<int32_t*>(code + 1);
                mem->push(static_cast<uint32_t>(mem->rip + 5));
                jump_offset = rel32;
                Logger::Log(LogLevel::INFO, "CALL rel32, offset = " + std::to_string(rel32));
                instr_size = 5;
            }
            break;
        }
        case 0xEB: { // JMP rel8
            if (instr_size < mem->size) {
                int8_t rel8 = static_cast<int8_t>(code[1]);
                jump_offset = rel8;
                Logger::Log(LogLevel::INFO, "JMP rel8, offset = " + std::to_string(rel8));
                instr_size = 2;
            }
            break;
        }
        case 0xF8: { // CLC
            carry_flag = false;
            Logger::Log(LogLevel::INFO, "CLC");
            break;
        }
        case 0xFC: { // CLD
            direction_flag = false;
            Logger::Log(LogLevel::INFO, "CLD");
            break;
        }
        case 0xFF: { // CALL/JMP/PUSH indireto
            if (instr_size < mem->size && modrm) {
                if (reg == 6) { // PUSH [mem]
                    uint32_t addr = (mod == 0x0 && rm == 0x5) ? *reinterpret_cast<uint32_t*>(code + 2) :
                                    (mod == 0x2 && rm == 0x5) ? ebp + disp : 0;
                    if (addr >= mem->image_base && addr < mem->image_base + mem->size) {
                        uint32_t value = mem->read(addr, 4);
                        mem->push(value);
                        esp = mem->stack_pointer;
                        Logger::Log(LogLevel::INFO, "PUSH [0x" + std::to_string(addr) + "]");
                        instr_size = (mod == 0x0) ? 6 : 6;
                    } else {
                        Logger::Log(LogLevel::ERROR, "Endereço inválido para PUSH: 0x" + std::to_string(addr));
                        instr_size = (mod == 0x0) ? 6 : 6;
                    }
                }
            }
            break;
        }
        default:
            Logger::Log(LogLevel::ERROR, "Instrução desconhecida: 0x" + ss.str());
            break;
    }
}

std::vector<uint8_t> Emulator::translateToARM64(uint8_t* code, uint32_t& instr_size, int64_t& jump_offset) {
    std::vector<uint8_t> arm64_code;
    uint8_t opcode = code[0];
    jump_offset = 0;
    instr_size = 1;

    uint8_t modrm = (instr_size < mem->size) ? code[1] : 0;
    uint8_t mod = (modrm >> 6) & 0x3;
    uint8_t reg = (modrm >> 3) & 0x7;
    uint8_t rm = modrm & 0x7;

    std::stringstream ss;
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(opcode);

    switch (opcode) {
        case 0x00: { // ADD [EAX], AL
            Logger::Log(LogLevel::INFO, "DynaRec: ADD [EAX], AL");
            uint32_t ldrb = 0x39400001; // LDRB W1, [X0]
            uint32_t add = 0x0B010021;  // ADD W1, W1, W0
            uint32_t strb = 0x39000001; // STRB W1, [X0]
            arm64_code.insert(arm64_code.end(), {ARM64(ldrb), ARM64(add), ARM64(strb)});
            break;
        }
        case 0x08: { // OR [mem], reg
            if (mod == 0x0 && rm == 0x4 && instr_size + 1 < mem->size) {
                uint8_t sib = code[2];
                if ((sib & 0x7) == 0x4 && (sib >> 3 & 0x7) == 0x1 && (sib >> 6 & 0x3) == 0x3) {
                    Logger::Log(LogLevel::INFO, "DynaRec: OR [EAX + ECX*8], reg" + std::to_string(reg));
                    uint32_t ldrb = 0x38616801; // LDRB W1, [X0, X1, LSL #3]
                    uint32_t orr = 0x2A000021 | (reg << 16); // ORR W1, W1, Wreg
                    uint32_t strb = 0x38216801; // STRB W1, [X0, X1, LSL #3]
                    arm64_code.insert(arm64_code.end(), {ARM64(ldrb), ARM64(orr), ARM64(strb)});
                    instr_size = 3;
                }
            }
            break;
        }
        case 0x15: { // ADC EAX, imm32
            uint32_t imm32 = *reinterpret_cast<uint32_t*>(code + 1);
            Logger::Log(LogLevel::INFO, "DynaRec: ADC EAX, " + std::to_string(imm32));
            uint32_t add = 0x91000000 | ((imm32 & 0xFFF) << 10); // ADD X0, X0, #imm32
            uint32_t adc = 0x9A010000; // ADC X0, X0, X1 (carry em X1)
            arm64_code.insert(arm64_code.end(), {ARM64(add), ARM64(adc)});
            instr_size = 5;
            break;
        }
        case 0x31: { // XOR reg, reg
            if (mod == 0x3) {
                Logger::Log(LogLevel::INFO, "DynaRec: XOR reg" + std::to_string(rm) + ", reg" + std::to_string(reg));
                uint32_t eor = 0x4A000000 | (rm << 0) | (reg << 16) | (rm << 5); // EOR Xrm, Xrm, Xreg
                arm64_code.insert(arm64_code.end(), {ARM64(eor)});
                instr_size = 2;
            }
            break;
        }
        case 0x33: { // XOR reg, [mem]
            if (mod == 0x2 && rm == 0x5 && instr_size + 4 < mem->size) {
                int32_t disp = *reinterpret_cast<int32_t*>(code + 2);
                Logger::Log(LogLevel::INFO, "DynaRec: XOR reg" + std::to_string(reg) + ", [EBP + " + std::to_string(disp) + "]");
                uint32_t ldr = 0xB9400000 | (reg << 0) | (5 << 5) | ((disp & 0xFFF) << 10); // LDR Wreg, [X5, #disp]
                uint32_t eor = 0x4A000000 | (reg << 0) | (reg << 5); // EOR Wreg, Wreg, Wreg
                arm64_code.insert(arm64_code.end(), {ARM64(ldr), ARM64(eor)});
                instr_size = 6;
            }
            break;
        }
        case 0x40: { // INC EAX
            Logger::Log(LogLevel::INFO, "DynaRec: INC EAX");
            uint32_t add = 0x91000400; // ADD X0, X0, #1
            arm64_code.insert(arm64_code.end(), {ARM64(add)});
            break;
        }
        case 0x45: { // INC EBP
            Logger::Log(LogLevel::INFO, "DynaRec: INC EBP");
            uint32_t add = 0x910004A5; // ADD X5, X5, #1
            arm64_code.insert(arm64_code.end(), {ARM64(add)});
            break;
        }
        case 0x4A: { // DEC EDX
            Logger::Log(LogLevel::INFO, "DynaRec: DEC EDX");
            uint32_t sub = 0xD1000422; // SUB X2, X2, #1
            arm64_code.insert(arm64_code.end(), {ARM64(sub)});
            break;
        }
        case 0x4E: { // DEC ESI
            Logger::Log(LogLevel::INFO, "DynaRec: DEC ESI");
            uint32_t sub = 0xD10004C6; // SUB X6, X6, #1
            arm64_code.insert(arm64_code.end(), {ARM64(sub)});
            break;
        }
        case 0x50: { // PUSH EAX
            Logger::Log(LogLevel::INFO, "DynaRec: PUSH EAX");
            uint32_t str = 0xF81F0FE0; // STR X0, [SP, #-16]!
            arm64_code.insert(arm64_code.end(), {ARM64(str)});
            break;
        }
        case 0x51: { // PUSH ECX
            Logger::Log(LogLevel::INFO, "DynaRec: PUSH ECX");
            uint32_t str = 0xF81F0FE1; // STR X1, [SP, #-16]!
            arm64_code.insert(arm64_code.end(), {ARM64(str)});
            break;
        }
        case 0x55: { // PUSH EBP
            Logger::Log(LogLevel::INFO, "DynaRec: PUSH EBP");
            uint32_t str = 0xF81F0FE5; // STR X5, [SP, #-16]!
            arm64_code.insert(arm64_code.end(), {ARM64(str)});
            break;
        }
        case 0x56: { // PUSH ESI
            Logger::Log(LogLevel::INFO, "DynaRec: PUSH ESI");
            uint32_t str = 0xF81F0FE6; // STR X6, [SP, #-16]!
            arm64_code.insert(arm64_code.end(), {ARM64(str)});
            break;
        }
        case 0x57: { // PUSH EDI
            Logger::Log(LogLevel::INFO, "DynaRec: PUSH EDI");
            uint32_t str = 0xF81F0FE7; // STR X7, [SP, #-16]!
            arm64_code.insert(arm64_code.end(), {ARM64(str)});
            break;
        }
        case 0x5D: { // POP EBP
            Logger::Log(LogLevel::INFO, "DynaRec: POP EBP");
            uint32_t ldr = 0xF84003E5; // LDR X5, [SP], #16
            arm64_code.insert(arm64_code.end(), {ARM64(ldr)});
            break;
        }
        case 0x5E: { // POP ESI
            Logger::Log(LogLevel::INFO, "DynaRec: POP ESI");
            uint32_t ldr = 0xF84003E6; // LDR X6, [SP], #16
            arm64_code.insert(arm64_code.end(), {ARM64(ldr)});
            break;
        }
        case 0x5F: { // POP EDI
            Logger::Log(LogLevel::INFO, "DynaRec: POP EDI");
            uint32_t ldr = 0xF84003E7; // LDR X7, [SP], #16
            arm64_code.insert(arm64_code.end(), {ARM64(ldr)});
            break;
        }
        case 0xFA: { // CLI
            Logger::Log(LogLevel::INFO, "DynaRec: CLI");
            uint32_t mov = 0xD2800003; // MOV X3, #0 (interrupt_flag)
            arm64_code.insert(arm64_code.end(), {ARM64(mov)});
            break;
        }
        case 0x74: { // JE rel8
            int8_t rel8 = static_cast<int8_t>(code[1]);
            Logger::Log(LogLevel::INFO, "DynaRec: JE rel8, offset = " + std::to_string(rel8));
            uint32_t cbz = 0xB4000000 | ((rel8 >> 2) & 0x7FFFF); // CBZ X0, #offset
            arm64_code.insert(arm64_code.end(), {ARM64(cbz)});
            jump_offset = rel8;
            instr_size = 2;
            break;
        }
        case 0x75: { // JNZ rel8
            int8_t rel8 = static_cast<int8_t>(code[1]);
            Logger::Log(LogLevel::INFO, "DynaRec: JNZ rel8, offset = " + std::to_string(rel8));
            uint32_t cbnz = 0xB5000000 | ((rel8 >> 2) & 0x7FFFF); // CBNZ X0, #offset
            arm64_code.insert(arm64_code.end(), {ARM64(cbnz)});
            jump_offset = rel8;
            instr_size = 2;
            break;
        }
        case 0x80: { // CMP [mem], imm8
            if (mod == 0x0 && rm == 0x0 && instr_size + 2 < mem->size) {
                int8_t disp8 = static_cast<int8_t>(code[2]);
                uint8_t imm8 = code[3];
                Logger::Log(LogLevel::INFO, "DynaRec: CMP [EAX + " + std::to_string(disp8) + "], " + std::to_string(imm8));
                uint32_t ldrb = 0x39400001 | ((disp8 & 0xFF) << 12); // LDRB W1, [X0, #disp]
                uint32_t cmp = 0x7100001F | (imm8 << 10); // CMP W1, #imm8
                arm64_code.insert(arm64_code.end(), {ARM64(ldrb), ARM64(cmp)});
                instr_size = 4;
            }
            break;
        }
        case 0x83: { // CMP reg, imm8
            if (mod == 0x3 && instr_size + 1 < mem->size) {
                int8_t imm8 = static_cast<int8_t>(code[2]);
                if (reg == 7) {
                    Logger::Log(LogLevel::INFO, "DynaRec: CMP reg" + std::to_string(rm) + ", " + std::to_string(imm8));
                    uint32_t cmp = 0xF1000000 | (rm << 5) | ((imm8 & 0xFFF) << 10); // CMP Xrm, #imm8
                    arm64_code.insert(arm64_code.end(), {ARM64(cmp)});
                    instr_size = 3;
                }
            }
            break;
        }
        case 0x85: { // TEST reg, reg
            if (mod == 0x3) {
                Logger::Log(LogLevel::INFO, "DynaRec: TEST reg" + std::to_string(rm) + ", reg" + std::to_string(reg));
                uint32_t tst = 0xEA000000 | (rm << 0) | (reg << 5); // TST Xrm, Xreg
                arm64_code.insert(arm64_code.end(), {ARM64(tst)});
                instr_size = 2;
            }
            break;
        }
        case 0x89: { // MOV reg, reg
            if (mod == 0x3) {
                Logger::Log(LogLevel::INFO, "DynaRec: MOV reg" + std::to_string(rm) + ", reg" + std::to_string(reg));
                uint32_t mov = 0xAA0003E0 | (rm << 0) | (reg << 16); // MOV Xrm, Xreg
                arm64_code.insert(arm64_code.end(), {ARM64(mov)});
                instr_size = 2;
            }
            break;
        }
        case 0x8B: { // MOV reg, [mem]
            if (mod == 0x2 && rm == 0x5 && instr_size + 4 < mem->size) {
                int32_t disp = *reinterpret_cast<int32_t*>(code + 2);
                Logger::Log(LogLevel::INFO, "DynaRec: MOV reg" + std::to_string(reg) + ", [EBP + " + std::to_string(disp) + "]");
                uint32_t ldr = 0xB9400000 | (reg << 0) | (5 << 5) | ((disp & 0xFFF) << 10); // LDR Wreg, [X5, #disp]
                arm64_code.insert(arm64_code.end(), {ARM64(ldr)});
                instr_size = 6;
            }
            break;
        }
        case 0x8D: { // LEA reg, [mem]
            if (mod == 0x2 && rm == 0x5 && instr_size + 4 < mem->size) {
                int32_t disp = *reinterpret_cast<int32_t*>(code + 2);
                Logger::Log(LogLevel::INFO, "DynaRec: LEA reg" + std::to_string(reg) + ", [EBP + " + std::to_string(disp) + "]");
                uint32_t add = 0x91000000 | (reg << 0) | (5 << 5) | ((disp & 0xFFF) << 10); // ADD Xreg, X5, #disp
                arm64_code.insert(arm64_code.end(), {ARM64(add)});
                instr_size = 6;
            }
            break;
        }
        case 0xA1: { // MOV EAX, [mem]
            if (instr_size + 3 < mem->size) {
                uint32_t addr = *reinterpret_cast<uint32_t*>(code + 1);
                Logger::Log(LogLevel::INFO, "DynaRec: MOV EAX, [0x" + std::to_string(addr) + "]");
                uint32_t ldr = 0xF9400000 | ((addr & 0xFFF) << 10); // LDR X0, [X0, #addr]
                arm64_code.insert(arm64_code.end(), {ARM64(ldr)});
                instr_size = 5;
            }
            break;
        }
         case 0xC3: { // RET
            Logger::Log(LogLevel::INFO, "DynaRec: RET");
            uint32_t ldr = 0xF94003E0; // LDR X0, [SP], #16
            uint32_t ret = 0xD65F0000; // RET X0
            arm64_code.insert(arm64_code.end(), {ARM64(ldr), ARM64(ret)});
            jump_offset = -1;
            break;
        }
	case 0x3B: { // CMP reg, reg
            if (mod == 0x3) {
                Logger::Log(LogLevel::INFO, "DynaRec: CMP reg" + std::to_string(rm) + ", reg" + std::to_string(reg));
                uint32_t cmp = 0xEB000000 | (rm << 0) | (reg << 16); // CMP Xrm, Xreg
                arm64_code.insert(arm64_code.end(), {ARM64(cmp)});
                instr_size = 2;
            }
            break;
        }
	case 0x4D: { // DEC EBP
            Logger::Log(LogLevel::INFO, "DynaRec: DEC EBP");
            uint32_t sub = 0xD10004A5; // SUB X5, X5, #1
            arm64_code.insert(arm64_code.end(), {ARM64(sub)});
            break;
        }
        case 0xBB: { // MOV EBX, imm32
            if (instr_size + 4 < mem->size) {
                uint32_t imm32 = *reinterpret_cast<uint32_t*>(code + 1);
                Logger::Log(LogLevel::INFO, "DynaRec: MOV EBX, " + std::to_string(imm32));
                uint32_t mov = 0xD2800003 | ((imm32 & 0xFFFF) << 5); // MOV X3, #imm32 (parte baixa)
                arm64_code.insert(arm64_code.end(), {ARM64(mov)});
                if (imm32 > 0xFFFF) {
                    uint32_t movk = 0xF2800003 | (((imm32 >> 16) & 0xFFFF) << 5); // MOVK X3, #imm32>>16, LSL #16
                    arm64_code.insert(arm64_code.end(), {ARM64(movk)});
                }
                instr_size = 5;
            }
            break;
        }
        case 0xBF: { // MOV EDI, imm32
            if (instr_size + 4 < mem->size) {
                uint32_t imm32 = *reinterpret_cast<uint32_t*>(code + 1);
                Logger::Log(LogLevel::INFO, "DynaRec: MOV EDI, " + std::to_string(imm32));
                uint32_t mov = 0xD2800007 | ((imm32 & 0xFFFF) << 5); // MOV X7, #imm32 (parte baixa)
                arm64_code.insert(arm64_code.end(), {ARM64(mov)});
                if (imm32 > 0xFFFF) {
                    uint32_t movk = 0xF2800007 | (((imm32 >> 16) & 0xFFFF) << 5); // MOVK X7, #imm32>>16, LSL #16
                    arm64_code.insert(arm64_code.end(), {ARM64(movk)});
                }
                instr_size = 5;
            }
            break;
        }
        case 0xE8: { // CALL rel32
            int32_t rel32 = *reinterpret_cast<int32_t*>(code + 1);
            Logger::Log(LogLevel::INFO, "DynaRec: CALL rel32, offset = " + std::to_string(rel32));
            uint32_t bl = 0x94000000 | ((rel32 >> 2) & 0x03FFFFFF); // BL
            arm64_code.insert(arm64_code.end(), {ARM64(bl)});
            jump_offset = rel32;
            instr_size = 5;
            break;
        }
        case 0xEB: { // JMP rel8
            int8_t rel8 = static_cast<int8_t>(code[1]);
            Logger::Log(LogLevel::INFO, "DynaRec: JMP rel8, offset = " + std::to_string(rel8));
            uint32_t b = 0x14000000 | (rel8 & 0x03FFFFFF); // B
            arm64_code.insert(arm64_code.end(), {ARM64(b)});
            jump_offset = rel8;
            instr_size = 2;
            break;
        }
        case 0xF8: { // CLC
            Logger::Log(LogLevel::INFO, "DynaRec: CLC");
            uint32_t mov = 0xD2800001; // MOV X1, #0 (carry_flag)
            arm64_code.insert(arm64_code.end(), {ARM64(mov)});
            break;
        }
        case 0xFC: { // CLD
            Logger::Log(LogLevel::INFO, "DynaRec: CLD");
            uint32_t mov = 0xD2800002; // MOV X2, #0 (direction_flag)
            arm64_code.insert(arm64_code.end(), {ARM64(mov)});
            break;
        }
        case 0xFF: { // PUSH [mem]
            if (mod == 0x0 && rm == 0x5 && instr_size + 4 < mem->size) {
                uint32_t addr = *reinterpret_cast<uint32_t*>(code + 2);
            if (addr >= mem->image_base && addr < mem->image_base + mem->size) {
                Logger::Log(LogLevel::INFO, "DynaRec: PUSH [0x" + std::to_string(addr) + "]");
                uint32_t ldr = 0xF9400000 | ((addr & 0xFFF) << 10); // LDR X0, [X0, #addr]
                uint32_t str = 0xF81F0FE0; // STR X0, [SP, #-16]!
                arm64_code.insert(arm64_code.end(), {ARM64(ldr), ARM64(str)});
                instr_size = 6;
            } else {
                    Logger::Log(LogLevel::ERROR, "Endereço inválido para PUSH: 0x" + std::to_string(addr));
                    instr_size = 6;
               }
            }
            break;
        }
	case 0xBE: { // MOV ESI, imm32
            if (instr_size + 4 < mem->size) {
                uint32_t imm32 = *reinterpret_cast<uint32_t*>(code + 1);
                Logger::Log(LogLevel::INFO, "DynaRec: MOV ESI, " + std::to_string(imm32));
                uint32_t mov = 0xD2800006 | ((imm32 & 0xFFFF) << 5); // MOV X6, #imm32 (parte baixa)
                arm64_code.insert(arm64_code.end(), {ARM64(mov)});
                if (imm32 > 0xFFFF) {
                    uint32_t movk = 0xF2800006 | (((imm32 >> 16) & 0xFFFF) << 5); // MOVK X6, #imm32>>16, LSL #16
                    arm64_code.insert(arm64_code.end(), {ARM64(movk)});
                }
                instr_size = 5;
            }
            break;
        }

        default:
            Logger::Log(LogLevel::DEBUG, "Opcode não suportado no DynaRec: 0x" + ss.str());
            return {};
    }
    return arm64_code;
}

// --- Execution ---
void Emulator::run() {
    const uint32_t MAX_ITERATIONS = 5000;
    uint32_t iterations = 0;

    while (is_running && iterations++ < MAX_ITERATIONS) {
        if (mem->rip - mem->image_base >= mem->size) {
            Logger::Log(LogLevel::ERROR, "RIP fora dos limites: 0x" + std::to_string(mem->rip));
            is_running = false;
            break;
        }

        uint8_t* code = mem->getCodeAt(mem->rip);
        uint32_t instr_size = 1;
        int64_t jump_offset = 0;

        auto it = block_cache.find(mem->rip);
        if (it != block_cache.end()) {
            instr_size = it->second.second;
            jump_offset = it->second.first;
            Logger::Log(LogLevel::DEBUG, "Executando bloco em cache em RIP 0x" + std::to_string(mem->rip));
        } else {
            std::vector<uint8_t> arm64_code = translateToARM64(code, instr_size, jump_offset);
            if (arm64_code.empty()) {
                executeInstruction(code[0], code, instr_size, jump_offset);
            }
            block_cache[mem->rip] = std::make_pair(jump_offset, instr_size);
            Logger::Log(LogLevel::DEBUG, "Bloco recompilado em RIP 0x" + std::to_string(mem->rip) + " com tamanho x86 " + std::to_string(instr_size));
        }

        mem->rip += instr_size;
        if (jump_offset != 0) {
            if (jump_offset == -1) { // RET
                uint32_t return_addr = mem->pop();
                if (return_addr == 0xFFFFFFFF) {
                    Logger::Log(LogLevel::INFO, "Retorno fictício detectado, encerrando execução.");
                    is_running = false;
                    break;
                }
                mem->rip = return_addr;
            } else {
                mem->rip += jump_offset;
            }
            if (mem->rip < mem->image_base || mem->rip - mem->image_base >= mem->size) {
                Logger::Log(LogLevel::ERROR, "Salto inválido para RIP: 0x" + std::to_string(mem->rip));
                is_running = false;
                break;
            }
        }
        Logger::Log(LogLevel::DEBUG, "RIP atualizado para: 0x" + std::to_string(mem->rip));
    }

    if (iterations >= MAX_ITERATIONS) {
        Logger::Log(LogLevel::INFO, "Limite de iterações atingido: " + std::to_string(MAX_ITERATIONS));
    }
    Logger::Log(LogLevel::INFO, "Execução finalizada.");
}
