#ifndef EMULATOR_H
#define EMULATOR_H

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include "logger.h"

class Emulator {
public:
    enum class BinaryType {
        UNKNOWN,
        PE_X86,
        PE_X64
    };

    struct PEInfo {
        uint32_t image_base;
        uint32_t entry_point;
        uint32_t image_size;
        uint32_t reloc_rva;
        uint32_t reloc_size;

        struct Section {
            uint32_t virtual_address;
            uint32_t size;
            uint32_t file_offset;
        };
        std::vector<Section> sections;
    };

    class MemoryManager {
    public:
        uint32_t size;           // Tamanho total da memória virtual
        uint8_t* virtual_memory; // Ponteiro para memória alocada
        uint64_t rip;            // Instruction Pointer ajustado com image_base
        uint32_t image_base;     // Base da imagem carregada
        uint32_t stack_base;     // Base da pilha
        uint32_t stack_pointer;  // Ponteiro atual da pilha (ESP)
        uint32_t heap_base;      // Base do heap
        uint32_t heap_pointer;   // Ponteiro atual do heap

        MemoryManager(size_t mem_size);
        ~MemoryManager();

        void mapSection(const PEInfo::Section& section, const uint8_t* data, size_t file_size);
        void write(uint32_t addr, uint32_t value, size_t bytes = 4);
        uint32_t read(uint32_t addr, size_t bytes = 4);
        void push(uint32_t value);
        uint32_t pop();
        uint32_t allocateHeap(size_t bytes);
        void initStack(uint32_t return_addr, uint32_t entry_point, uint32_t img_base);
        uint8_t* getCodeAt(uint64_t addr) const;
    };

    Emulator(const std::string& filename);
    ~Emulator();

    void LoadBinary(const char* path);
    bool DetectBinaryType(PEInfo& pe_info);
    void ApplyRelocations(PEInfo& pe_info);
    void executeInstruction(uint8_t opcode, uint8_t* code, uint32_t& instr_size, int64_t& jump_offset);
    std::vector<uint8_t> translateToARM64(uint8_t* code, uint32_t& instr_size, int64_t& jump_offset);
    void run();

private:
    void* memory;                            // Memória bruta do binário carregado
    size_t memory_size;                      // Tamanho do binário em disco
    MemoryManager* mem;                      // Gerenciador de memória virtual
    BinaryType binary_type;                  // Tipo de binário detectado
    PEInfo pe_info;                          // Informações do cabeçalho PE
    bool is_running;                         // Estado de execução
    std::map<uint64_t, std::pair<int64_t, uint32_t>> block_cache; // Cache de blocos: <RIP, <jump_offset, x86_size>>

    // Registradores
    uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi;

    // Flags
    bool carry_flag;
    bool interrupt_flag;
    bool zero_flag;
    bool direction_flag;
};

#endif // EMULATOR_H
