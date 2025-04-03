---

# Bionic64

🚀 **Bionic64** is an experimental x86/x64 emulator with dynamic ARM64 translation, designed to run Windows PE binaries on ARM64 devices like Android. It combines interpretation and JIT compilation for a balance of speed and flexibility!

---

## ❗ Requirements

- **C++17**: For modern language features.  
- **Linux-based OS**: Tested on Android/Linux with Bionic syscalls.  
- **ARM64 Hardware**: Optimized for ARM64 CPUs.
  
---

## ✨ Features

- **Dynamic JIT**: Translates x86/x64 instructions to ARM64 on-the-fly using a Just-In-Time compiler.  
- **PE Support**: Loads Windows Portable Executable (PE) files with basic section mapping.  
- **Memory Management**: Virtual memory with stack and heap allocation.  
- **Syscall Handling**: Initial support for Bionic syscalls (e.g., `write`).  
- **Opcode Translation**: Handles a small set of x86 instructions (e.g., `MOV`, `ADD`, `JMP`).  

---

## 📜 How It Works

Bionic64 emulates x86/x64 binaries in three steps:
1. **Binary Loading**: Parses PE files, maps sections into virtual memory, and sets up the stack.  
2. **Instruction Processing**: Uses a hybrid approach:  
   - **Interpreter**: Executes unknown instructions directly (slow but reliable).  
   - **JIT Compiler**: Translates known opcodes to ARM64 and caches them for speed.  
3. **Execution**: Runs the translated code or interpreted instructions, updating registers and memory dynamically.  

The emulator starts at the PE entry point and processes instructions until a return or error occurs. It’s currently limited to basic programs due to partial opcode coverage.

---

## 📊 Progress

- **Completion**: ~5-10%  
- **What’s Done**: Basic PE loading, memory management, JIT framework, and a handful of opcodes.  
- **Planned Additions**:  
  - **Wine Integration**: Enable compatibility with Wine to run Windows applications seamlessly on ARM64.  
  - **Bionic/libc Library Support**: Fully integrate with the Bionic libc library for native Android syscall handling.  
  - **ARM64EC-Inspired Native Code Execution**: Implement hybrid static and dynamic translation for native ARM64 execution, inspired by Microsoft’s ARM64EC.  
  - **Expand Opcode Table**: Increase coverage of x86/x64 instructions for broader compatibility.  
  - **FPU/SSE Support**: Add floating-point and SIMD instruction emulation for modern software.  
  - **Full Syscall Mapping**: Complete syscall support for both 32-bit and 64-bit binaries.  
- **Note**: This project is under active development and subject to changes. The current state does not represent the final product.

---

## ⭐ Join Our Community

Get support, updates, and share your ideas on our Discord server!  
👉 **[Discord](https://discord.gg/pyHvRwkJC2)**  

---

## 🛠️ Contributing

Want to help?  
- Report bugs or suggest features in the [Issues](https://github.com/Estem01/Bionic64/issues) tab.  
- Submit code improvements via [Pull Requests](https://github.com/Estem01/Bionic64/pulls).  

Check the [commits](https://github.com/Estem01/Bionic64/commits/main) for the latest progress!

---

## 📝 License

This project is licensed under the [Apache License](https://github.com/Estem01/Bionic64/blob/main/LICENSE).  

## 👥 Authors

- [Estem01](https://github.com/Estem01)  

---
