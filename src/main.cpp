#include "emulator.h"
#include "wine_support.h"
#include "logger.h"
#include <iostream>

int main(int argc, char* argv[]) {
    Logger::Log(LogLevel::INFO, "Iniciando Bionic64...");
    if (argc < 2) {
        Logger::Log(LogLevel::ERROR, "Uso incorreto. Sintaxe: Bionic64 <caminho_do_binario>");
        return 1;
    }

    Emulator emu(argv[1]);
    WineSupport wine;

    emu.LoadBinary(argv[1]);
    wine.InitializeWine();
    wine.RunWineApp(argv[1]);
    emu.run();

    Logger::Log(LogLevel::INFO, "Bionic64 finalizado.");
    return 0;
}
