#include "wine_support.h"
#include "logger.h"
#include <iostream>

WineSupport::WineSupport() {
    Logger::Log(LogLevel::INFO, "Inicializando suporte ao Wine...");
}

void WineSupport::InitializeWine() {
    Logger::Log(LogLevel::INFO, "Configurando Wine com WOW64...");
    // TODO: Integrar com o prefixo do Wine
}

void WineSupport::RunWineApp(const char* path) {
    Logger::Log(LogLevel::INFO, std::string("Rodando aplicação Wine: ") + path);
    // Aqui chamaria o emulador para rodar o binário via Wine
}
