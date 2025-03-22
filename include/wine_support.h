#ifndef WINE_SUPPORT_H
#define WINE_SUPPORT_H

class WineSupport {
public:
    WineSupport();
    void InitializeWine();
    void RunWineApp(const char* path);
};

#endif
