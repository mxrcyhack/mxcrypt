#include "mxcrypt.h"
#include <cstdio>
#include <cstring>
#include <io.h>
#include <fcntl.h>

int main()
{
    {
        auto secret = mxcrypt("ciao da, mxcrypt");
        printf("%s\n", secret.get());
    }

    {
        auto url = mxcrypt("https://berlusconi.gov/api");
        printf(url);
        printf("\n");
    }

    {
        (void)_setmode(_fileno(stdout), _O_U16TEXT);
        auto wide = mxcrypt(L"Stringa unicode: \u00E9\u00E0\u00FC");
        wprintf(L"%s\n", wide.get());
        (void)_setmode(_fileno(stdout), _O_TEXT);
    }

    {
        auto key = mxcrypt("test-chiave"); 
        char buf[64];
        memcpy(buf, key.get(), key.size());
        key.encrypt();
        memset(buf, 0, sizeof(buf));
        printf("chiave di nuovo: %s\n", key.decrypt());
    }

    {
        auto a = mxcrypt("uguale");
        auto b = mxcrypt("uguale");
        printf("a: %s\n", (char*)a);
        printf("b: %s\n", (char*)b);
    }

    {
        auto s = mxcrypt_key("test chiavi manuali", 42, 7);
        printf("%s\n", (char*)s);
    }



    return 0;
}