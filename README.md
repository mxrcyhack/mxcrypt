# mxCrypt

Libreria header-only per la cifratura di stringhe a compile-time. C++17+, Windows Usermode.

Le stringhe protette con `mxCrypt()` non sono mai presenti in chiaro nel binario. Il ciphertext XOR viene incorporato a compile-time e decifrato automaticamente a runtime solo quando viene acceduto.


# Caratteristiche

- Cifratura a compile-time, il plaintext non e' visibile nel binario ne' con scanner di stringhe
- Seed univoco per stringa derivato da `__TIME__` + `__DATE__` + `__LINE__` + `__COUNTER__`, due stringhe identiche in posizioni diverse producono ciphertext diversi
- Keystream xorshift64 con seed mixing Murmur3, imprevedibile byte per byte
- La chiave non e' mai zero, quindi il rilevamento dello stato cifrato/decifrato e' sempre affidabile
- Il distruttore fa un zero-fill volatile automaticamente all'uscita dallo scope
- Il loop volatile impedisce al compilatore di ottimizzare via l'azzeramento della memoria
- Supporto char e wchar_t
- Un solo file mxcrypt.h, nessun linking
- C++17+


# facile da usare


#include "mxcrypt.h"
#include <cstdio>

int main()
{
    auto secret = mxCrypt("stringa segreta");
    printf(secret);   // decifratura automatica
    // il distruttore azzera la memoria quando esce dallo scope
}



# qualche  esempo

Base:


auto s = mxCrypt("ciao mondo");
printf(s);           // cast implicito, decrypt automatico
printf(s.get());     // decrypt esplicito


Ri-cifratura dopo l'uso:


auto chiave = mxCrypt("chiave-super-segreta");

char buf[64];
memcpy(buf, chiave.get(), chiave.size());

chiave.encrypt();    // ri-cifra lo storage mentre lavori con buf

memset(buf, 0, sizeof(buf));

printf(chiave.decrypt()); // decifratura di nuovo quando serve
// auto-azzerato all'uscita dallo scope


Cancellazione manuale:


auto s = mxCrypt("dati sensibili");
s.clear();           // zero-fill volatile, chiamato anche dal distruttore


Stringhe wide:


auto ws = mxCrypt(L"unicode: éàü");
wprintf(ws);


Controllo stato:


auto s = mxCrypt("test");
s.isEncrypted();   // true  — appena creata
s.decrypt();
s.isEncrypted();   // false — plaintext nello storage
s.encrypt();
s.isEncrypted();   // true  — torna al ciphertext


Chiavi manuali:


auto s = mxCrypt_key("stringa", 42, 7);



# API

- decrypt() — decifratura in-place, idempotente, ritorna T*
- encrypt() — ri-cifratura in-place, idempotente, ritorna T*
- get() — alias di decrypt()
- clear() — zero-fill volatile dell'intero storage
- isEncrypted() — true se lo storage contiene il ciphertext
- size() — numero di caratteri incluso il null terminator
- operator T*() — cast implicito, chiama decrypt() automaticamente


# spiegazione

Il seed di ogni stringa e' un valore a 64-bit calcolato mescolando TIME, DATE, numero di riga e __COUNTER__ tramite un passaggio Murmur3. In questo modo due stringhe identiche scritte in punti diversi del codice producono ciphertext completamente diversi nel binario.

Il keystream viene generato avanzando un PRNG xorshift64 per ogni posizione della stringa. Il risultato e' garantito non-zero per ogni byte, il che rende affidabile la distinzione tra stato cifrato e decifrato controllando il null terminator.

La cifratura e' un semplice XOR, che e' simmetrico, quindi la stessa operazione cifra e decifra.

In C++17 una variabile constexpr static richiede un tipo senza distruttore, ma il RAII richiede un distruttore. Per risolvere il conflitto mxCrypt usa due classi: CrypterStorage e' il tipo letterale che vive nel binario come ciphertext, Crypter e' la copia di lavoro restituita all'utente con il distruttore che fa il wipe automatico.


# Ottimizzazione del compilatore

Con /O2 MSVC puo' produrre decifratura errata, e' un problema noto con constexpr static dentro lambda. Usa /O1 nelle build Release. Entrambi i progetti sono gia' configurati in questo modo.


# Struttura del progetto



 mxcrypt.h    //includila e basta



# Integrazione

Copia mxcrypt.h nel tuo progetto e includilo. Nient'altro.


#include "mxcrypt.h"


Richiede C++17 (/std:c++17) e /O1 in Release.


# Confronto con skCrypter

skCrypter usa un seed di 2 byte presi da __TIME__, quindi tutte le stringhe nella stessa compilazione hanno lo stesso seed. mxCrypt usa un seed a 64-bit che cambia per ogni stringa grazie a __LINE__ e __COUNTER__.

In skCrypter la chiave puo' essere zero in certi casi, il che rompe il rilevamento dello stato. In mxCrypt e' impossibile per costruzione.

skCrypter non ha un distruttore, quindi devi chiamare .clear() a mano. mxCrypt lo fa automaticamente.


# Licenza

MIT