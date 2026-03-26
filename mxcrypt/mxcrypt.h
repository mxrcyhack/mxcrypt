#pragma once

/*
  mxcrypt  -  Cifratura di stringhe a compile-time  |  C++17+  |  Windows Usermode

  Utilizzo:
      auto s = mxcrypt("stringa segreta");   // cifrata a compile-time
      printf(s);                        // decifratura automatica all'uso
      s.encrypt();                          // ri-cifra dopo l'uso
      s.clear();                // cancellazione sicura esplicita
      // }  il distruttore cancella automaticamente all'uscita dallo scope

  Stringhe wide (Unicode):
      auto ws = mxcrypt(L"stringa unicode");
      wprintf(ws);

  ogni stringa ottiene un seed univoco da: TIME + DATE + __LINE__ + __COUNTER__
  due stringhe identiche in posizioni diverse nel sorgente = ciphertext diversi.
*/

#include <cstdint>
#include <type_traits>

#ifdef _MSC_VER
#  define MX_INLINE __forceinline
#else
#  define MX_INLINE __attribute__((always_inline)) inline
#endif

#define MX_SEED_TIME \
    ( ((uint64_t)(uint8_t)__TIME__[0] << 40) \
    | ((uint64_t)(uint8_t)__TIME__[1] << 32) \
    | ((uint64_t)(uint8_t)__TIME__[3] << 24) \
    | ((uint64_t)(uint8_t)__TIME__[4] << 16) \
    | ((uint64_t)(uint8_t)__TIME__[6] <<  8) \
    | ((uint64_t)(uint8_t)__TIME__[7]      ) )

#define MX_SEED_DATE \
    ( ((uint64_t)(uint8_t)__DATE__[0] << 48) \
    | ((uint64_t)(uint8_t)__DATE__[1] << 40) \
    | ((uint64_t)(uint8_t)__DATE__[2] << 32) \
    | ((uint64_t)(uint8_t)__DATE__[4] << 24) \
    | ((uint64_t)(uint8_t)__DATE__[5] << 16) \
    | ((uint64_t)(uint8_t)__DATE__[7] <<  8) \
    | ((uint64_t)(uint8_t)__DATE__[10]     ) )

namespace mx {

    template<class T>
    using clean_t = std::remove_const_t<std::remove_reference_t<T>>;

    constexpr uint64_t cx_xorshift64(uint64_t s) noexcept {
        s ^= s << 13;
        s ^= s >>  7;
        s ^= s << 17;
        return s;
    }

    constexpr uint64_t cx_mix_seed(uint64_t tv, uint64_t dv,
                                    uint64_t ln, uint64_t ctr) noexcept {
        uint64_t s = tv  * 6364136223846793005ULL + 1442695040888963407ULL;
        s ^= dv  * 2246822519ULL;
        s ^= ln  * 2654435761ULL;
        s += ctr *  374761393ULL;
        s ^= s >> 33;  s *= 0xff51afd7ed558ccdULL;
        s ^= s >> 33;  s *= 0xc4ceb9fe1a85ec53ULL;
        s ^= s >> 33;
        return s ? s : 0xDEADBEEFCAFEBABEULL;
    }

    constexpr uint8_t cx_key_at(uint64_t seed, int i) noexcept {
        uint64_t s = seed;
        for (int j = 0; j <= i; ++j)
            s = cx_xorshift64(s);
        uint8_t k = static_cast<uint8_t>(s) ^ static_cast<uint8_t>(s >> 8);
        return k ? k : (static_cast<uint8_t>(s >> 16) | 0x01u);
    }

    template<int N, uint64_t Seed, typename T>
    struct CrypterStorage {
        T data[N]{};

        MX_INLINE constexpr explicit CrypterStorage(const T* src) noexcept {
            for (int i = 0; i < N; ++i)
                data[i] = src[i] ^ static_cast<T>(cx_key_at(Seed, i));
        }
    };

    template<int N, uint64_t Seed, typename T>
    class Crypter {
        static_assert(N > 0, "mxcrypt: la stringa non puo' essere vuota");

    public:
        MX_INLINE explicit Crypter(const CrypterStorage<N, Seed, T>& s) noexcept {
            for (int i = 0; i < N; ++i)
                _storage[i] = s.data[i];
        }

        Crypter(const Crypter&) noexcept = default;

        Crypter(Crypter&&)                 = delete;
        Crypter& operator=(const Crypter&) = delete;
        Crypter& operator=(Crypter&&)      = delete;

        ~Crypter() noexcept { clear(); }

        MX_INLINE T* decrypt() noexcept {
            if (isEncrypted())
                for (int i = 0; i < N; ++i)
                    _storage[i] ^= static_cast<T>(cx_key_at(Seed, i));
            return _storage;
        }

        MX_INLINE T* encrypt() noexcept {
            if (!isEncrypted())
                for (int i = 0; i < N; ++i)
                    _storage[i] ^= static_cast<T>(cx_key_at(Seed, i));
            return _storage;
        }

        MX_INLINE void clear() noexcept {
            volatile T* p = _storage;
            for (int i = 0; i < N; ++i)
                p[i] = T(0);
        }

        MX_INLINE bool isEncrypted() const noexcept {
            return _storage[N - 1] != T(0);
        }

        MX_INLINE operator T*() noexcept { return decrypt(); }

        MX_INLINE T*  get()  noexcept       { return decrypt(); }
        MX_INLINE int size() const noexcept { return N; }

    private:
        T _storage[N]{};
    };

} // namespace mx

#define mxcrypt(str) mxcrypt_key(str, __LINE__, __COUNTER__)

#define mxcrypt_key(str, ln, ctr)                                               \
    ([]() noexcept {                                                             \
        using _T = mx::clean_t<decltype(str[0])>;                               \
        constexpr static mx::CrypterStorage<                                    \
            (int)(sizeof(str) / sizeof(str[0])),                                \
            mx::cx_mix_seed(MX_SEED_TIME, MX_SEED_DATE,                         \
                            (uint64_t)(ln), (uint64_t)(ctr)),                   \
            _T                                                                   \
        > _s((const _T*)(str));                                                 \
        return mx::Crypter<                                                      \
            (int)(sizeof(str) / sizeof(str[0])),                                \
            mx::cx_mix_seed(MX_SEED_TIME, MX_SEED_DATE,                         \
                            (uint64_t)(ln), (uint64_t)(ctr)),                   \
            _T                                                                   \
        >(_s);                                                                   \
    }())


/*

    MIT License
    
    Copyright(c) 2026 mxrcy
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files(the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions :
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

*/