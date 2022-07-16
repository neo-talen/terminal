// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once

#include "bit.h"

#if defined(_M_X64) && !defined(_M_ARM64EC)
#define TIL_HASH_X64
#elif defined(_M_ARM64) || defined(_M_ARM64EC)
#define TIL_HASH_ARM64
#else
#define TIL_HASH_FALLBACK
#endif

namespace til
{
    namespace details
    {
#if defined(TIL_HASH_FALLBACK)

#if defined(_WIN64)
        inline constexpr size_t FNV1a_offset = 14695981039346656037ULL;
        inline constexpr size_t FNV1a_prime = 1099511628211ULL;
#else
        inline constexpr size_t FNV1a_offset = 2166136261U;
        inline constexpr size_t FNV1a_prime = 16777619U;
#endif

        inline constexpr size_t hash_seed = FNV1a_offset;

        // FNV1a
        inline size_t hash(const void* data, size_t len, size_t seed) noexcept
        {
            auto p = static_cast<const uint8_t*>(data);
            for (size_t i = 0; i < count; ++i)
            {
                seed ^= static_cast<size_t>(p[i]);
                seed *= FNV1a_prime;
            }
            return seed;
        }

#else // defined(TIL_HASH_FALLBACK)

        inline uint64_t _wymix(uint64_t lhs, uint64_t rhs) noexcept
        {
#if defined(TIL_HASH_X64)
            uint64_t hi;
            uint64_t lo = _umul128(lhs, rhs, &hi);
#elif defined(TIL_HASH_ARM64)
            const auto lo = lhs * rhs;
            const auto hi = __umulh(lhs, rhs);
#endif
            return lo ^ hi;
        }

        inline uint64_t _wyr1(const uint8_t* p) noexcept
        {
            return static_cast<uint64_t>(*p);
        }

        inline uint64_t _wyr4(const uint8_t* p) noexcept
        {
            uint32_t v;
            memcpy(&v, p, 4);
            return v;
        }

        inline uint64_t _wyr8(const uint8_t* p) noexcept
        {
            uint64_t v;
            memcpy(&v, p, 8);
            return v;
        }

        inline constexpr size_t hash_seed = 0;

        // wyhash
        inline uint64_t hash(const void* data, uint64_t len, uint64_t seed) noexcept
        {
            static constexpr auto s0 = UINT64_C(0xa0761d6478bd642f);
            static constexpr auto s1 = UINT64_C(0xe7037ed1a0b428db);
            static constexpr auto s2 = UINT64_C(0x8ebc6af09c88c6e3);
            static constexpr auto s3 = UINT64_C(0x589965cc75374cc3);

            auto p = static_cast<const uint8_t*>(data);
            seed ^= s0;
            uint64_t a, b;

            if (len <= 16)
            {
                if (len >= 4)
                {
                    a = (_wyr4(p) << 32) | _wyr4(p + ((len >> 3) << 2));
                    b = (_wyr4(p + len - 4) << 32) | _wyr4(p + len - 4 - ((len >> 3) << 2));
                }
                else if (len > 0)
                {
                    a = (_wyr1(p) << 16) | (_wyr1(p + (len >> 1)) << 8) | _wyr1(p + len - 1);
                    b = 0;
                }
                else
                {
                    a = b = 0;
                }
            }
            else
            {
                uint64_t i = len;
                if (i > 48)
                {
                    auto seed1 = seed;
                    auto seed2 = seed;
                    do
                    {
                        seed = _wymix(_wyr8(p) ^ s1, _wyr8(p + 8) ^ seed);
                        seed1 = _wymix(_wyr8(p + 16) ^ s2, _wyr8(p + 24) ^ seed1);
                        seed2 = _wymix(_wyr8(p + 32) ^ s3, _wyr8(p + 40) ^ seed2);
                        p += 48;
                        i -= 48;
                    } while (i > 48);
                    seed ^= seed1 ^ seed2;
                }
                while (i > 16)
                {
                    seed = _wymix(_wyr8(p) ^ s1, _wyr8(p + 8) ^ seed);
                    i -= 16;
                    p += 16;
                }
                a = _wyr8(p + i - 16);
                b = _wyr8(p + i - 8);
            }
            return _wymix(s1 ^ len, _wymix(a ^ s1, b ^ seed));
        }

#endif // defined(TIL_HASH_FALLBACK)
    }

    template<typename T>
    struct hash_trait;

    struct hasher
    {
        constexpr hasher() = default;
        explicit constexpr hasher(size_t state) noexcept :
            _hash{ state } {}

        template<typename T>
        void write(const T& v) noexcept
        {
            hash_trait<T>{}(*this, v);
        }

        template<typename T, typename = std::enable_if_t<std::has_unique_object_representations_v<T>>>
        void write(const T* data, size_t count) noexcept
        {
#pragma warning(suppress : 26490) // Don't use reinterpret_cast (type.1).
            write(static_cast<const void*>(data), sizeof(T) * count);
        }

#pragma warning(suppress : 26429) // Symbol 'data' is never tested for nullness, it can be marked as not_null (f.23).
        void write(const void* data, size_t len) noexcept
        {
            _hash = details::hash(data, len, _hash);
        }

        constexpr size_t finalize() const noexcept
        {
            return _hash;
        }

    private:
        size_t _hash = details::hash_seed;
    };

    namespace details
    {
        template<typename T, bool enable>
        struct conditionally_enabled_hash_trait
        {
            void operator()(hasher& h, const T& v) const noexcept
            {
                h.write(static_cast<const void*>(&v), sizeof(T));
            }
        };

        template<typename T>
        struct conditionally_enabled_hash_trait<T, false>
        {
            conditionally_enabled_hash_trait() = delete;
            conditionally_enabled_hash_trait(const conditionally_enabled_hash_trait&) = delete;
            conditionally_enabled_hash_trait(conditionally_enabled_hash_trait&&) = delete;
            conditionally_enabled_hash_trait& operator=(const conditionally_enabled_hash_trait&) = delete;
            conditionally_enabled_hash_trait& operator=(conditionally_enabled_hash_trait&&) = delete;
        };
    }

    template<typename T>
    struct hash_trait : details::conditionally_enabled_hash_trait<T, std::has_unique_object_representations_v<T>>
    {
    };

    template<>
    struct hash_trait<float>
    {
        void operator()(hasher& h, float v) const noexcept
        {
            v = v == 0.0f ? 0.0f : v; // map -0 to 0
            h.write(static_cast<const void*>(&v), sizeof(v));
        }
    };

    template<>
    struct hash_trait<double>
    {
        void operator()(hasher& h, double v) const noexcept
        {
            v = v == 0.0 ? 0.0 : v; // map -0 to 0
            h.write(static_cast<const void*>(&v), sizeof(v));
        }
    };

    template<typename T, typename CharTraits, typename Allocator>
    struct hash_trait<std::basic_string<T, CharTraits, Allocator>>
    {
        void operator()(hasher& h, const std::basic_string<T, CharTraits, Allocator>& v) const noexcept
        {
            h.write(static_cast<const void*>(v.data()), sizeof(T) * v.size());
        }
    };

    template<typename T, typename CharTraits>
    struct hash_trait<std::basic_string_view<T, CharTraits>>
    {
        void operator()(hasher& h, const std::basic_string_view<T, CharTraits>& v) const noexcept
        {
            h.write(static_cast<const void*>(v.data()), sizeof(T) * v.size());
        }
    };

    template<typename T>
    inline size_t hash(const T& v) noexcept
    {
        hasher h;
        h.write(v);
        return h.finalize();
    }
    
    inline size_t hash(const void* data, size_t len) noexcept
    {
        return details::hash(data, len, details::hash_seed);
    }
}
