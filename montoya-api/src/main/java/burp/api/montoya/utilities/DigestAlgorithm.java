/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.utilities;

/**
 * Enum of available message digest algorithms.
 */
public enum DigestAlgorithm
{
    BLAKE2B_160("BLAKE2B-160"),
    BLAKE2B_256("BLAKE2B-256"),
    BLAKE2B_384("BLAKE2B-384"),
    BLAKE2B_512("BLAKE2B-512"),
    BLAKE2S_128("BLAKE2S-128"),
    BLAKE2S_160("BLAKE2S-160"),
    BLAKE2S_224("BLAKE2S-224"),
    BLAKE2S_256("BLAKE2S-256"),
    BLAKE3_256("BLAKE3-256"),
    DSTU7564_256("DSTU7564-256"),
    DSTU7564_384("DSTU7564-384"),
    DSTU7564_512("DSTU7564-512"),
    GOST3411("GOST3411"),
    GOST3411_2012_256("GOST3411-2012-256"),
    GOST3411_2012_512("GOST3411-2012-512"),
    HARAKA_256("HARAKA-256"),
    HARAKA_512("HARAKA-512"),
    KECCAK_224("KECCAK-224"),
    KECCAK_256("KECCAK-256"),
    KECCAK_288("KECCAK-288"),
    KECCAK_384("KECCAK-384"),
    KECCAK_512("KECCAK-512"),
    MD2("MD2"),
    MD4("MD4"),
    MD5("MD5"),
    PARALLEL_HASH_128_256("PARALLELHASH128-256"),
    PARALLEL_HASH_256_512("PARALLELHASH256-512"),
    RIPEMD_128("RIPEMD128"),
    RIPEMD_160("RIPEMD160"),
    RIPEMD_256("RIPEMD256"),
    RIPEMD_320("RIPEMD320"),
    SHA_1("SHA-1"),
    SHA_224("SHA-224"),
    SHA_256("SHA-256"),
    SHA_384("SHA-384"),
    SHA_512("SHA-512"),
    SHA_512_224("SHA-512/224"),
    SHA_512_256("SHA-512/256"),
    SHA3_224("SHA3-224"),
    SHA3_256("SHA3-256"),
    SHA3_384("SHA3-384"),
    SHA3_512("SHA3-512"),
    SHAKE_128_256("SHAKE128-256"),
    SHAKE_256_512("SHAKE256-512"),
    SKEIN_1024_1024("SKEIN-1024-1024"),
    SKEIN_1024_384("SKEIN-1024-384"),
    SKEIN_1024_512("SKEIN-1024-512"),
    SKEIN_256_128("SKEIN-256-128"),
    SKEIN_256_160("SKEIN-256-160"),
    SKEIN_256_224("SKEIN-256-224"),
    SKEIN_256_256("SKEIN-256-256"),
    SKEIN_512_128("SKEIN-512-128"),
    SKEIN_512_160("SKEIN-512-160"),
    SKEIN_512_224("SKEIN-512-224"),
    SKEIN_512_256("SKEIN-512-256"),
    SKEIN_512_384("SKEIN-512-384"),
    SKEIN_512_512("SKEIN-512-512"),
    SM3("SM3"),
    TIGER("TIGER"),
    TUPLEHASH_128_256("TUPLEHASH128-256"),
    TUPLEHASH_256_512("TUPLEHASH256-512"),
    WHIRLPOOL("WHIRLPOOL");

    public final String displayName;

    DigestAlgorithm(String displayName)
    {
        this.displayName = displayName;
    }
}
