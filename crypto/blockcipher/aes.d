module crypto.blockcipher.aes;

import std.stdio;
import std.conv;
import std.format;
import std.algorithm;

/* 
 * AES standard: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 * Intel document: http://software.intel.com/file/20457
 *
 * Plaintext: 128 bits
 * Ciphertext: 128 bits
 * Keys: 128, 192 or 256 bit
 *
 */

class AES128 : AES!(4, 4, 10)
{
    this(ubyte[16] key) { super(key); }

    unittest
    {
        auto message = cast(ubyte[16]) x"00112233445566778899aabbccddeeff";
        auto key     = cast(ubyte[16]) x"000102030405060708090a0b0c0d0e0f";
        auto cipher  = cast(ubyte[16]) x"69c4e0d86a7b0430d8cdb78070b4c55a";

        auto aes = new AES128(key);

        assert(aes.Encrypt(message) == cipher);
        assert(aes.Decrypt(cipher) == message);
    }
}

class AES192 : AES!(4, 6, 12)
{
    this(ubyte[24] key) { super(key); }

    unittest
    {
        auto message = cast(ubyte[16]) x"00112233445566778899aabbccddeeff";
        auto key     = cast(ubyte[24]) x"000102030405060708090a0b0c0d0e0f1011121314151617";
        auto cipher  = cast(ubyte[16]) x"dda97ca4864cdfe06eaf70a0ec0d7191";

        auto aes = new AES192(key);

        assert(aes.Encrypt(message) == cipher);
        assert(aes.Decrypt(cipher) == message);
    }
}

class AES256 : AES!(4, 8, 14)
{
    this(ubyte[32] key) { super(key); }

    unittest
    {
        auto message = cast(ubyte[16]) x"00112233445566778899aabbccddeeff";
        auto key     = cast(ubyte[32]) x"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        auto cipher  = cast(ubyte[16]) x"8ea2b7ca516745bfeafc49904b496089";

        auto aes = new AES256(key);

        assert(aes.Encrypt(message) == cipher);
        assert(aes.Decrypt(cipher) == message);
    }
}

/*
 * Nk (key length in words)
 * Nb (block length in words)
 * Nr (number of rounds)
 */
class AES(uint Nb, uint Nk, uint Nr)
if ((Nb == 4 && Nk == 4 && Nr == 10) || 
    (Nb == 4 && Nk == 6 && Nr == 12) ||
    (Nb == 4 && Nk == 8 && Nr == 14))
{
    alias uint[Nb] State;
    alias uint[Nb] Key;

    // Generate and store one key per round
    protected Key[Nr+1] key;

    static const ubyte[] sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ];

    static const ubyte[] inv_sbox = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ];

    public this(ubyte[4*Nk] k)
    {
        KeyExpansion2( k );
    }
    
    public ubyte[4*Nb] Encrypt(ubyte[4*Nb] message)
    {
        ubyte[4*Nb] m = message[0 .. 4*Nb];

        // Shuffle around bytes to conform to Intel standard
        State state = cast(State) BytesToWords(ReverseBytes(m));

        //Key key = cast(Key) BytesToWords(ReverseBytes(k));
        PrintHex(0, "input", state);

        //Key[] w = KeyExpansion(key);
        PrintHex(0, "k_sch", key[0]);

        AddRoundKey(state, key[0]);
        PrintHex(0, "start", state);

        uint round = 0;
        while (round++ < Nr - 1)
        {
            SubBytes(state);
            PrintHex(round, "s_box", state);

            state = ShiftRows(state);
            PrintHex(round, "s_row", state);

            state = MixColumns(state);
            PrintHex(round, "m_col", state);
            PrintHex(round, "k_sch", key[round]);

            AddRoundKey(state, key[round]);
            PrintHex(round, "start", state);
        }

        SubBytes(state);
        PrintHex(round, "s_box", state);

        state = ShiftRows(state);
        PrintHex(round, "s_row", state);
        PrintHex(round, "k_sch", key[round]);

        AddRoundKey(state, key[round]);
        PrintHex(round, "output", state);

        return cast(ubyte[4*Nb]) ReverseBytes(WordsToBytes(state));
    }
 
    public ubyte[4*Nb] Decrypt(ubyte[4*Nb] c)
    {
        State state = cast(State) BytesToWords(ReverseBytes(c));

        //Key key = cast(Key) BytesToWords(ReverseBytes(k));
        PrintHex(0, "iinput", state);

        //Key[] w = KeyExpansion(key);
        PrintHex(0, "ik_sch", key[Nr]);

        AddRoundKey(state, key[Nr]);
        PrintHex(0, "istart", state);

        uint round = 0;
        for (round = Nr - 1; round > 0; --round)
        {
            state = InvShiftRows(state);
            PrintHex(round, "is_row", state);

            InvSubBytes(state);
            PrintHex(round, "is_box", state);

            PrintHex(round, "ik_sch", key[round]);
            AddRoundKey(state, key[round]);
            PrintHex(round, "is_add", state);

            state = InvMixColumns(state);
            PrintHex(round, "istart", state);
        }

        state = InvShiftRows(state);
        PrintHex(round, "is_row", state);

        InvSubBytes(state);
        PrintHex(round, "is_box", state);

        PrintHex(round, "ik_sch", key[0]);
        AddRoundKey(state, key[0]);
        PrintHex(round, "ioutput", state);

        return cast(ubyte[4*Nb]) ReverseBytes(WordsToBytes(state));
    }

    private static void AddRoundKey(ref State s, ref Key k)
    {
        foreach (uint i, ref uint n; s) n ^= k[i];
    }

    unittest {
        State a = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
        State b = [0x00102030, 0x40506070, 0x8090a0b0, 0xc0d0e0f0];
        Key k   = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f];
        AddRoundKey(a, k);
        assert(a == b, "AddRoundKey");
    }

    private static void SubBytes(ref State s, ref const ubyte[] b = sbox)
    {
        foreach (ref uint i; s) 
            i = b[i >> 24] << 24 | b[(i & 0x00ff0000) >> 16] << 16 | 
                b[(i & 0x0000ff00) >> 8] << 8 | b[i & 0x000000ff];
    }

    private static void InvSubBytes(ref State s)
    {
        SubBytes(s, inv_sbox);
    }

    /*
     * Independent on byte ordering.
     */
    unittest
    {
        State a = [0x73744765, 0x63535465, 0x5d5b5672, 0x7b746f5d];
        State b = [0x8f92a04d, 0xfbed204d, 0x4c39b140, 0x2192a84c];
        State c = [0x73744765, 0x63535465, 0x5d5b5672, 0x7b746f5d];

        SubBytes(a);
        assert(a == b, "SubBytes");

        InvSubBytes(b);
        assert(b == c, "InvSubBytes");
    }

    private static State ShiftRows(State s)
    {
        State sp = [0, 0, 0, 0];
        foreach (uint i, uint n; s)
        {
            sp[(i + 3) % 4] ^= n & 0xff000000;
            sp[(i + 2) % 4] ^= n & 0x00ff0000;
            sp[(i + 1) % 4] ^= n & 0x0000ff00;
            sp[i % 4]       ^= n & 0x000000ff;
        }
        return sp;
    }
    
    private static State InvShiftRows(State s)
    {
        State sp = [0, 0, 0, 0];
        foreach (uint i, uint n; s)
        {
            sp[(i + 1) % 4] ^= n & 0xff000000;
            sp[(i + 2) % 4] ^= n & 0x00ff0000;
            sp[(i + 3) % 4] ^= n & 0x0000ff00;
            sp[i % 4]       ^= n & 0x000000ff;
        }
        return sp;
    }

    unittest {
        State a = [0x7b5b5465, 0x73745665, 0x63746f72, 0x5d53475d];
        State b = [0x73744765, 0x63535465, 0x5d5b5672, 0x7b746f5d];
        State c = [0x5d745665, 0x7b536f65, 0x735b4772, 0x6374545d];

        assert(ShiftRows(a) == b, "ShiftRows");
        assert(InvShiftRows(a) == c, "InvShiftRows");
    }

    // Multiplication under GF(256)
    private static ubyte xtimes(ubyte a, ubyte b)
    {
        ubyte tmp = b;
        ubyte res = 0x0;
        if ((a & 0x01) != 0) res = b;
        foreach (uint c; [0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]) { // TODO, add 0x01 ?
            tmp = xtime(tmp); // b * { 02, 04, 08, 10, 20, 40, 80 }
            if ((a & c) != 0) {
                res ^= tmp;
            }
        }
        return res;
    }

    private static ubyte xtime(ubyte b) {
        ubyte a = cast(ubyte)(b << 1);
        if ((b & 0b10000000) == 0b10000000) return cast(ubyte)(a ^ 0x1b);
        return a;
    };

    private static State MixColumns(State s)
    {
        State sp = [0, 0, 0, 0];
        for (uint i = 0; i < 4; ++i)
        {
            ubyte a = (s[i] & 0x000000ff);
            ubyte b = (s[i] & 0x0000ff00) >> 8;
            ubyte c = (s[i] & 0x00ff0000) >> 16;
            ubyte d = (s[i] & 0xff000000) >>> 24;
            sp[i] |= (xtimes(0x02, a) ^ xtimes(0x03, b) ^ c ^ d);
            sp[i] |= (a ^ xtimes(0x02, b) ^ xtimes(0x03, c) ^ d) << 8;
            sp[i] |= (a ^ b ^ xtimes(0x02, c) ^ xtimes(0x03, d)) << 16;
            sp[i] |= (xtimes(0x03, a) ^ b ^ c ^ xtimes(0x02, d)) << 24;
        }
        return sp;
    }

    private static State InvMixColumns(State s)
    {
        State sp = [0, 0, 0, 0];
        for (uint i = 0; i < 4; ++i)
        {
            ubyte a = (s[i] & 0x000000ff);
            ubyte b = (s[i] & 0x0000ff00) >> 8;
            ubyte c = (s[i] & 0x00ff0000) >> 16;
            ubyte d = (s[i] & 0xff000000) >>> 24;
            sp[i] |= (xtimes(0x0e, a) ^ xtimes(0x0b, b) ^ xtimes(0x0d, c) ^ xtimes(0x09, d));
            sp[i] |= (xtimes(0x09, a) ^ xtimes(0x0e, b) ^ xtimes(0x0b, c) ^ xtimes(0x0d, d)) << 8;
            sp[i] |= (xtimes(0x0d, a) ^ xtimes(0x09, b) ^ xtimes(0x0e, c) ^ xtimes(0x0b, d)) << 16;
            sp[i] |= (xtimes(0x0b, a) ^ xtimes(0x0d, b) ^ xtimes(0x09, c) ^ xtimes(0x0e, d)) << 24;
        }
        return sp;
    }

    unittest 
    {
        assert(xtime(0x57) == 0xae);
        assert(xtime(0xae) == 0x47);
        assert(xtime(0x47) == 0x8e);
        assert(xtime(0x8e) == 0x07);

        assert(xtime(0x57) == xtimes(0x02, 0x57));
        assert(xtimes(0x13, 0x57) == 0xfe);

        State a = [0x627a6f66, 0x44b109c8, 0x2b18330a, 0x81c3b3e5];
        State b = [0x7b5b5465, 0x73745665, 0x63746f72, 0x5d53475d];
        assert(MixColumns(a) == b, "MixColumns");

        State c = [0x8dcab9dc, 0x035006bc, 0x8f57161e, 0x00cafd8d];
        State d = [0xd635a667, 0x928b5eae, 0xeec9cc3b, 0xc55f5777];
        assert(InvMixColumns(c) == d, "InvMixColumns");
    }

    private static uint SubWord(uint w)
    {
        return sbox[(w & 0xff000000) >> 24] << 24 |
               sbox[(w & 0x00ff0000) >> 16] << 16 |
               sbox[(w & 0x0000ff00) >> 8] << 8 |
               sbox[(w & 0x000000ff)];
    }

    unittest
    {
        assert(SubWord(0x73744765) == 0x8f92a04d);
    }

    private static uint RotWord(uint w)
    {
        return (w >> 8) | (w << 24);
    }

    unittest
    {
        assert(RotWord(0x3c4fcf09) == 0x093c4fcf);
    }

    private void KeyExpansion(Key k)
    {
        uint[Nb*(Nr+1)] w;

        // Round key constants
        static const uint[10] rCon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

        // First round key(s) is a copy of the original key
        w[0] = k[3];
        w[1] = k[2];
        w[2] = k[1];
        w[3] = k[0];// Reverse order from xmm layout (to make indexing easy)
        
        uint tmp;
        uint i = Nk;
        while (i < Nb*(Nr+1))
        {
            tmp = w[i-1];
            if (i % Nk == 0)
                tmp = SubWord(RotWord(tmp)) ^ rCon[i/Nk-1];
            w[i] = w[i - Nk] ^ tmp; // w[i - 4] is the same
            ++i;
        }

        // Rotate back words
        for (uint j = 0; j < Nr + 1; ++j)
            key[j] = [w[4*j+3], w[4*j+2], w[4*j+1], w[4*j]];
    }

    private void KeyExpansion2(ubyte[4*Nk] k)
    {
        uint[Nb*(Nr+1)] w;

        // Round key constants
        static const uint[10] rCon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

        // First round key(s) is a copy of the original key (reverse bytes internally)
        uint i = 0;
        while (i < Nk)
        {
            w[i] = k[4*i] | k[4*i+1] << 8 | k[4*i+2] << 16 | k[4*i+3] << 24;
            i++;
        }// Still in reverse word order from xmm layout (to make indexing easy)

        uint tmp;
        i = Nk;
        while (i < Nb*(Nr+1))
        {
            tmp = w[i-1];
            if (i % Nk == 0)
                tmp = SubWord(RotWord(tmp)) ^ rCon[i/Nk-1];
            else if (Nk > 6 && i % Nk == 4)
                tmp = SubWord(tmp);
            w[i] = w[i - Nk] ^ tmp; // w[i - 4] is the same
            ++i;
        }

        // Rotate back words (could remove this if we don't use Intel ordering)
        for (uint j = 0; j < Nr + 1; ++j)
            key[j] = [w[4*j+3], w[4*j+2], w[4*j+1], w[4*j]];
    }

    unittest
    {
        Key k  = [0x3c4fcf09, 0x8815f7ab, 0xa6d2ae28, 0x16157e2b];
        Key r1 = [0x05766c2a, 0x3939a323, 0xb12c5488, 0x17fefaa0];
        //Key[] res = KeyExpansion(k);

        //assert(res[0] == k);
        //assert(res[1] == r1);
    }

    // Utility

    private static ubyte[4*Nb] ReverseBytes(ubyte[4*Nb] b)
    {
        ubyte[4*Nb] res;
        for (uint i = 0; i < 4*Nb; ++i)
            res[i] = b[4*Nb-1-i];
        return res;
    }

    private static ubyte[4*Nk] ReverseKeyBytes(ubyte[4*Nk] b)
    {
        ubyte[4*Nk] res;
        for (uint i = 0; i < 4*Nk; ++i)
            res[i] = b[4*Nk-1-i];
        return res;
    }

    private static uint[4] BytesToWords(ubyte[4*Nb] b)
    {
        uint[4] str;
        for (uint i = 0; i < 4; ++i)
            str[i] = b[4*i] << 24 | b[4*i+1] << 16 | b[4*i+2] << 8 | b[4*i+3];
        return str;
    }

    private static ubyte[4*Nb] WordsToBytes(uint[4] w)
    {
        ubyte[4*Nb] bytes;
        foreach (uint i, uint n; w)
        {
            bytes[4*i] = (n & 0xff000000) >> 24;
            bytes[4*i+1] = (n & 0x00ff0000) >> 16;
            bytes[4*i+2] = (n & 0x0000ff00) >> 8;
            bytes[4*i+3] = (n & 0x000000ff);
        }
        return bytes;
    }

    private static ubyte[4*Nk] KeyToBytes(Key k)
    {
        ubyte[4*Nk] bytes;
        foreach (uint i, uint n; k)
        {
            bytes[4*i] = (n & 0xff000000) >> 24;
            bytes[4*i+1] = (n & 0x00ff0000) >> 16;
            bytes[4*i+2] = (n & 0x0000ff00) >> 8;
            bytes[4*i+3] = (n & 0x000000ff);
        }
        return bytes;
    }

    private static Key BytesToKey(ubyte[4*Nk] b)
    {
        Key str;
        for (uint i = 0; i < 4; ++i)
            str[i] = b[4*i] << 24 | b[4*i+1] << 16 | b[4*i+2] << 8 | b[4*i+3];
        return str;
    }
}

// -- Debug stuff --

private static void PrintHex(uint round, string s, uint[] b)
{
    write("round["); write(round); write("]."~s~"\t");
    for (uint i = 0; i < b.length; ++i)
        write(wordToString(b[i]));
    writeln("");
}

static string wordToString(uint word) {
    ubyte[4] ss = [cast(ubyte)(word >> 24), cast(ubyte)(word >> 16), cast(ubyte)(word >> 8), cast(ubyte)word];
    return byteToHexString(ss);
}

auto byteToHexString(ubyte[] s) // 0..256
{
    auto byteToHex = function (ubyte a) {
        ubyte upper = (a & 0b11110000) >> 4;
        ubyte lower = a & 0b00001111;
        auto lookup = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"];

        return lookup[upper]~lookup[lower];
    };
    string res = ""; int i = 0;
    foreach (b; s) {
        res ~= byteToHex(b); i++;
        if (i % 4 == 0) res ~= " ";
    }

    return res;
}

// -- End debug stuff --