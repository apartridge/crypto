module crypto.blockcipher.aes;

import std.stdio;
import std.conv;
import std.format;
import std.algorithm;

/* 
 * AES standard: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 *
 * Keys: __128__, 192 or 256 bit
 *
 */


class AES128
{
    static const uint Nk = 4;   // Key length (4 words)
    static const uint Nr = 10;  // Number of rounds
    static const uint Nb = 4;   // Block size (4 words) ??????

    static ubyte[] sbox = 
        [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]~
        [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0]~
        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15]~
        [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75]~
        [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84]~
        [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf]~
        [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8]~
        [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2]~
        [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73]~
        [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb]~
        [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79]~
        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08]~
        [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a]~
        [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e]~
        [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf]~
        [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];

    // TODO: No ~, just onee large array literal. Looks nicer
    static ubyte[] inv_sbox = 
        [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb]~
        [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb]~
        [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e]~
        [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25]~
        [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92]~
        [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84]~
        [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06]~
        [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b]~
        [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73]~
        [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e]~
        [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b]~
        [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4]~
        [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f]~
        [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef]~
        [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61]~
        [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d];
    

    static ubyte[4][Nb] toState(ubyte[16] txt)
    {
        ubyte[4][Nb] state;
        for (uint i = 0; i < 16; ++i)
            state[i % 4][i / 4] = txt[i];
        return state;
    }

    static ubyte[16] fromState(ubyte[4][Nb] state)
    {
        ubyte[16] txt;
        for (uint i = 0; i < 16; ++i) 
            txt[i] = state[i % 4][i / 4];
        return txt;
    }

    static ubyte[16] encrypt(ubyte[16] txt, ubyte[4*Nk] key) 
    {
        // Copy message in state array - will be mutated in each step
        ubyte[4][Nb] state = toState(txt);
        printState(0, "input", state);

        // Perform key schedule
        uint[Nb*(Nr+1)] w = keyExpansion(key);
        printKey(0, "k_sch", w[0 .. Nb]);

        state = addRoundKey(state, w[0 .. Nb]);
        printState(0, "start", state);

        uint round = 0;
        while ( round++ < Nr-1) {
            state = subBytes(state);
            printState(round, "s_box", state); 

            state = shiftRows(state);
            printState(round, "s_row", state);

            state = mixColumns(state);
            printState(round, "m_col", state);

            uint[Nb] roundKey = w[round*Nb .. (round+1)*Nb];
            printKey(round, "k_sch", roundKey);

            state = addRoundKey(state, roundKey);
            printState(round, "start", state);
        }

        state = subBytes(state);
        printState(round, "s_box", state);

        state = shiftRows(state);
        printState(round, "s_rows", state);

        uint[Nb] roundKey = w[Nr*Nb .. (Nr+1)*Nb];
        printKey(round, "k_sch", roundKey);

        state = addRoundKey(state, roundKey);
        printState(round, "output", state);

        return fromState(state);
    }

    static ubyte[16] decrypt(ubyte[16] ciphertext, ubyte[4*Nk] key) 
    { 
        ubyte[4][Nb] state = toState(ciphertext);
        printState(0, "iinput", state);

        // Perform key schedule
        uint[Nb*(Nr+1)] w = keyExpansion(key);
        printKey(0, "ik_sch", w[Nr*Nb .. (Nr+1)*Nb]);

        state = addRoundKey(state, w[Nr*Nb .. (Nr+1)*Nb]);
        printState(1, "istart", state);

        uint i = 1;
        for (uint round = Nr - 1; round > 0; --round, ++i)
        {
            state = invShiftRows(state);
            printState(i, "is_row", state);

            state = invSubBytes(state);
            printState(i, "is_box", state); 

            printKey(i, "ik_sch", w[round*Nb .. (round+1)*Nb]);
            state = addRoundKey(state, w[round*Nb .. (round+1)*Nb]);
            printState(i, "ik_add", state);

            state = invMixColumns(state);
            printState(i, "istart", state);
        }

        state = invShiftRows(state);
        printState(i, "is_row", state);

        state = invSubBytes(state);
        printState(i, "is_box", state); 

        printKey(i, "ik_sch", w[0 .. Nb]);
        state = addRoundKey(state, w[0 .. Nb]);

        printState(i, "ioutput", state);
        return fromState(state); 
    }

    /*
     * Add each word of the round key with the corresponding state column
     * Here, state should have been just a flat array of bytes ...
     */
    private static ubyte[4][Nb] addRoundKey(ubyte[4][Nb] state, uint[] key)
    {
        //write("Key: ");
        //writeln(key);
        for (uint i = 0; i < 4; ++i) {
            state[0][i] = state[0][i] ^ (cast(ubyte)(key[i] >> 24));
            state[1][i] = state[1][i] ^ (cast(ubyte)(key[i] >> 16));
            state[2][i] = state[2][i] ^ (cast(ubyte)(key[i] >> 8));
            state[3][i] = state[3][i] ^ (cast(ubyte)(key[i]));
        }
        return state;
    }

    unittest {
        ubyte[4][4] state = toState(cast(ubyte[16])x"00112233445566778899aabbccddeeff");
        ubyte[4][4] res   = toState(cast(ubyte[16])x"00102030405060708090a0b0c0d0e0f0");
        uint[4] key       = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f];

        assert( addRoundKey(state, key) == res );
    }

    private static ubyte[4][Nb] subBytes(ubyte[4][Nb] state) {
        for (uint i = 0; i < state.length; ++i) {
            for (uint j = 0; j < state[0].length; ++j) {
                state[i][j] = sbox[state[i][j]];
            }
        }
        return state;
    }

    private static ubyte[4][Nb] invSubBytes(ubyte[4][Nb] state)
    {
        // TODO: Reuse code from subBytes. 99.99% identical
        for (uint i = 0; i < state.length; ++i) {
            for (uint j = 0; j < state[0].length; ++j) {
                state[i][j] = inv_sbox[state[i][j]];
            }
        }
        return state;
    }

    unittest
    {
        // TODO
    }

    /*
     * Cyclically shift the last three rows
     * TODO: Efficiently
     */
    private static ubyte[4][Nb] shiftRows(ubyte[4][Nb] state)
    {
        auto shiftRow(uint row) {
            ubyte tmp = state[row][0];
            state[row][0] = state[row][1];
            state[row][1] = state[row][2];
            state[row][2] = state[row][3];
            state[row][3] = tmp;
        }

        for (uint i = 1; i < 4; ++i)
            for (uint j = 0; j < i; ++j)
                shiftRow(i);

        return state;
    }

    private static ubyte[4][Nb] invShiftRows(ubyte[4][Nb] state)
    {
        auto invShiftRow(uint row) {
            ubyte tmp = state[row][3];
            state[row][3] = state[row][2];
            state[row][2] = state[row][1];
            state[row][1] = state[row][0];
            state[row][0] = tmp;
        }

        for (uint i = 1; i < 4; ++i)
            for (uint j = 0; j < i; ++j)
                invShiftRow(i);

        return state;
    }

    unittest {
        ubyte[4][4] state = toState(cast(ubyte[16])x"63cab7040953d051cd60e0e7ba70e18c");
        ubyte[4][4] res   = toState(cast(ubyte[16])x"6353e08c0960e104cd70b751bacad0e7");
        writeln(stateToString(state));
        writeln(stateToString(res));
        assert( shiftRows(state) == res );
    }

    private static ubyte[4][Nb] mixColumns(ubyte[4][Nb] s)
    {
        // Need to make a copy to not overwrite the results
        ubyte[4][Nb] sp = s;

        // TODO: Lookup table?
        for (uint c = 0; c < 4; ++c) {
            sp[0][c] = xtime(s[0][c]) ^ (xtime(s[1][c]) ^ s[1][c]) ^ s[2][c] ^ s[3][c];
            sp[1][c] = s[0][c] ^ xtime(s[1][c]) ^ (xtime(s[2][c]) ^ s[2][c]) ^ s[3][c];
            sp[2][c] = s[0][c] ^ s[1][c] ^ xtime(s[2][c]) ^ (xtime(s[3][c]) ^ s[3][c]);
            sp[3][c] = (xtime(s[0][c]) ^ s[0][c]) ^ s[1][c] ^ s[2][c] ^ xtime(s[3][c]);
        }

        return sp;
    }

    // This fails somehow. Needs testing... Also black screen = wtf??
    private static ubyte[4][Nb] invMixColumns(ubyte[4][Nb] s)
    {
        ubyte[4][Nb] sp = s;
        for (uint c = 0; c < 4; ++c) {
            sp[0][c] = xtimes(0x0e, s[0][c]) ^ xtimes(0x0b, s[1][c]) ^ xtimes(0x0d, s[2][c]) ^ xtimes(0x09, s[3][c]);
            sp[1][c] = xtimes(0x09, s[0][c]) ^ xtimes(0x0e, s[1][c]) ^ xtimes(0x0b, s[2][c]) ^ xtimes(0x0d, s[3][c]);
            sp[2][c] = xtimes(0x0d, s[0][c]) ^ xtimes(0x09, s[1][c]) ^ xtimes(0x0e, s[2][c]) ^ xtimes(0x0b, s[3][c]);
            sp[3][c] = xtimes(0x0b, s[0][c]) ^ xtimes(0x0d, s[1][c]) ^ xtimes(0x09, s[2][c]) ^ xtimes(0x0e, s[3][c]);
        }
        return sp;
    }

    // Calculate funky stuff like {0e} * s etc. 
    // {03} * s = ({02} ^ {01}) * s = ({02} * s) ^ ({01} ^ s) = xtime(s) ^ s
    private static ubyte xtimes(ubyte a, ubyte b)
    {
        ubyte tmp = b;
        ubyte res = 0x0;
        if ((a & 0x01) != 0) res = b;
        foreach (uint c; [0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]) {
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

    unittest 
    {
        assert(xtime(0x57) == 0xae);
        assert(xtime(0xae) == 0x47);
        assert(xtime(0x47) == 0x8e);
        assert(xtime(0x8e) == 0x07);

        assert(xtimes(0x13, 0x57) == 0xfe);

        ubyte[4][4] state = toState( cast(ubyte[16])x"6353e08c0960e104cd70b751bacad0e7" );
        ubyte[4][4] res   = toState( cast(ubyte[16])x"5f72641557f5bc92f7be3b291db9f91a" );
        
        assert( mixColumns(state) == res, "MixColumns" );
    }



    /* 
     * Expand the key into one key for each round + original
     * TODO: Rewrite with 32-bit uint ?
     */
    static uint[Nb*(Nr+1)] keyExpansion(ubyte[4*Nk] key) 
    {
        // Round key constant. Dependent on key size (TODO)
        const uint[10] rCon = [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 
        0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000];

        // Do S-box substitution on each byte
        auto subWord = function(uint word) {
            uint a = sbox[(word & 0xff000000) >>> 24] << 24;
            uint b = sbox[(word & 0x00ff0000) >>> 16] << 16;
            uint c = sbox[(word & 0x0000ff00) >>> 8 ] << 8;
            return a | b | c | sbox[word & 0x000000ff];
        };
        //write("Input key to expansion: ");
        //writeln(byteToHexString(key));

        // [abcd] -> [bcda]
        auto rotWord = function(uint word) {
            return word << 8 | word >>> 24;
        };

        // Store keys in array of words (first 4 words is original key)
        uint[Nb * (Nr + 1)] w;
        //writeln(w);
        for (uint i = 0; i < Nk; ++i)
            w[i] = key[4*i] << 24 | key[4*i+1] << 16 | key[4*i+2] << 8 | key[4*i+3];
        //writeln("w0: "~wordToString(w[0])~"\tw1: "~wordToString(w[1])~"\tw2: "~wordToString(w[2])~"\tw3: "~wordToString(w[3]));

        for (uint i = Nk; i < Nb*(Nr + 1); ++i) {
            uint temp = w[i-1];
            //write("i: ");
            //write(i);
            //write("\t temp: ");
            //write(wordToString(temp));
            if (i % Nk == 0) {
                temp = subWord(rotWord(temp)) ^ rCon[i/Nk-1];
            } else if (Nk > 6 && i % Nk == 4) {
                temp = subWord(temp);
            }
            w[i] = w[i-Nk] ^ temp;
            //write("\t w[i-Nk]: ");
            //write(wordToString(w[i-Nk]));
            //write("\t w[i]: ");
            //writeln(wordToString(w[i]));
        }
        return w;
    }

    unittest
    {
        // TODO
    }


    // -- Debug stuff --

    static void printState(uint round, string s, ubyte[4][Nb] state) 
    {
        write("round["); write(round); writeln("]."~s~"\t"~stateToString( cast(ubyte[4][4])fromState(state) ));
    }

    static void printKey(uint round, string s, uint[] key) 
    {
        write("round["); write(round); write("]."~s~"\t");
        for (uint i = 0; i < key.length; ++i)
            write(wordToString(key[i]));
        writeln("");
    }

    static string stateToString(ubyte[4][] state) {
        ubyte[4*Nb] ss;
        for (uint i = 0; i < 4 * Nb; ++i)
            ss[i] = state[i / 4][i % 4];
        return byteToHexString(ss);
    }

    static string wordToString(uint word) {
        ubyte[4] ss = [cast(ubyte)(word >> 24), cast(ubyte)(word >> 16), cast(ubyte)(word >> 8), cast(ubyte)word];
        return byteToHexString(ss);
    }

    // -- End debug stuff --
}


unittest
{
    writeln("Running AES test cases ...");
    auto message = cast(ubyte[16]) x"00112233445566778899aabbccddeeff";
    auto key     = cast(ubyte[16]) x"000102030405060708090a0b0c0d0e0f";
    auto cipher  = cast(ubyte[16]) x"69c4e0d86a7b0430d8cdb78070b4c55a";

    writeln("Message: "~byteToHexString(message));
    writeln("Key:     "~byteToHexString(key));

    assert( AES128.encrypt(message, key) == cipher );

    writeln("");

    assert( AES128.decrypt(cipher, key) == message );

    writeln("Done!");
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