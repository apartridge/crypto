module crypto.hash.sha2;

private import crypto.hash.base;
private import crypto.hash.merkle_damgaard;
private import std.bitmanip;

version(unittest){
    private import std.stdio : writeln;
}

private class SHA256Internal (int outputBytes )  : MerkleDamgaard!(outputBytes, uint, 32, 64, 8) 
{
    private immutable uint[64] roundConstants = [ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                                                  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                                                  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                                                  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                                                  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                                                  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                                                  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                                                  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 ];

    protected override void compress(const(ubyte)[] data, ref uint[8] h)
    {
        uint w[64] = void;

        w[0..16] = cast(uint[]) data;

        version(LittleEndian)
        {
            foreach(i; 0..16){
                w[i] = swapEndian(w[i]);
            }
        }

        foreach(i; 16..64)
        {
            uint s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            uint s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = s0 + s1 + w[i-16] + w[i-7];
        }

        uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], _h = h[7]; 

        foreach(i; 0..64)
        {
            uint sum0_a = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint maj_abc = (a & b) ^ (a & c) ^ (b & c);
            uint t2 = sum0_a + maj_abc;
            uint sum1_e = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint ch_efg = (e & f) ^ (~e & g);
            uint t1 = _h + sum1_e + ch_efg + roundConstants[i] + w[i];
            
            _h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += _h;

    }

}

class SHA224 : SHA256Internal!28
{
    protected void setInitialVector () {
        h[0] = 0xc1059ed8;
        h[1] = 0x367cd507;
        h[2] = 0x3070dd17;
        h[3] = 0xf70e5939;
        h[4] = 0xffc00b31;
        h[5] = 0x68581511;
        h[6] = 0x64f98fa7;
        h[7] = 0xbefa4fa4;
    }

    unittest
    {
        assert(hash!SHA224("The quick brown fox jumps over the lazy dog") == x"730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",
               "SHA224 failed with wrong digest.");

        assert(hash!SHA224("The quick brown fox jumps over the lazy dog.") == x"619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c",
               "SHA224 failed with wrong digest.");

        assert(hash!SHA224("") == x"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
               "SHA224 failed with wrong digest on empty input.");
    }
}



class SHA256 : SHA256Internal!32
{
    protected void setInitialVector () {
        h[0] = 0x6a09e667;
        h[1] = 0xbb67ae85;
        h[2] = 0x3c6ef372;
        h[3] = 0xa54ff53a;
        h[4] = 0x510e527f;
        h[5] = 0x9b05688c;
        h[6] = 0x1f83d9ab;
        h[7] = 0x5be0cd19;
    }

    unittest
    {
        assert(hash!SHA256("The quick brown fox jumps over the lazy dog") == x"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
               "SHA256 failed with wrong digest.");

        assert(hash!SHA256("The quick brown fox jumps over the lazy dog.") == x"ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
               "SHA256 failed with wrong digest.");

        assert(hash!SHA256("") == x"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
               "SHA256 failed with wrong digest on empty input.");
    }
}

private class SHA512Internal (int outputBytes) : MerkleDamgaard!(outputBytes, ulong, 64, 128, 16) 
{
    private immutable ulong[80] roundConstants = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ];

    protected override void compress(const(ubyte)[] data, ref ulong[8] h)
    {
        ulong w[80] = void;

        w[0..16] = cast(ulong[]) data;

        version(LittleEndian)
        {
            foreach(i; 0..16){
                w[i] = swapEndian(w[i]);
            }
        }

        foreach(i; 16..80)
        {
            ulong sigma0 = rotr(w[i-15], 1) ^ rotr(w[i-15], 8) ^ (w[i-15] >> 7);
            ulong sigma1 = rotr(w[i-2], 19) ^ rotr(w[i-2], 61) ^ (w[i-2] >> 6);
            w[i] = sigma0 + sigma1 + w[i-16] + w[i-7];
        }

        ulong a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], _h = h[7]; 

        foreach(i; 0..80)
        {
            ulong sum1_e = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
            ulong ch_efg = (e & f) ^ (~e & g);
            
            ulong sum0_a = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
            ulong maj_abc = (a & b) ^ (a & c) ^ (b & c);
            
            ulong t1 = _h + sum1_e + ch_efg + roundConstants[i] + w[i];
            ulong t2 = sum0_a + maj_abc;

            _h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += _h;

    }

    protected ubyte[16] messageLengthAppendix(ulong messageLengthBytes)
    {
        ubyte[16] r = void;
        r[0..8] = 0;
        r[8..$] = nativeToBigEndian!(ulong)(messageLengthBytes << 3);
        return r;
    }

}

class SHA384 : SHA512Internal!48
{
    protected void setInitialVector () {

        h[0] = 0xcbbb9d5dc1059ed8; 
        h[1] = 0x629a292a367cd507; 
        h[2] = 0x9159015a3070dd17; 
        h[3] = 0x152fecd8f70e5939; 
        h[4] = 0x67332667ffc00b31; 
        h[5] = 0x8eb44a8768581511; 
        h[6] = 0xdb0c2e0d64f98fa7; 
        h[7] = 0x47b5481dbefa4fa4;

    }

    unittest
    {
        assert(hash!SHA384("The quick brown fox jumps over the lazy dog")
               == x"ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1",
               "SH384 failed with wrong digest.");
        assert(hash!SHA384("The quick brown fox jumps over the lazy dog.")
               == x"ed892481d8272ca6df370bf706e4d7bc1b5739fa2177aae6c50e946678718fc67a7af2819a021c2fc34e91bdb63409d7",
               "SH384 failed with wrong digest.");

        assert(hash!SHA384("")
               == x"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
               "SH384 failed with wrong digest on empty input.");
    }

}

class SHA512 : SHA512Internal!64
{
    protected void setInitialVector () {
        h[0] = 0x6a09e667f3bcc908;
        h[1] = 0xbb67ae8584caa73b;
        h[2] = 0x3c6ef372fe94f82b;
        h[3] = 0xa54ff53a5f1d36f1;
        h[4] = 0x510e527fade682d1;
        h[5] = 0x9b05688c2b3e6c1f;
        h[6] = 0x1f83d9abfb41bd6b;
        h[7] = 0x5be0cd19137e2179;
    }

    unittest
    {
        assert(hash!SHA512("The quick brown fox jumps over the lazy dog")
               == x"07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
               "SHA512 failed with wrong digest.");

        assert(hash!SHA512("The quick brown fox jumps over the lazy dog.")
               == x"91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed",
               "SHA512 failed with wrong digest.");

        assert(hash!SHA512("")
               == x"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
               "SHA512 failed with wrong digest on empty input.");
    }

}