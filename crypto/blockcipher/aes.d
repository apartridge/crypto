module crypto.blockcipher.aes;

import std.stdio, std.bitmanip;
import std.datetime;


public interface BlockCipher
{
    public void encrypt(ubyte[] message, ref ubyte[] cipher);
    public void decrypt(ubyte[] cipher, ref ubyte[] message);

    @property public const uint blockSize();
    public void reportTiming();
}


/* 
 * AES standard: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 * Intel document: http://software.intel.com/file/20457
 *
 * Plaintext: 128 bit
 * Ciphertext: 128 bit
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
        ubyte[] buffer = new ubyte[16];

        auto aes = new AES128(key);

        aes.encrypt(message, buffer);
        assert(buffer == cipher);

        aes.decrypt(cipher, buffer);
        assert(buffer == message);
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
        ubyte[] buffer = new ubyte[16];

        auto aes = new AES192(key);

        aes.encrypt(message, buffer);
        assert(buffer == cipher);

        aes.decrypt(cipher, buffer);
        assert(buffer == message);
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
        ubyte[] buffer = new ubyte[16];

        auto aes = new AES256(key);

        aes.encrypt(message, buffer);
        assert(buffer == cipher);

        aes.decrypt(cipher, buffer);
        assert(buffer == message);
    }
}

abstract class AES(uint Nb, uint Nk, uint Nr)
if ((Nb == 4 && Nk == 4 && Nr == 10) || 
    (Nb == 4 && Nk == 6 && Nr == 12) ||
    (Nb == 4 && Nk == 8 && Nr == 14)) : BlockCipher
{
    alias uint[Nb] State;
    alias uint[Nb] Key;

    union state_t
    {
        uint[Nb] words;
        ubyte[4*Nb] bytes;
    }

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

    static const ubyte[] x_0x02 = [
        0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30,
        32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62,
        64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94,
        96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126,
        128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158,
        160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190,
        192, 194, 196, 198, 200, 202, 204, 206, 208, 210, 212, 214, 216, 218, 220, 222,
        224, 226, 228, 230, 232, 234, 236, 238, 240, 242, 244, 246, 248, 250, 252, 254,
        27, 25, 31, 29, 19, 17, 23, 21, 11, 9, 15, 13, 3, 1, 7, 5,
        59, 57, 63, 61, 51, 49, 55, 53, 43, 41, 47, 45, 35, 33, 39, 37,
        91, 89, 95, 93, 83, 81, 87, 85, 75, 73, 79, 77, 67, 65, 71, 69,
        123, 121, 127, 125, 115, 113, 119, 117, 107, 105, 111, 109, 99, 97, 103, 101,
        155, 153, 159, 157, 147, 145, 151, 149, 139, 137, 143, 141, 131, 129, 135, 133,
        187, 185, 191, 189, 179, 177, 183, 181, 171, 169, 175, 173, 163, 161, 167, 165,
        219, 217, 223, 221, 211, 209, 215, 213, 203, 201, 207, 205, 195, 193, 199, 197,
        251, 249, 255, 253, 243, 241, 247, 245, 235, 233, 239, 237, 227, 225, 231, 229
    ];

    static const ubyte[] x_0x03 = [
        0, 3, 6, 5, 12, 15, 10, 9, 24, 27, 30, 29, 20, 23, 18, 17,
        48, 51, 54, 53, 60, 63, 58, 57, 40, 43, 46, 45, 36, 39, 34, 33,
        96, 99, 102, 101, 108, 111, 106, 105, 120, 123, 126, 125, 116, 119, 114, 113,
        80, 83, 86, 85, 92, 95, 90, 89, 72, 75, 78, 77, 68, 71, 66, 65,
        192, 195, 198, 197, 204, 207, 202, 201, 216, 219, 222, 221, 212, 215, 210, 209,
        240, 243, 246, 245, 252, 255, 250, 249, 232, 235, 238, 237, 228, 231, 226, 225,
        160, 163, 166, 165, 172, 175, 170, 169, 184, 187, 190, 189, 180, 183, 178, 177,
        144, 147, 150, 149, 156, 159, 154, 153, 136, 139, 142, 141, 132, 135, 130, 129,
        155, 152, 157, 158, 151, 148, 145, 146, 131, 128, 133, 134, 143, 140, 137, 138,
        171, 168, 173, 174, 167, 164, 161, 162, 179, 176, 181, 182, 191, 188, 185, 186,
        251, 248, 253, 254, 247, 244, 241, 242, 227, 224, 229, 230, 239, 236, 233, 234,
        203, 200, 205, 206, 199, 196, 193, 194, 211, 208, 213, 214, 223, 220, 217, 218,
        91, 88, 93, 94, 87, 84, 81, 82, 67, 64, 69, 70, 79, 76, 73, 74,
        107, 104, 109, 110, 103, 100, 97, 98, 115, 112, 117, 118, 127, 124, 121, 122,
        59, 56, 61, 62, 55, 52, 49, 50, 35, 32, 37, 38, 47, 44, 41, 42,
        11, 8, 13, 14, 7, 4, 1, 2, 19, 16, 21, 22, 31, 28, 25, 26
    ];

    static const ubyte[] x_0x09 = [
        0, 9, 18, 27, 36, 45, 54, 63, 72, 65, 90, 83, 108, 101, 126, 119,
        144, 153, 130, 139, 180, 189, 166, 175, 216, 209, 202, 195, 252, 245, 238, 231,
        59, 50, 41, 32, 31, 22, 13, 4, 115, 122, 97, 104, 87, 94, 69, 76,
        171, 162, 185, 176, 143, 134, 157, 148, 227, 234, 241, 248, 199, 206, 213, 220,
        118, 127, 100, 109, 82, 91, 64, 73, 62, 55, 44, 37, 26, 19, 8, 1,
        230, 239, 244, 253, 194, 203, 208, 217, 174, 167, 188, 181, 138, 131, 152, 145,
        77, 68, 95, 86, 105, 96, 123, 114, 5, 12, 23, 30, 33, 40, 51, 58,
        221, 212, 207, 198, 249, 240, 235, 226, 149, 156, 135, 142, 177, 184, 163, 170,
        236, 229, 254, 247, 200, 193, 218, 211, 164, 173, 182, 191, 128, 137, 146, 155,
        124, 117, 110, 103, 88, 81, 74, 67, 52, 61, 38, 47, 16, 25, 2, 11,
        215, 222, 197, 204, 243, 250, 225, 232, 159, 150, 141, 132, 187, 178, 169, 160,
        71, 78, 85, 92, 99, 106, 113, 120, 15, 6, 29, 20, 43, 34, 57, 48,
        154, 147, 136, 129, 190, 183, 172, 165, 210, 219, 192, 201, 246, 255, 228, 237,
        10, 3, 24, 17, 46, 39, 60, 53, 66, 75, 80, 89, 102, 111, 116, 125,
        161, 168, 179, 186, 133, 140, 151, 158, 233, 224, 251, 242, 205, 196, 223, 214,
        49, 56, 35, 42, 21, 28, 7, 14, 121, 112, 107, 98, 93, 84, 79, 70
    ];
    
    static const ubyte[] x_0x0b = [
        0, 11, 22, 29, 44, 39, 58, 49, 88, 83, 78, 69, 116, 127, 98, 105,
        176, 187, 166, 173, 156, 151, 138, 129, 232, 227, 254, 245, 196, 207, 210, 217,
        123, 112, 109, 102, 87, 92, 65, 74, 35, 40, 53, 62, 15, 4, 25, 18,
        203, 192, 221, 214, 231, 236, 241, 250, 147, 152, 133, 142, 191, 180, 169, 162,
        246, 253, 224, 235, 218, 209, 204, 199, 174, 165, 184, 179, 130, 137, 148, 159,
        70, 77, 80, 91, 106, 97, 124, 119, 30, 21, 8, 3, 50, 57, 36, 47,
        141, 134, 155, 144, 161, 170, 183, 188, 213, 222, 195, 200, 249, 242, 239, 228,
        61, 54, 43, 32, 17, 26, 7, 12, 101, 110, 115, 120, 73, 66, 95, 84,
        247, 252, 225, 234, 219, 208, 205, 198, 175, 164, 185, 178, 131, 136, 149, 158,
        71, 76, 81, 90, 107, 96, 125, 118, 31, 20, 9, 2, 51, 56, 37, 46,
        140, 135, 154, 145, 160, 171, 182, 189, 212, 223, 194, 201, 248, 243, 238, 229,
        60, 55, 42, 33, 16, 27, 6, 13, 100, 111, 114, 121, 72, 67, 94, 85,
        1, 10, 23, 28, 45, 38, 59, 48, 89, 82, 79, 68, 117, 126, 99, 104,
        177, 186, 167, 172, 157, 150, 139, 128, 233, 226, 255, 244, 197, 206, 211, 216,
        122, 113, 108, 103, 86, 93, 64, 75, 34, 41, 52, 63, 14, 5, 24, 19,
        202, 193, 220, 215, 230, 237, 240, 251, 146, 153, 132, 143, 190, 181, 168, 163
    ];

    static const ubyte[] x_0x0d = [
        0, 13, 26, 23, 52, 57, 46, 35, 104, 101, 114, 127, 92, 81, 70, 75,
        208, 221, 202, 199, 228, 233, 254, 243, 184, 181, 162, 175, 140, 129, 150, 155,
        187, 182, 161, 172, 143, 130, 149, 152, 211, 222, 201, 196, 231, 234, 253, 240,
        107, 102, 113, 124, 95, 82, 69, 72, 3, 14, 25, 20, 55, 58, 45, 32,
        109, 96, 119, 122, 89, 84, 67, 78, 5, 8, 31, 18, 49, 60, 43, 38,
        189, 176, 167, 170, 137, 132, 147, 158, 213, 216, 207, 194, 225, 236, 251, 246,
        214, 219, 204, 193, 226, 239, 248, 245, 190, 179, 164, 169, 138, 135, 144, 157,
        6, 11, 28, 17, 50, 63, 40, 37, 110, 99, 116, 121, 90, 87, 64, 77,
        218, 215, 192, 205, 238, 227, 244, 249, 178, 191, 168, 165, 134, 139, 156, 145,
        10, 7, 16, 29, 62, 51, 36, 41, 98, 111, 120, 117, 86, 91, 76, 65,
        97, 108, 123, 118, 85, 88, 79, 66, 9, 4, 19, 30, 61, 48, 39, 42,
        177, 188, 171, 166, 133, 136, 159, 146, 217, 212, 195, 206, 237, 224, 247, 250,
        183, 186, 173, 160, 131, 142, 153, 148, 223, 210, 197, 200, 235, 230, 241, 252,
        103, 106, 125, 112, 83, 94, 73, 68, 15, 2, 21, 24, 59, 54, 33, 44,
        12, 1, 22, 27, 56, 53, 34, 47, 100, 105, 126, 115, 80, 93, 74, 71,
        220, 209, 198, 203, 232, 229, 242, 255, 180, 185, 174, 163, 128, 141, 154, 151
    ];

    static const ubyte[] x_0x0e = [
        0, 14, 28, 18, 56, 54, 36, 42, 112, 126, 108, 98, 72, 70, 84, 90,
        224, 238, 252, 242, 216, 214, 196, 202, 144, 158, 140, 130, 168, 166, 180, 186,
        219, 213, 199, 201, 227, 237, 255, 241, 171, 165, 183, 185, 147, 157, 143, 129,
        59, 53, 39, 41, 3, 13, 31, 17, 75, 69, 87, 89, 115, 125, 111, 97,
        173, 163, 177, 191, 149, 155, 137, 135, 221, 211, 193, 207, 229, 235, 249, 247,
        77, 67, 81, 95, 117, 123, 105, 103, 61, 51, 33, 47, 5, 11, 25, 23,
        118, 120, 106, 100, 78, 64, 82, 92, 6, 8, 26, 20, 62, 48, 34, 44,
        150, 152, 138, 132, 174, 160, 178, 188, 230, 232, 250, 244, 222, 208, 194, 204,
        65, 79, 93, 83, 121, 119, 101, 107, 49, 63, 45, 35, 9, 7, 21, 27,
        161, 175, 189, 179, 153, 151, 133, 139, 209, 223, 205, 195, 233, 231, 245, 251,
        154, 148, 134, 136, 162, 172, 190, 176, 234, 228, 246, 248, 210, 220, 206, 192,
        122, 116, 102, 104, 66, 76, 94, 80, 10, 4, 22, 24, 50, 60, 46, 32,
        236, 226, 240, 254, 212, 218, 200, 198, 156, 146, 128, 142, 164, 170, 184, 182,
        12, 2, 16, 30, 52, 58, 40, 38, 124, 114, 96, 110, 68, 74, 88, 86,
        55, 57, 43, 37, 15, 1, 19, 29, 71, 73, 91, 85, 127, 113, 99, 109,
        215, 217, 203, 197, 239, 225, 243, 253, 167, 169, 187, 181, 159, 145, 131, 141
    ];

    @property public const uint blockSize() 
    {
        return Nb*4;
    }

    public this(ubyte[4*Nk] k)
    {
        keyExpansion( k );
    }

    public static long subBytesTime;
    public static long shiftRowsTime;
    public static long mixColumnsTime;
    public static long addRoundKeyTime;

    public void reportTiming()
    {
        std.stdio.writeln("AES encrypt timings:");
        std.stdio.write("Sub Bytes: "); std.stdio.write(subBytesTime / 10000000.0); writeln(" seconds");
        std.stdio.write("Shift Rows: "); std.stdio.write(shiftRowsTime / 10000000.0); writeln(" seconds");
        std.stdio.write("Mix Columns: "); std.stdio.write(mixColumnsTime / 10000000.0); writeln(" seconds");
        std.stdio.write("Add Round Key: "); std.stdio.write(addRoundKeyTime / 10000000.0); writeln(" seconds");
    }

    public void encrypt(ubyte[] message, ref ubyte[] cipher)
    {
        // Shuffle around bytes to conform to Intel little endian standard
        // Possible to use sse instructions with 128 bit registers
        State state = cast(State) bytesToWords(reverseBytes(message));

        addRoundKey(state, key[0]);
        uint round = 0;
        while (round++ < Nr - 1)
        {
            subBytes(state);
            state = shiftRows(state);
            state = mixColumns(state);
            addRoundKey(state, key[round]);
        }
        subBytes(state);
        state = shiftRows(state);
        addRoundKey(state, key[round]);

        foreach (uint i, ubyte b; reverseBytes(wordsToBytes(state)))
            cipher[i] = b;
    }
 
    public void decrypt(ubyte[] cipher, ref ubyte[] message)
    {
        State state = cast(State) bytesToWords(reverseBytes(cipher));

        addRoundKey(state, key[Nr]);
        uint round = 0;
        for (round = Nr - 1; round > 0; --round)
        {
            state = invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, key[round]);
            state = invMixColumns(state);
        }
        state = invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, key[0]);

        foreach (uint i, ubyte b; reverseBytes(wordsToBytes(state)))
            message[i] = b;
    }

    private static void addRoundKey(ref State s, ref Key k)
    {
        long tStart = Clock.currStdTime();
        /*version(D_InlineAsm_X86)
        {
            auto state_ptr = s.ptr;
            auto key_ptr = k.ptr;
            asm
            {
                mov EAX, state_ptr;
                mov ECX, key_ptr;
                movupd XMM1, [EAX];
                movupd XMM2, [ECX];
                xorpd XMM1, XMM2;
                movupd [EAX], XMM1;
                mov state_ptr, EAX;
            }
        }
        else*/
        {
            foreach (uint i, ref uint n; s) n ^= k[i];
        }
        long tEnd = Clock.currStdTime();
        addRoundKeyTime += (tEnd - tStart);
    }

    unittest {
        State a = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
        State b = [0x00102030, 0x40506070, 0x8090a0b0, 0xc0d0e0f0];
        Key k   = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f];
        addRoundKey(a, k);
        assert(a == b, "AddRoundKey");
    }

    private static void subBytes(ref State s, ref const ubyte[] b = sbox)
    {
        long tStart = Clock.currStdTime();
        foreach (ref uint i; s) 
            i = b[i >> 24] << 24 | b[(i & 0x00ff0000) >> 16] << 16 | 
            b[(i & 0x0000ff00) >> 8] << 8 | b[i & 0x000000ff];
        
        long tEnd = Clock.currStdTime();
        subBytesTime += (tEnd - tStart);
    }

    private static void invSubBytes(ref State s)
    {
        subBytes(s, inv_sbox);
    }

    unittest
    {
        State a = [0x73744765, 0x63535465, 0x5d5b5672, 0x7b746f5d];
        State b = [0x8f92a04d, 0xfbed204d, 0x4c39b140, 0x2192a84c];
        State c = [0x73744765, 0x63535465, 0x5d5b5672, 0x7b746f5d];

        subBytes(a);
        assert(a == b, "SubBytes");

        invSubBytes(b);
        assert(b == c, "InvSubBytes");
    }

    private static State shiftRows(State s)
    {
        long tStart = Clock.currStdTime();
        State sp = [0, 0, 0, 0];
        foreach (uint i, uint n; s)
        {
            sp[(i + 3) % 4] ^= n & 0xff000000;
            sp[(i + 2) % 4] ^= n & 0x00ff0000;
            sp[(i + 1) % 4] ^= n & 0x0000ff00;
            sp[i % 4]       ^= n & 0x000000ff;
        }
        long tEnd = Clock.currStdTime();
        shiftRowsTime += (tEnd - tStart);
        return sp;
    }
    
    private static State invShiftRows(State s)
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

        assert(shiftRows(a) == b, "ShiftRows");
        assert(invShiftRows(a) == c, "InvShiftRows");
    }

    // Multiplication under GF(256)
    // Could perhaps do lookup for this? Needs benchmarking
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

    private static State mixColumns(State s)
    {
        long tStart = Clock.currStdTime();
        State sp = [0, 0, 0, 0];
        for (uint i = 0; i < 4; ++i)
        {
            ubyte a = (s[i] & 0x000000ff);
            ubyte b = (s[i] & 0x0000ff00) >> 8;
            ubyte c = (s[i] & 0x00ff0000) >> 16;
            ubyte d = (s[i] & 0xff000000) >>> 24;
            sp[i] |= x_0x02[a] ^ x_0x03[b] ^ c ^ d;
            sp[i] |= (a ^  x_0x02[b] ^ x_0x03[c] ^ d) << 8;
            sp[i] |= (a ^ b ^  x_0x02[c] ^ x_0x03[d]) << 16;
            sp[i] |= (x_0x03[a] ^ b ^ c ^  x_0x02[d]) << 24;
        }
        long tEnd = Clock.currStdTime();
        mixColumnsTime += (tEnd - tStart);

        return sp;
    }

    private static State invMixColumns(State s)
    {
        State sp = [0, 0, 0, 0];
        for (uint i = 0; i < 4; ++i)
        {
            ubyte a = (s[i] & 0x000000ff);
            ubyte b = (s[i] & 0x0000ff00) >> 8;
            ubyte c = (s[i] & 0x00ff0000) >> 16;
            ubyte d = (s[i] & 0xff000000) >>> 24;
            sp[i] |= x_0x0e[a] ^ x_0x0b[b] ^ x_0x0d[c] ^ x_0x09[d];
            sp[i] |= (x_0x09[a] ^ x_0x0e[b] ^ x_0x0b[c] ^ x_0x0d[d]) << 8;
            sp[i] |= (x_0x0d[a] ^ x_0x09[b] ^ x_0x0e[c] ^ x_0x0b[d]) << 16;
            sp[i] |= (x_0x0b[a] ^ x_0x0d[b] ^ x_0x09[c] ^ x_0x0e[d]) << 24;
        }
        return sp;
    }
/*
    unittest
    {
        // Print xtimes table
        foreach (ubyte b; cast(ubyte[])[0x02, 0x03, 0x09, 0x0b, 0x0d, 0x0e])
        {
            std.stdio.write(b);
            std.stdio.writeln("table = [");
            for (int i = 0; i < 256; ++i)
            {
                if (i % 16 == 0 && i != 0)
                    std.stdio.writeln();
                std.stdio.write(xtimes(b, cast(ubyte)i)); std.stdio.write(", ");
            }
            std.stdio.writeln("];");
        }
    }*/

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
        assert(mixColumns(a) == b, "MixColumns");

        State c = [0x8dcab9dc, 0x035006bc, 0x8f57161e, 0x00cafd8d];
        State d = [0xd635a667, 0x928b5eae, 0xeec9cc3b, 0xc55f5777];
        assert(invMixColumns(c) == d, "InvMixColumns");
    }

    private static uint subWord(uint w)
    {
        return sbox[(w & 0xff000000) >> 24] << 24 |
               sbox[(w & 0x00ff0000) >> 16] << 16 |
               sbox[(w & 0x0000ff00) >> 8] << 8 |
               sbox[(w & 0x000000ff)];
    }

    unittest
    {
        assert(subWord(0x73744765) == 0x8f92a04d);
    }

    private static uint rotWord(uint w)
    {
        return (w >> 8) | (w << 24);
    }

    unittest
    {
        assert(rotWord(0x3c4fcf09) == 0x093c4fcf);
    }

    private void keyExpansion(ubyte[4*Nk] k)
    {
        uint[Nb*(Nr+1)] w;

        // Round key constants
        static const uint[10] rCon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

        // First round key(s) is a copy of the original key (reverse bytes internally)
        // Still in reverse word order from xmm layout (to make indexing easy)
        uint i = 0;
        while (i < Nk)
        {
            w[i] = k[4*i] | k[4*i+1] << 8 | k[4*i+2] << 16 | k[4*i+3] << 24;
            i++;
        }

        uint tmp;
        i = Nk;
        while (i < Nb*(Nr+1))
        {
            tmp = w[i-1];
            if (i % Nk == 0)
                tmp = subWord(rotWord(tmp)) ^ rCon[i/Nk-1];
            static if (Nk > 6)
                if (i % Nk == 4)
                    tmp = subWord(tmp);
            w[i] = w[i - Nk] ^ tmp;
            ++i;
        }

        // Rotate back words (could remove this if we don't use Intel ordering)
        for (uint j = 0; j < Nr + 1; ++j)
            key[j] = [w[4*j+3], w[4*j+2], w[4*j+1], w[4*j]];
    }

    // Utility
    private static ubyte[4*Nb] reverseBytes(ubyte[] b)
    {
        ubyte[4*Nb] res;
        for (uint i = 0; i < 4*Nb; ++i)
            res[i] = b[4*Nb-1-i];
        return res;
    }

    private static uint[4] bytesToWords(ubyte[4*Nb] b)
    {
        uint[4] str;
        for (uint i = 0; i < 4; ++i)
            str[i] = b[4*i] << 24 | b[4*i+1] << 16 | b[4*i+2] << 8 | b[4*i+3];
        return str;
    }

    private static ubyte[4*Nb] wordsToBytes(uint[4] w)
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
}

// -- Debug stuff --

private static void printHex(uint round, string s, uint[] b)
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