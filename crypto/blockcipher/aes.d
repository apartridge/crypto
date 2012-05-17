module crypto.blockcipher.aes;

import std.stdio, std.bitmanip;
import std.datetime;


public interface BlockCipher
{
    public void encrypt(ref ubyte[] message);
    public void decrypt(ref ubyte[] cipher);

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
        auto key     = cast(ubyte[16]) x"000102030405060708090a0b0c0d0e0f";
        auto message = cast(ubyte[16]) x"00112233445566778899aabbccddeeff";
        auto cipher  = cast(ubyte[16]) x"69c4e0d86a7b0430d8cdb78070b4c55a";
        ubyte[] buffer = message.dup;

        auto aes = new AES128(key);

        aes.encrypt(buffer);
        assert(buffer == cipher, byteToHexString(buffer));

        aes.decrypt(buffer);
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
        ubyte[] buffer = message.dup;

        auto aes = new AES192(key);

        aes.encrypt(buffer);
        assert(buffer == cipher);

        aes.decrypt(buffer);
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
        ubyte[] buffer = message.dup;

        auto aes = new AES256(key);

        aes.encrypt(buffer);
        assert(buffer == cipher);

        aes.decrypt(buffer);
        assert(buffer == message);
    }
}

abstract class AES(uint Nb, uint Nk, uint Nr)
if ((Nb == 4 && Nk == 4 && Nr == 10) || 
    (Nb == 4 && Nk == 6 && Nr == 12) ||
    (Nb == 4 && Nk == 8 && Nr == 14)) : BlockCipher
{
    alias uint[Nb] Key;

    uint[Nb*(Nr+1)] w;

    union State
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
    public static long copyTime;

    public void reportTiming()
    {
        std.stdio.writeln("AES encrypt timings:");
        std.stdio.write("Sub Bytes: "); std.stdio.write(subBytesTime / 10000000.0); writeln(" seconds");
        std.stdio.write("Shift Rows: "); std.stdio.write(shiftRowsTime / 10000000.0); writeln(" seconds");
        std.stdio.write("Mix Columns: "); std.stdio.write(mixColumnsTime / 10000000.0); writeln(" seconds");
        std.stdio.write("Add Round Key: "); std.stdio.write(addRoundKeyTime / 10000000.0); writeln(" seconds");
        std.stdio.write("Copy overhead: "); std.stdio.write(copyTime / 10000000.0); writeln(" seconds");
    }

    public void encrypt(ref ubyte[] message)
    {
        long tStart = Clock.currStdTime();
        State state;
        state.bytes = message;
        long tEnd = Clock.currStdTime();
        copyTime += (tEnd - tStart);

        //std.stdio.writeln(wordToString(0x00112233));
        //std.stdio.writeln(byteToHexString(state.bytes));
        //printHex(0, "input", state.bytes);

        addRoundKey(state, w[0 .. Nb]); // key[0]
        //printHex(0, "k_sch", w[0 .. Nb]);
        //printHex(0, "start", state.bytes);

        uint round = 0;
        while (round++ < Nr - 1)
        {
            subBytes(state);
            //printHex(round, "s_box", state.bytes);

            shiftRows(state);
            //printHex(round, "s_row", state.bytes);

            mixColumns(state);
            //printHex(round, "m_col", state.bytes);
            //printHex(round, "k_sch", w[round*Nb .. (round+1)*Nb]);

            addRoundKey(state, w[round*Nb .. (round+1)*Nb]); //key[round]
            //printHex(round, "start", state.bytes);

        }
        subBytes(state);
        //printHex(round, "s_box", state.bytes);

        shiftRows(state);
        //printHex(round, "s_row", state.bytes);
        //printHex(round, "k_sch", w[Nr*Nb .. (Nr+1)*Nb]);

        addRoundKey(state, w[Nr*Nb .. (Nr+1)*Nb]); // key[round]
        //printHex(round, "output", state.bytes);

        tStart = Clock.currStdTime();
        message[0 .. state.bytes.length] = state.bytes;
        tEnd = Clock.currStdTime();
        copyTime += (tEnd - tStart);
    }

    public void decrypt(ref ubyte[] cipher)
    {
        State state;
        state.bytes = cipher[0 .. 16];
        
        addRoundKey(state, w[Nr*Nb .. (Nr+1)*Nb]);

        for (int round = Nr - 1; round > 0; --round)
        {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, w[round*Nb .. (round+1)*Nb]);
            invMixColumns(state);
        }
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, w[0 .. Nb]);

        cipher[0 .. state.bytes.length] = state.bytes;
    }

    private static void addRoundKey(ref State s, ref uint[] k)
    {
        long tStart = Clock.currStdTime();

        for (int i = 0; i < Nb; ++i)
            s.words[i] ^= k[i];

        long tEnd = Clock.currStdTime();
        addRoundKeyTime += (tEnd - tStart);
    }

    unittest 
    {
        State a, b;
        a.bytes = cast(ubyte[16]) x"00112233445566778899aabbccddeeff";
        b.bytes = cast(ubyte[16]) x"00102030405060708090a0b0c0d0e0f0";
        uint[] key = [0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c];
        addRoundKey(a, key);
        assert(a == b);
    }

    private static void subBytes(ref State s, ref const ubyte[] b = sbox)
    {
        long tStart = Clock.currStdTime();
        for (uint i = 0; i < Nb*4; ++i)
        {
            s.bytes[i] = b[s.bytes[i]];
        }
        long tEnd = Clock.currStdTime();
        subBytesTime += (tEnd - tStart);
    }

    private static void invSubBytes(ref State s)
    {
        subBytes(s, inv_sbox);
    }

    unittest
    {
        State a, b, c;
        a.bytes = cast(ubyte[16]) x"73744765635354655d5b56727b746f5d";
        b.bytes = cast(ubyte[16]) x"8f92a04dfbed204d4c39b1402192a84c";
        c.bytes = cast(ubyte[16]) x"73744765635354655d5b56727b746f5d";

        subBytes(a);
        assert(a == b);

        invSubBytes(b);
        assert(b == c);
    }

    /*
     * The three last rows (columns in memory layout(!)) are rotated 1, 2, 3 steps
     * NB: This works for little-endian. Need special case for big endian
     */
    private static void shiftRows(ref State s)
    {
        long tStart = Clock.currStdTime();

        ubyte tmp = s.bytes[0x1];
        s.bytes[0x1] = s.bytes[0x5];
        s.bytes[0x5] = s.bytes[0x9];
        s.bytes[0x9] = s.bytes[0xd];
        s.bytes[0xd] = tmp;

        tmp = s.bytes[0x2];
        s.bytes[0x2] = s.bytes[0xa];
        s.bytes[0xa] = tmp;
        tmp = s.bytes[0x6];
        s.bytes[0x6] = s.bytes[0xe];
        s.bytes[0xe] = tmp;

        tmp = s.bytes[0x3];
        s.bytes[0x3] = s.bytes[0xf];
        s.bytes[0xf] = s.bytes[0xb];
        s.bytes[0xb] = s.bytes[0x7];
        s.bytes[0x7] = tmp;

        long tEnd = Clock.currStdTime();
        shiftRowsTime += (tEnd - tStart);
    }

    unittest
    {
        State a, b;
        a.bytes = cast(ubyte[16]) x"63cab7040953d051cd60e0e7ba70e18c";
        b.bytes = cast(ubyte[16]) x"6353e08c0960e104cd70b751bacad0e7";
        shiftRows(a);
        assert(a == b);
    }

    private static void invShiftRows(ref State s)
    {
        ubyte tmp = s.bytes[0xd];
        s.bytes[0xd] = s.bytes[0x9];
        s.bytes[0x9] = s.bytes[0x5];
        s.bytes[0x5] = s.bytes[0x1];
        s.bytes[0x1] = tmp;

        tmp = s.bytes[0x2];
        s.bytes[0x2] = s.bytes[0xa];
        s.bytes[0xa] = tmp;
        tmp = s.bytes[0x6];
        s.bytes[0x6] = s.bytes[0xe];
        s.bytes[0xe] = tmp;

        tmp = s.bytes[0x3];
        s.bytes[0x3] = s.bytes[0x7];
        s.bytes[0x7] = s.bytes[0xb];
        s.bytes[0xb] = s.bytes[0xf];
        s.bytes[0xf] = tmp;
    }

    unittest
    {
        State a, b;
        a.bytes = cast(ubyte[16]) x"7ad5fda789ef4e272bca100b3d9ff59f";
        b.bytes = cast(ubyte[16]) x"7a9f102789d5f50b2beffd9f3dca4ea7";
        invShiftRows(a);
        assert(a == b);
    }

    private static void mixColumns(ref State s)
    {
        long tStart = Clock.currStdTime();

        for (int col = 0; col < 4; ++col)
        {
            ubyte a = s.bytes[col*4];
            ubyte b = s.bytes[col*4+1];
            ubyte c = s.bytes[col*4+2];
            ubyte d = s.bytes[col*4+3];
            s.bytes[col*4]   = x_0x02[a] ^ x_0x03[b] ^ c ^ d;
            s.bytes[col*4+1] = a ^ x_0x02[b] ^ x_0x03[c] ^ d;
            s.bytes[col*4+2] = a ^ b ^ x_0x02[c] ^ x_0x03[d];
            s.bytes[col*4+3] = x_0x03[a] ^ b ^ c ^  x_0x02[d];
        }

        long tEnd = Clock.currStdTime();
        mixColumnsTime += (tEnd - tStart);
    }

    private static void invMixColumns(ref State s)
    {
        for (uint col = 0; col < 4; ++col)
        {
            ubyte a = s.bytes[col*4];
            ubyte b = s.bytes[col*4+1];
            ubyte c = s.bytes[col*4+2];
            ubyte d = s.bytes[col*4+3];
            s.bytes[col*4]   = x_0x0e[a] ^ x_0x0b[b] ^ x_0x0d[c] ^ x_0x09[d];
            s.bytes[col*4+1] = x_0x09[a] ^ x_0x0e[b] ^ x_0x0b[c] ^ x_0x0d[d];
            s.bytes[col*4+2] = x_0x0d[a] ^ x_0x09[b] ^ x_0x0e[c] ^ x_0x0b[d];
            s.bytes[col*4+3] = x_0x0b[a] ^ x_0x0d[b] ^ x_0x09[c] ^ x_0x0e[d];
        }
    }

    unittest 
    {
        State a, b;
        a.bytes = cast(ubyte[16]) x"6353e08c0960e104cd70b751bacad0e7";
        b.bytes = cast(ubyte[16]) x"5f72641557f5bc92f7be3b291db9f91a";
        mixColumns(a);
        assert(a == b);

        State c, d;
        c.bytes = cast(ubyte[16]) x"fde3bad205e5d0d73547964ef1fe37f1";
        d.bytes = cast(ubyte[16]) x"2d7e86a339d9393ee6570a1101904e16";
        invMixColumns(c);
        assert(c == d);
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
        static const uint[10] rCon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

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
    }

    unittest
    {
        // TODO 
    }
}


// -- Debug stuff --

private static void printHex(uint round, string s, ubyte[] b)
{
    write("round["); write(round); write("]."~s~"\t");
    write(byteToHexString(b));
    //for (uint i = 0; i < b.length; ++i)
    //    write(wordToString(b[i]));
    writeln("");
}

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

void AESspeedBenchmark()
{
    auto blockCipher = new AES128(cast(ubyte[16]) x"63cab7040953d051cd60e0e7ba70e18c");
    auto message = new ubyte[16];
    auto outputBuffer = new ubyte[16];

    std.stdio.writeln("Running AES benchmark");

    int megaBytes = 10;
    int iterations = megaBytes*1024*1024 / 16;

    long tStart = Clock.currStdTime();

    for (int i = 0; i < iterations; ++i)
    {
        blockCipher.encrypt(message);
    }

    long tEnd = Clock.currStdTime();
    long encryptTime = tEnd - tStart;

    write("Encryption time: "); write(encryptTime / 10000000.0); writeln(" seconds");
    blockCipher.reportTiming();
    std.stdio.write("Throughput: "); std.stdio.write(megaBytes / (encryptTime / 10000000.0)); writeln(" MB/s");
}

// -- End debug stuff --