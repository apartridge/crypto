module crypto.mode.cbc;

import crypto.mode.scheme;
import crypto.blockcipher.aes;
import crypto.blockcipher.blockcipher;

import std.file, std.stdio, std.array, std.stream, std.datetime;
import std.range;

class CBC : SymmetricScheme
{
    this(BlockCipher cipher, ubyte[] iv, Padding pad = Padding.None)
    {
        super(cipher, pad);
        this.iv = iv.dup;
        assert(iv.length == cipher.blockSize());
    }

    override void encrypt(InputStream input, OutputStream output)
    {
        long tStart = Clock.currStdTime();

        const size_t blockSize = cipher.blockSize();
        size_t bytesRead;
        ubyte[] buffer  = new ubyte[blockSize];
        ubyte[] lastBlock = iv.dup;

        // Write IV
        output.write(iv);

        // Encrypt all whole blocks
        while ((bytesRead = input.read(buffer)) == blockSize)
        {
            for (uint i = 0; i < blockSize; ++i)
                buffer[i] ^= lastBlock[i];
            cipher.encrypt(buffer);
            output.write(buffer);

            lastBlock[] = buffer[0 .. blockSize];
        }

        // Pad last block
        switch (padding)
        {
            case Padding.None:
                break;

            case Padding.PKCS5:
                ubyte paddingByte = cast(ubyte)(blockSize - bytesRead);
                for (uint i = bytesRead; i < blockSize; ++i)
                    buffer[i] = paddingByte;
                cipher.encrypt(buffer);
                output.write(buffer);
                break;

            default:
                break;
        }

        long tEnd = Clock.currStdTime();
        //writeln("Encryption time (CBC): ", (tEnd - tStart)/10000000.0, " seconds");
    }
    
    override void decrypt(InputStream input, OutputStream output)
    {
        const size_t blockSize = cipher.blockSize();
        size_t bytesRead;
        ubyte[] buffer = new ubyte[blockSize];
        
        // Read IV
        ubyte[] lastBlock = new ubyte[blockSize];
        if (input.read(lastBlock) != blockSize)
            throw new Exception("Invalid size");

        // Decrypt blocks
        while ((bytesRead = input.read(buffer)) == blockSize)
        {
            ubyte[] tmp = lastBlock.dup;
            lastBlock[] = buffer[0 .. blockSize];

            cipher.decrypt(buffer);
            for (size_t i = 0; i < blockSize; ++i)
                buffer[i] ^= tmp[i];

            if (!input.eof())
                output.write(buffer);
        }
    
        // Remove padding from last block
        switch (padding)
        {
            case Padding.None:
                output.write(buffer);
                break;

            case Padding.PKCS5:
                size_t messageBytes = blockSize - cast(ubyte)(buffer[blockSize-1]);
                //writeln("Last block: ", byteToHexString(buffer));
                assert(messageBytes >= 0 && messageBytes < blockSize);
                output.write(buffer[0 .. messageBytes]);
                break;

            default:
                break;
        }
    }
    
    unittest
    {
        auto 
        plaintext = [
            cast(ubyte[]) x"00112233 44556677 8899aabb ccddeeff 00112233 44556677 8899aabb ccddeeff", // Nopad
            cast(ubyte[]) x"00112233 44556677 8899aabb ccddeeff 00112233 44556677 8899aabb ccddeeff 37" // PKCS5
        ],
        ciphertext = [
            cast(ubyte[]) x"00000000 00000000 00000000 00000000 69c4e0d8 6a7b0430 d8cdb780 70b4c55a 7d7786be 32d059a6 0ca8021a 65dd9f09", // Nopad
            cast(ubyte[]) x"00000000 00000000 00000000 00000000 69c4e0d8 6a7b0430 d8cdb780 70b4c55a 7d7786be 32d059a6 0ca8021a 65dd9f09 b503c779 12c4f75b 88a570aa 03738902"
        ];

        auto cipher = new AES128(cast(ubyte[16]) x"000102030405060708090a0b0c0d0e0f");
        auto scheme = new CBC(cipher, new ubyte[16], SymmetricScheme.Padding.None);

        // Encrypt
        auto inputBuffer = new MemoryStream(plaintext[0]);
        auto outputBuffer = new MemoryStream();

        scheme.encrypt(inputBuffer, outputBuffer);
        auto res = cast(ubyte[]) (outputBuffer.toString());
        //writeln(byteToHexString(res));
        assert( res == ciphertext[0], byteToHexString(res) );

        // Decrypt
        inputBuffer = new MemoryStream(ciphertext[0]);
        outputBuffer = new MemoryStream();

        scheme.decrypt(inputBuffer, outputBuffer);
        res = cast(ubyte[]) (outputBuffer.toString());
        //writeln("Decrypted: ", byteToHexString(res));
        assert( res == plaintext[0], byteToHexString(res) );
    }
}