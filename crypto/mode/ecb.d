module crypto.mode.ecb;

import crypto.blockcipher.aes;
import crypto.blockcipher.blockcipher;
import std.file, std.stdio, std.array, std.stream;
import std.datetime;

public interface SymmetricScheme
{
    public void encrypt(InputStream input, OutputStream output);
    public void decrypt(InputStream input, OutputStream output);
}

class ECB : SymmetricScheme
{
    private BlockCipher blockCipher;

    this(BlockCipher bc)
    {
        blockCipher = bc;
    }

    public void encrypt(InputStream input, OutputStream output)
    {
        const uint blockSize = blockCipher.blockSize();
        ubyte[] buffer = new ubyte[blockSize];
        uint bytesRead;
        long encryptTime = 0;

        // Encrypt all whole blocks
        while ((bytesRead = input.read(buffer)) == blockSize)
        {
            long tStart = Clock.currStdTime();
            blockCipher.encrypt(buffer);
            long tEnd = Clock.currStdTime();
            encryptTime += (tEnd - tStart);
            output.write(buffer);
        }

        // Pad last block with number of padding bytes (PKCS#5)
        ubyte paddingByte = cast(ubyte)(blockSize - bytesRead);
        for (uint i = bytesRead; i < blockSize; ++i)
            buffer[i] = paddingByte;
        blockCipher.encrypt(buffer);
        output.write(buffer);

        //write("Encryption time: "); write(encryptTime / 10000000.0); writeln(" seconds");
        //blockCipher.reportTiming();
    }
    
    public void decrypt(InputStream input, OutputStream output)
    {
        const uint blockSize = blockCipher.blockSize();
        ubyte[] buffer = new ubyte[blockSize];

        while (input.read(buffer))
        {
            blockCipher.decrypt(buffer);

            // Remove padding in last block
            if (input.eof())
            {
                buffer = buffer[0 .. (blockSize-buffer[blockSize-1])];
            }
            output.write(buffer);
        }
    }

    unittest
    {
        auto cipher = new AES128(cast(ubyte[16]) x"000102030405060708090a0b0c0d0e0f");
        auto scheme = new ECB(cipher);

        auto plaintext  = cast(ubyte[]) "The quick brown fox jumped over the lazy dog";
        auto ciphertext = cast(ubyte[]) x"f7021c01de43c8147cd2477a7eba55b3 2a2fd906badb2adf811766d2aeb5cdfd 3fbc811e6a3361dadde672fad4bf4ad4";
        
        // Encrypt
        auto inputBuffer = new MemoryStream(plaintext);
        auto outputBuffer = new MemoryStream();

        scheme.encrypt(inputBuffer, outputBuffer);
        auto res = cast(ubyte[]) (outputBuffer.toString());
        assert( res == ciphertext );
        
        // Decrypt
        inputBuffer = new MemoryStream(ciphertext);
        outputBuffer = new MemoryStream();

        scheme.decrypt(inputBuffer, outputBuffer);
        res = cast(ubyte[]) (outputBuffer.toString());
        assert( res == plaintext );
    }
}
