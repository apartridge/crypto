module crypto.mode.ecb;

import crypto.blockcipher.aes;
import std.file, std.stdio, std.array;

class ECB
{
    private AES128 blockcipher;

    this(AES128 cipher)
    {
        blockcipher = cipher;
    }

    private void transform(string inputFilename, string outputFilename, bool encrypt = true)
    {
        ubyte[16] padding = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        const uint blockSize = 16; //blockcipher.blockSize();

        // Wipe file
        std.file.write(outputFilename, "");

        // Read input file (todo: stream or something, not keep
        // everything in memory)
        auto bytes = cast(ubyte[]) read(inputFilename);

        ubyte[blockSize] block;
        uint count = 0;
        bool done = false;

        // Loop through each block
        while ((bytes.length - count) >= blockSize)
        {
            block = bytes[count .. count+blockSize];
            ubyte[] cipher;
            if (encrypt)
                cipher = blockcipher.encrypt(block);
            else
                cipher = blockcipher.decrypt(block);
            std.file.append(outputFilename, cipher);
            count += blockSize;
        }

        // Pad the last block
        if ((bytes.length - count) > 0)
        {
            block = bytes[count .. $] ~ padding[0 .. blockSize-(bytes.length-count)];
            ubyte[] cipher;
            if (encrypt)
                cipher = blockcipher.encrypt(block);
            else
                cipher = blockcipher.decrypt(block);
            std.file.append(outputFilename, cipher);
        }
    }

    public void encryptFile(string inputFilename, string outputFilename)
    {
        transform(inputFilename, outputFilename);
    }

    public void decryptFile(string inputFilename, string outputFilename)
    {
        transform(inputFilename, outputFilename, false);
    }
}
