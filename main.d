module main;

import crypto.hash.sha1;
import crypto.blockcipher.aes;
import crypto.mode.ecb;
import crypto.mode.cbc;
import crypto.mode.scheme;

import std.stdio, std.algorithm, std.getopt, std.stream, std.cstream, std.mmfile;
import std.datetime;

/***
 * Simple command line support for accessing functions.
 * Leaving out --in or --out will default to stdin and stdout.
 *
 * >crypto --hash sha1 -in <file>
 * >crypto --enc aes-128-ecb --in <file1> --out <file2> --key <key>
 * >crypto --dec aes-128-ecb --in <file2> --out <file1> --key <key>
 * >crypto --benchmark aes-128-ecb --in "test/bbt.avi" --out "test/bbt.avi.enc" --key 000102030405060708090a0b0c0d0e0f
*/

void execute(string[] args)
{
    string enc, dec, hash, benchmark, input, output, key;
    getopt(args,
           "enc", &enc,
           "dec", &dec,
           "hash", &hash,
           "benchmark", &benchmark,
           "in", &input,
           "out", &output,
	       "key", &key
    );

    // Initialize input/output streams to stdin/stdout
    Stream inStream = din;
    OutputStream outStream = dout;
    ulong inputFileLength = 0;
    if (input != null)
    {
        auto inputMemoryMap = new MmFile(input);
        inputFileLength = inputMemoryMap.length();
        inStream = new MmFileStream(inputMemoryMap);
    }
    if (output != null)
        outStream = new BufferedFile(output, FileMode.Out);
    
 
    // Encrypt
    if (enc != null)
    {
        switch (enc)
        {
            case "aes-128-ecb":
                auto k = parseHexString!(16)(key);
                auto ecb = new ECB(new AES128(k));
                ecb.encrypt(inStream, outStream);
                break;

            case "aes-128-cbc":
                auto k = parseHexString!(16)(key);
                auto iv = cast(ubyte[16]) x"00000000000000000000000000000000";
/*
                auto scheme  = new CBC(new AES128(k), iv, SymmetricScheme.Padding.None);
                auto cStream = new CipherStream(inStream, scheme);
                
                auto buf = new ubyte[16];
                while (cStream.read(buf) > 0)
                    outStream.write(cast(ubyte[])byteToHexString(buf));
                */
                break;

            default:
                writeln("Valid parameters for --enc: \naes-128-ecb");
        }
    }

    // Decrypt
    else if (dec != null)
    {

    }

    // Hash
    else if (hash != null)
    {
        switch (hash)
        {
            case "sha1":
                auto sha1 = new SHA1();
                while (!inStream.eof())
                    sha1.put(inStream.readLine());
                outStream.writeLine(sha1.digestHex());
                break;
            default:
               writeln("Valid parameters for --hash: \nsha1");
        }
    }

    // Benchmark
    else if (benchmark != null)
    {
        // Create memory mapped output file as well, need precalculated result size
        /*if (output != null)
        {
            auto paddingLength = 16L;
            auto outputMemoryMap = new MmFile(input, MmFile.Mode.readWriteNew, inputFileLength + paddingLength, null, 0);
            outStream = new MmFileStream(outputMemoryMap);
        }*/
        
        if (output == null)
        {
            uint paddingLength = 16;
            MemoryStream memOut = new MemoryStream();
            memOut.reserve(cast(uint)inputFileLength + paddingLength);
            outStream = memOut;
        }

        switch (benchmark)
        {
            case "aes-128-ecb":
                auto k = parseHexString!(16)(key);
                auto aes = new AES128(k);
                auto ecb = new ECB(aes);

                long tStart = Clock.currStdTime();
                ecb.encrypt(inStream, outStream);
                long tEnd = Clock.currStdTime();

                auto mb = inputFileLength/(1024.0*1024.0);
                auto sec = (tEnd - tStart) / 10000000.0;
                write("Duration: "); writeln(dur!"hnsecs"(tEnd - tStart));
                write("Throughput: "); write(mb / sec); writeln(" MB/s");
                break;

            case "speed-aes":
                auto blockCipher = new AES128(cast(ubyte[16]) x"63cab7040953d051cd60e0e7ba70e18c");
                auto message = new ubyte[16];
                auto outputBuffer = new ubyte[16];

                std.stdio.writeln("Running AES speed benchmark");

                int megaBytes = 10;
                int iterations = megaBytes*1024*1024 / 16;

                long tStart = Clock.currStdTime();

                for (int i = 0; i < iterations; ++i)
                    blockCipher.encrypt(message);

                long tEnd = Clock.currStdTime();
                long encryptTime = tEnd - tStart;

                writeln("Encryption time: ", encryptTime/10000000.0, " seconds");
                writeln("Throughput: ", megaBytes/(encryptTime/10000000.0), " MB/s");
                break;
            default:
                writeln("Valid parameters for --benchmark: \naes-128-ecb");
                break;
        }
    }

    // Invalid command
    else
    {
        writeln("Invalid command. Use --enc for encryption, --dec for decryption or --hash for hashing");
    }
}

ubyte[k] parseHexString(uint k)(string s)
if (k % 2 == 0)
{
    char[] hex = cast(char[]) s;
    ubyte[char] lookup;
    lookup['0'] = 0x00; lookup['1'] = 0x01; lookup['2'] = 0x02; lookup['3'] = 0x03; lookup['4'] = 0x04; 
    lookup['5'] = 0x05; lookup['6'] = 0x06; lookup['7'] = 0x07; lookup['8'] = 0x08; lookup['9'] = 0x09;
    lookup['a'] = 0x0a; lookup['b'] = 0x0b; lookup['c'] = 0x0c; lookup['d'] = 0x0d; lookup['e'] = 0x0e; lookup['f'] = 0x0f;
    ubyte[k] res = 0;
    for (uint i = 0; i < hex.length; i += 2)
    {
        char a = hex[i], b = hex[i+1];
        if (!std.ascii.isHexDigit(a) || !std.ascii.isHexDigit(b))
            throw new Exception("Input not hexadecimal, "~s);
        res[i/2] = cast(ubyte) (lookup[a] << 4 | lookup[b]);
    }
    return res;
}


int main(string[] argv)
{

    try
    {
        execute(argv);
    }
    catch (Exception e)
    {
        //writeln("Bad input");
        //writeln(e);
        //import crypto.asymmetric.rsa;
        //rsaMain();
    }

    //std.process.system("pause");
	return 0;
}
