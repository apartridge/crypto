module crypto.asymmetric.rsa;

/*
// Implements PKCS #1 V2.1: RSA CRYPTOGRAPHY STANDARD (June 14, 2002)
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf
*/

import crypto.prng.d;
import crypto.prng.insecure;
import crypto.asymmetric.bigint;
import crypto.hash.sha1;

import std.stdio, std.traits, std.datetime, std.conv : to;

version(unittest)
{
    private class AlwaysOnePRNG : PRNG
    {
        override void nextBytes(ubyte[] buffer)
        {
            buffer[] = 1;
        }
    }
}

struct RSAKeyPair
{
    public BigInt N;
    public BigInt e;
    public BigInt d;

    public BigInt p;
    public BigInt q;

    public BigInt dp;
    public BigInt dq;
    public BigInt qinv;

    private bool _hasPrivateKey = false;
    private bool _hasCRTDetails = false;
    private uint _bitLength;

    public @property uint bitLength()
    {
        return _bitLength;
    }

    public @property bool hasPrivateKey()
    {
        return _hasPrivateKey;
    }

    public @property bool hasCRTDetails()
    {
        return _hasCRTDetails;
    }

    this(uint bitLength, BigInt N, BigInt e, BigInt d, BigInt p, BigInt q)
    {
        this._bitLength = bitLength;

        this.N = N;
        this.e = e;
        this.d = d;
        this.p = p;
        this.q = q;

        this._hasPrivateKey = true;

        // Find dp, dq and qinv

        this.dp = d % (p-1);
        this.dq = d % (q-1);
        this.qinv = RSAKeyGenerator.modularMultiplicativeInverse(q, p);

        this._hasCRTDetails = true; // some bug with CRT implementation. 

        /*writeln(d, " % ", p-1, " is ", dp);
        writeln(d, " % ", q-1, " is ", dq);
        writeln(q,"^-1 is ", qinv, " mod ", p);*/

    }
}

/* 
* Generates a 
*/

class RSAKeyGenerator
{
    private static auto ZERO = BigInt("0");
    private static auto ONE = BigInt("0x1");
    private static auto TWO = BigInt("0x2");

    private uint bitLength;
    private IRandom randomGenerator;

    this(IRandom randomGenerator, uint bitLength)
    in
    {
        assert(bitLength % 8 == 0, "Bitlength is required to be a multiple of 8.");
    }
    body
    {
        this.bitLength = bitLength;
        this.randomGenerator = randomGenerator;
    }

    public RSAKeyPair newKeyPair()
    {
        BigInt e = 17;

        BigInt p, q;
        do
        {
            p = newRandomPrime(e);
            q = newRandomPrime(e);
        }
        while(p == q);

        BigInt N = p*q;
        BigInt totient = (p-ONE)*(q-ONE);


        BigInt d = modularMultiplicativeInverse(e, totient);

        RSAKeyPair keypair = RSAKeyPair (bitLength, N, e, d, p, q);
        return keypair;

    }

    /*
    // Returns a random prime with length bitlength/2 to be used
    // as a factor in N. p-1 must be coprime to BigInt e. This is checked
    // as p-1 != 0 mod e, or p != 1 mod e.
    */

    private BigInt newRandomPrime(BigInt e)
    {
        int tries = 0;
        while(++tries)
        {
            BigInt randomCandidate = randomBigInt(bitLength/2, true);

            if(randomCandidate % e != ONE && isProbablePrime(randomCandidate))
            {
                //writeln("Found a probable prime of bitlength ",bitLength/2," with ", tries, " guesses of a prime.\n", randomCandidate);
                return randomCandidate;
            }
        }
        assert(0);
    }

    // Checks if this prime candidate is a (very) possible prime

    private bool isProbablePrime(BigInt randomCandidate)
    {
        if(randomCandidate % 3 == 0 || randomCandidate % 5 == 0 || randomCandidate % 7 == 0 
           || randomCandidate % 11 == 0 || randomCandidate % 13 == 0 || randomCandidate % 17 == 0)
        {
            return false;
        }

        return millerRabinPrimeTest(randomCandidate, 40); // Yields a probability 4^-X false positives
    }

    // Check this random number with the Miller Rabin Test, with a given number of tries
    // Returns true if it is a possible prime, false if it is a composite

    private bool millerRabinPrimeTest(BigInt randomCandidate, uint tries)
    {

        BigInt rcmin1 = randomCandidate - 1;
        ulong s = rcmin1.trailingZeroBits;
        BigInt d = rcmin1 >> s;

        for(uint i = 0; i < tries; i++)
        {
            BigInt apick;
            do
            {
                apick = randomBigInt(rcmin1.bitLength);
            }
            while(apick >= rcmin1 || apick < 2);

            BigInt x = apick.powMod(d, randomCandidate);

            if(x == ONE || x == rcmin1)
            {
                continue;
            }

            bool do_continue = false;

            for(int ri = 1; ri < s; ri++)
            {
                x = apick.powMod(TWO, randomCandidate);
                if(x == ONE)
                {
                    return false;
                }
                else if(x == rcmin1)
                {
                    do_continue = true;
                    break;
                }
            }

            if(do_continue)
            {
                continue;
            }

            return false;
        }

        return true;
    }

    /*
    // Returns a random BigInt of bit length n
    // If odd is set, returned number will be odd/uneven. Useful for prime generation
    // If SetHighBit, it will return a BigInt [2^^n-1, 2^^(n-1)]
    */

    private BigInt randomBigInt(uint nbits, bool odd = false, bool setHighBit = false)
    {
        // Need one extra byte if bits not evenly divisible by 8
        ubyte[] randomCandidateBytes = new ubyte[ ((nbits & 7) == 0) ? (nbits/8) : (nbits/8 + 1)];
        randomGenerator.nextBytes(randomCandidateBytes);      

        if(setHighBit) // Make sure sufficiently large
        {
            randomCandidateBytes[0] |= 0x80;
        }

        if((nbits & 7) != 0)
        {
            randomCandidateBytes[0] = randomCandidateBytes[0]  >> (8 - nbits & 7);
        }

        if(odd)
        {
            randomCandidateBytes[$-1] |= 0x01;
        }

        return BigInt(randomCandidateBytes);

    }

    unittest
    {
        RSAKeyGenerator a = new RSAKeyGenerator ( new InsecurePRNG, 8);
        BigInt random = a.randomBigInt(1, true);
        assert(random == 1);
        random = a.randomBigInt(6, false, true);
        assert(random >= 32 && random <= 63, "The random number does not fall withing a valid range.");
    }

    /*
    // Returns a^-1 mod m
    */
    private static BigInt modularMultiplicativeInverse(BigInt a, BigInt m)
    {
        BigInt inv = extendedEuclidX(a, m);
        if(inv < 0)
        {
            inv += m;
        }

        return inv;
    }

    /* unittest
    {
    assert(RSAKeyGenerator.modularMultiplicativeInverse(BigInt("3"), BigInt("11")) == BigInt("4"),
    "Modular Multiplicative Inverse simplest case failed.");
    assert(RSAKeyGenerator.modularMultiplicativeInverse(BigInt("17"), BigInt("3120")) == BigInt("2753"), 
    "Modular Multiplicative Inverse case 2 failed.");
    assert(RSAKeyGenerator.modularMultiplicativeInverse(BigInt("7136894511284418597546878456"), BigInt("589743216878943213987498637986541")) 
    == BigInt("28667610335819904460119453172384"), "Modular Multiplicative Inverse large case failed.");
    }*/

    /*
    // Solves ax + by = gcd(a, b) and returns x
    */

    private static BigInt extendedEuclidX(BigInt a, BigInt b)
    {
        BigInt x = "0";
        BigInt lastx = "1";

        /*BigInt y = "1";
        BigInt lasty = "0";*/

        while( b != ZERO)
        {
            BigInt quotient = a / b;
            BigInt temp = a % b;
            a = b;
            b = temp;




            temp = x;

            x = lastx - (quotient*x);
            lastx = temp;


            /*temp = y;
            y = lasty - (quotient*y);
            lasty = temp;*/

            /*writeln("b ", b);
            writeln("lastx ", b);*/


        }

        // writeln("GCD = ", (x*a) + (y*b));

        return lastx;
    }

    /*unittest
    {
    assert(RSAKeyGenerator.extendedEuclidX(BigInt("4864"), BigInt("3458")) == BigInt("32"), 
    "Inverse Extended Euclid simple case failed.");
    assert(RSAKeyGenerator.extendedEuclidX(BigInt("45004045"), BigInt("2321544121")) == BigInt("-783915036"), 
    "Inverse Extended Euclid case 2 failed.");
    }*/

}

/* 
* Handles RSA encryption and decryption.
*/

class RSA
{
    public enum PaddingMode {OAEP, NO_PADDING};

    private RSAKeyPair keypair;
    private PaddingMode padding;
    private IRandom random;

    public this(RSAKeyPair keypair, IRandom random, PaddingMode padding = PaddingMode.OAEP)
    {
        this.keypair = keypair;
        this.padding = padding;
        this.random = random;
    }

    /*
    // Encryption
    */

    public ubyte[] encrypt(T)(T text) if (isArray!T) // todo endian problems
    {
        ubyte[] msg = cast(ubyte[]) text;

        switch(padding)
        {
            case PaddingMode.OAEP:
                return encryptOAEP(msg);
            case PaddingMode.NO_PADDING:
                return encryptPlain(msg);
            default:
                throw new Exception("Unrecognized padding mode for RSA.encrypt().");
        }
    }

    private ubyte[] encryptPlain(ubyte[] message)
    {
        BigInt m = BigInt(message);
        BigInt result = m.powMod(keypair.e, keypair.N);

        return result.toUbyteArray();
    }

    /*
    // Decryption
    */

    public ubyte[] decrypt(T)(T text) if (isArray!T) // todo endian problems
    {
        ubyte[] msg = cast(ubyte[]) text;

        switch(padding)
        {
            case PaddingMode.OAEP:
                return decryptOAEP(msg);
            case PaddingMode.NO_PADDING:
                return decryptPlain(msg);
            default:
                throw new Exception("Unrecognized padding mode for RSA.decrypt().");
        }
    }

    private ubyte[] decryptPlain(ubyte[] text)
    {
        BigInt temp = BigInt(text);

        if(keypair.hasCRTDetails) // Use the Chinese Remainder Theorem to speed up
        {
            BigInt m1 = temp.powMod(keypair.dp, keypair.p);
            BigInt m2 = temp.powMod(keypair.dq, keypair.q);
            BigInt h = (keypair.qinv*(m1-m2)) % keypair.p;
            if(h < 0)
            {
                h += keypair.p;
            }
            temp = m2 + h*keypair.q;
        }
        else
        {
            temp = temp.powMod(keypair.d, keypair.N);
        }

        return temp.toUbyteArrayDim(keypair.bitLength >> 3);

    }

    /*
    // OAEP Encryption Scheme
    // Implemented following the details in PKCS#1 2.2
    // The messagePadded array is transformed in the following way using the Mask Generation Function 
    // 1) [0 Seed Hash PS 1 M ] where PS is enough zeros to fill it up
    // 2) [0 Seed XOR(dbmask, Hash PS 1 M)] where dbmask = MGF(seed)
    // 3) [0 XOR(Seed, seedmask) XOR(dbmask, Hash PS 1 M)] where seedmask = MGF(XOR(dbmask, Hash PS 1 M))
    // This is the padded message that's encrypted using plain RSA.
    */

    private ubyte[] encryptOAEP(T = SHA1)(ubyte[] message)
    {
        ubyte[] padded_message = padOAEP(new T, message);
        //writeln("padOAEP Padded Message ", padded_message.length, " \n", padded_message);
        return this.encryptPlain(padded_message);
    }

    private ubyte[] padOAEP(Hash hashfn, ubyte[] message)
    {
        const ubyte[] label = [];

        uint hashLength = hashfn.digestBytes;
        int maxlengthBytes = (keypair.bitLength>>3) - 2*hashLength - 2;

        if(maxlengthBytes <= 0)
        {
            throw new Exception("The RSA modulus length " ~ to!string(keypair.bitLength>>3) ~ " bytes is too small to encrypt with OAEP padding."
                                " Add at least " ~ to!string(-maxlengthBytes + 1)~ " bytes to the modulus in order to encrypt one byte of data.");
        }

        if(message.length > maxlengthBytes)
        {
            throw new Exception("The message is too big. " ~ to!string(message.length) ~ " has to be less than " ~ to!string(maxlengthBytes) ~ ".");
        }

        // We have two slices into messagePadded for clean code
        // messagePadded = 0 ~ maskedSeed ~ maskedDb
        ubyte[] messagePadded = new ubyte[keypair.bitLength>>3];
        ubyte[] maskedSeed = messagePadded[1..hashLength+1];
        ubyte[] maskedDb = messagePadded[hashLength+1..$];

        // Create the initial state of the messagePadded

        messagePadded[0] = 0;
        random.nextBytes(maskedSeed);

        hashfn.put(label);
        hashfn.digest(maskedDb[0..hashLength]);

        maskedDb[hashLength+1..$-message.length-1] = 0;
        maskedDb[$-message.length-1] = 1;
        maskedDb[$-message.length..$] = message[];

        ubyte[] dbMask;
        OAEP_MGF(hashfn, maskedSeed, (keypair.bitLength>>3) - hashLength - 1, dbMask);
        maskedDb[] = dbMask[] ^ maskedDb[];

        ubyte[] seedMask;
        OAEP_MGF(hashfn, maskedDb, hashLength, seedMask);
        maskedSeed[] = seedMask[] ^ maskedSeed[];

        delete dbMask;
        delete seedMask;
        delete message;

        return messagePadded;

    }

    private ubyte[] decryptOAEP(T = SHA1)(ubyte[] message)
    {
        ubyte[] padded_message = decryptPlain(message);
        return this.depadOAEM(new T, padded_message);
    }

    private ubyte[] depadOAEM(Hash hashfn, ubyte[] padded_message)
    {
        //writeln("DEPAD Padded Message: ", padded_message.length, " \n",  padded_message);

        if(padded_message[0] != 0)
        {
            throw new Exception("Message does not start on 0. Possible tamper of data.");
        }

        // The leading zero during padding is removed by converting back from BigInt
        int hashLength = hashfn.digestBytes;
        ubyte[] maskedSeed = padded_message[1..hashLength+1];
        ubyte[] maskedDb = padded_message[hashLength+1..$];

        ubyte[] seedMask;
        OAEP_MGF(hashfn, maskedDb, hashLength, seedMask);
        maskedSeed[] = seedMask[] ^ maskedSeed[];

        ubyte[] dbMask;
        OAEP_MGF(hashfn, maskedSeed, maskedDb.length, dbMask);
        maskedDb[] = dbMask[] ^ maskedDb[];

        hashfn.reset();
        ubyte[] hashcompare = hashfn.digest();

        if(hashcompare != maskedDb[0..hashLength])
        {
            throw new Exception("Depadding hash function does not give correct results. Possible tamper of data.");
        }

        // Where does the message start?

        ubyte[] message = maskedDb[hashLength..$];
        while(message[0] != 1)
        {
            message = message[1..$];
        }

        if(message[0] != 1)
        {
            throw new Exception("Depadding padding misses 1 byte. Possible tamper of data.");
        }

        message = message[1..$]; // Skip right past that '1' byte

        delete dbMask;
        delete seedMask;

        return message;
    }

    /*
    // The Mask Generation Function is used in OAEP as defined in the standard as MGF1. Memory for output is 
    // allocated on the heap within this method, and the slice output is set to point to this area.
    */
    private void OAEP_MGF(Hash hashfn, const(ubyte[]) input, int output_length, ref ubyte[] output)
    {
        uint hashlength = hashfn.digestBytes;
        uint countTo = output_length / hashlength - (output_length % hashlength == 0 ? 1 : 0);

        ubyte[] t = new ubyte[hashlength*(countTo+1)];

        ubyte[] hashfn_round_input = new ubyte[input.length + 4];
        hashfn_round_input[0..$-4] = input[];

        for(uint counter = 0; counter <= countTo; counter++)
        {
            hashfn_round_input[$-4..$] = std.bitmanip.nativeToBigEndian!uint(counter);
            hashfn.reset();
            hashfn.put(hashfn_round_input);
            hashfn.digest(t[counter*hashlength..(counter+1)*hashlength]);
        }

        delete hashfn_round_input;

        output = t[0..output_length];

    }

    /*
    // Test RSA plain encryption and decryption
    */

    /*unittest
    {
    BigInt p = "61";
    BigInt q = "53";
    BigInt n = p*q;
    BigInt totient = (p-RSAKeyGenerator.one)*(q-RSAKeyGenerator.one);
    BigInt e = "17";
    BigInt d = RSAKeyGenerator.modularMultiplicativeInverse(e, totient);
    RSAKeyPair fixed_pair = RSAKeyPair(12, n, e, d, p, q );
    RSA rsaobj = new RSA(fixed_pair, null, RSA.PaddingMode.NO_PADDING );

    ubyte[] input = cast(ubyte[])x"41"; // 65 decimal

    ubyte[] encrypted = rsaobj.encrypt(input);
    ubyte[] decrypted = rsaobj.decrypt(encrypted);

    scope(failure)
    {
    writeln("RSA enryption/decryption test failed:");
    writeln("Input: ", input);
    writeln("Encrypted: ", encrypted);
    writeln("Decrypted: ", decrypted);
    }

    assert(encrypted == BigInt("2790").toUbyteArray(), "Encrypted value is not correct, expecting 2790.");
    assert(decrypted == input, "Decrypting does not give back original input.");

    }

    // Tests the OAEP Scheme

    unittest
    {
    BigInt p = "61";
    BigInt q = "53";
    RSAKeyPair fixed_pair = RSAKeyPair(360, p*q, BigInt("17"),  BigInt("2753"), p, q );
    RSA rsaobj = new RSA(fixed_pair, new AlwaysOnePRNG, RSA.PaddingMode.OAEP); 
    ubyte[] padded_message = rsaobj.padOAEP(new SHA1, [2, 4]);
    writeln(padded_message);
    assert(padded_message == [0, 112, 101, 75, 4, 137, 194, 65, 208, 224, 191, 232,
    37, 238, 227, 108, 218, 58, 191, 28, 192, 135, 42, 139, 113, 204, 216, 96,
    249, 249, 134, 42, 26, 34, 179, 56, 197, 32, 188, 94, 253, 82, 28, 11, 192],
    "The padded OAEP message is not correct.");
    scope(failure)
    {
    writeln("RSA enryption with OAEP padding mode failed.");
    }
    }*/

}

void main2()
{

    int num = 50;
    uint keysize = 1024;
    writeln("Generating ",num ," RSA keys for ", keysize, " bit modulus N. Encrypting 10 times per key.");

    StopWatch st;
    st.start();

    IRandom prng = new InsecurePRNG();
    auto generator = new RSAKeyGenerator(prng, keysize);
    RSAKeyPair keypair;

    auto f = File ("primes.txt", "w");

    foreach(i; 0..num)
    {
        keypair = generator.newKeyPair();
        f.writeln("#");
        f.writeln(keypair.p);
        f.writeln(keypair.q);

        /*writeln(keypair.p);
        writeln(keypair.q);*/

        /*BigInt p = "275571280751189193559444628257528861124727216495203160721042135088871484483";
        BigInt q = "7812733399781257497731268069628628373692228162578996268038862503493798757379";
        BigInt pq = p*q;
        BigInt tote = (p-1)*(q-1);
        BigInt e = 17;
        BigInt d = RSAKeyGenerator.modularMultiplicativeInverse(e, tote);
        keypair = RSAKeyPair(  pq.bitLength, p*q, e, d, p, q );
        writeln("D is ", keypair.d);
        BigInt tot = (keypair.p-1)*(keypair.q-1);
        writeln("totient mod e is", (tot % keypair.e));
        writeln("ed mod tot is", (keypair.e*keypair.d) % tot);*/


        RSA rsaobj = new RSA(keypair, prng, RSA.PaddingMode.OAEP);

        foreach(x; 0..10)
        {
            ubyte[] input = cast(ubyte[])x"5461";
            ubyte[] encrypted = rsaobj.encrypt(input);
            ubyte[] original = rsaobj.decrypt(encrypted);
            assert(input == original);
        }

    }


    st.stop();
    writeln(num, " Rsa Key Pairs generated in ", st.peek().msecs/1000.0f, " seconds, on average ", st.peek().msecs/1000.0f/num," seconds per pair. Stored in primes.txt.");

    std.process.system("pause");

}