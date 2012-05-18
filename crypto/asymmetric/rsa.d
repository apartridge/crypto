module crypto.asymmetric.rsa;

private import crypto.prng.d;
private import crypto.prng.insecure;
import crypto.asymmetric.bigint;
import std.stdio;
import std.datetime;

struct RSAKeyPair
{
    public BigInt n;
    public BigInt d;
    public BigInt e;
    public BigInt p;
    public BigInt q;

    public BigInt dp;
    public BigInt dq;
    public BigInt qinv;

    private bool _hasPrivateKey = false;
    private bool _hasCRTDetails = false;

    public @property bool hasPrivateKey()
    {
        return _hasPrivateKey;
    }

    public @property bool hasCRTDetails()
    {
        return _hasCRTDetails;
    }

    this(BigInt n, BigInt d, BigInt e, BigInt p, BigInt q)
    {
        this.n = n;
        this.d = d;
        this.e = e;
        this.p = p;
        this.q = q;

        this._hasPrivateKey = true;

        // Find dp, dq and qinv

        this.dp = d % (p-1);
        this.dq = d % (q-1);
        this.qinv = RSAKeyGenerator.modularMultiplicativeInverse(q, p);

        this._hasCRTDetails = true;

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
    private static auto zero = BigInt("0");
    private static auto one = BigInt("0x1");
    private static auto two = BigInt("0x2");

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
        BigInt p, q;
        do
        {
            p = newRandomPrime();
            q = newRandomPrime();
        }
        while(p == q);

        auto n = p*q;
        auto totient = (p-one)*(q-one);

        BigInt e = 17;
        auto d = modularMultiplicativeInverse(e, totient);

        RSAKeyPair keypair = RSAKeyPair (n, d, e, p, q);
        return keypair;

    }

    /*
    // Returns a random prime with length bitlength/2 to be used
    // as a factor in N.    
    */

    private BigInt newRandomPrime()
    {
        int tries = 0;
        while(++tries)
        {
            BigInt randomCandidate = randomBigInt(bitLength/2, true);

            if(isProbablePrime(randomCandidate))
            {
                writeln("Found a probable prime of bitlength ",bitLength/2," \n", randomCandidate, " \n with ", tries, " guesses of a prime.");
                return randomCandidate;
            }
        }
        assert(0);
    }

    // Checks if this prime candidate is a (very) possible prime

    private bool isProbablePrime(BigInt randomCandidate)
    {
        if(randomCandidate % 3 == 0 || randomCandidate % 7 == 0 || randomCandidate % 11 == 0 || randomCandidate % 13 == 0 || randomCandidate % 19 == 0)
        {
            return false;
        }

        return millerRabinPrimeTest(randomCandidate, 40); // Yields a probability 4^-40 false positives
    }

    // Check this random number with the Miller Rabin Test, with a given number of tries
    // Returns true if it is a possible prime, false if it is a composite

    private bool millerRabinPrimeTest(BigInt randomCandidate, uint tries)
    {

        BigInt rcmin1 = randomCandidate - 1;
        ulong s = rcmin1.trailingZeroBits;
        BigInt d = rcmin1 >> s;

        /*writeln("****\nRunning Miller-Rabin on ", randomCandidate);
        writeln("Candidate Minus One is ", rcmin1);
        writeln("S is ", s, " and D is ", d, " s.t. rcmin1 = 2^^s*d");*/

        for(uint i = 0; i < tries; i++)
        {
            BigInt apick;
            int repeats = 0;
            do
            {
                apick = randomBigInt(rcmin1.bitLength);
                repeats++;
            }
            while(apick >= rcmin1 || apick < 2);

            BigInt x = apick.powMod(d, randomCandidate);

            if(x == one || x == rcmin1)
            {
                break;
            }

            bool doublebreak = false;

            for(int ri = 1; ri < s; ri++)
            {
                x = apick.powMod(two, randomCandidate);
                if(x == one)
                {
                    return false;
                }
                else if(x == rcmin1)
                {
                    doublebreak = true;
                    break;
                }
            }

            if(doublebreak)
            {
                break;
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

        if(inv < zero)
        {
            inv += m;
        }

        return inv;
    }

    unittest
    {
        assert(RSAKeyGenerator.modularMultiplicativeInverse(BigInt("3"), BigInt("11")) == BigInt("4"), "Modular Multiplicative Inverse simplest case failed.");
        assert(RSAKeyGenerator.modularMultiplicativeInverse(BigInt("17"), BigInt("3120")) == BigInt("2753"), "Modular Multiplicative Inverse case 2 failed.");
        assert(RSAKeyGenerator.modularMultiplicativeInverse(BigInt("7136894511284418597546878456"), BigInt("589743216878943213987498637986541")) == BigInt("28667610335819904460119453172384"),
               "Modular Multiplicative Inverse large case failed.");
    }

    /*
    // Solves ax + by = gcd(a, b) and returns x
    */

    private static BigInt extendedEuclidX(BigInt a, BigInt b)
    {
        BigInt x = "0";
        BigInt lastx = "1";

        while( b != zero)
        {
            BigInt quot = a / b;
            BigInt temp = a % b;
            a = b;
            b = temp;

            temp = x;
            x = lastx - quot*x;
            lastx = temp;
        }

        return lastx;
    }

    unittest
    {
        assert(RSAKeyGenerator.extendedEuclidX(BigInt("4864"), BigInt("3458")) == BigInt("32"), "Inverse Extended Euclid simple case failed.");
        assert(RSAKeyGenerator.extendedEuclidX(BigInt("45004045"), BigInt("2321544121")) == BigInt("-783915036"), "Inverse Extended Euclid case 2 failed.");
    }

}

/* 
* Handles RSA encryption and decryption.
*/

class RSA
{
    private:
    RSAKeyPair keypair;

    public:

    this(RSAKeyPair keypair)
    {
        this.keypair = keypair;
    }

    /*
    // Encryption
    */

    BigInt encrypt(BigInt m)
    {
        BigInt result = m.powMod(keypair.e, keypair.n);

        return result;
    }

    /*
    // Decryption
    */
    BigInt decrypt(BigInt c)
    {
        // Use the Chinese Remainder Theorem to speed up

        if(keypair.hasCRTDetails)
        {
            BigInt m1 = c.powMod(keypair.dp, keypair.p);
            BigInt m2 = c.powMod(keypair.dq, keypair.q);
            BigInt h = (keypair.qinv*(m1-m2)) % keypair.p;
            if(h < 0)
            {
                h += keypair.p;
            }
            return m2 + h*keypair.q;
        }
        else
        {
            return c.powMod(keypair.d, keypair.n);
        }
    }

    /*
    // Test RSA encryption and decryption
    */

    unittest
    {
        BigInt p = "61";
        BigInt q = "53";
        BigInt n = p*q;
        BigInt totient = (p-RSAKeyGenerator.one)*(q-RSAKeyGenerator.one);
        BigInt e = "17";
        BigInt d = RSAKeyGenerator.modularMultiplicativeInverse(e, totient);
        RSAKeyPair fixed_pair = RSAKeyPair( n, d, e, p, q );
        RSA rsaobj = new RSA(fixed_pair);

        BigInt input = "65";
        BigInt encrypted = rsaobj.encrypt(input);
        BigInt decrypted = rsaobj.decrypt(encrypted);

        scope(failure)
        {
            writeln("RSA enryption/decryption test failed:");
            writeln("Input: ", input);
            writeln("Encrypted: ", encrypted);
            writeln("Decrypted: ", decrypted);
        }

        assert(encrypted == BigInt("2790"), "Encrypted value is not correct, expecting 2790.");
        assert(decrypted == input, "Decrypting does not give back original input.");

    }

}

void main11()
{

    uint keysize = 2048;
    writeln("Generating RSA keys for ", keysize, " bit modulus N.");
    StopWatch st;
    st.start();
/*}

void main1()
{*/
    IRandom prng = new InsecurePRNG();
    auto generator = new RSAKeyGenerator(prng, keysize);
    RSAKeyPair myfirstpair = generator.newKeyPair();

    st.stop();
    writeln("Rsa Keys with a modulus of bitlength ", myfirstpair.n.bitLength ," generated in ", st.peek().msecs/1000.0f, " seconds");




    RSA rsaobj = new RSA(myfirstpair);







    BigInt input = "5465454568452345687456";
    //writeln("Input value is ", input);
    BigInt encrypted = rsaobj.encrypt(input);
    //writeln("Encrypted value is ", encrypted);
    BigInt original = rsaobj.decrypt(encrypted);
    writeln("",input," encrypted and decrypted yields\n", original);
  

    std.process.system("pause");

}