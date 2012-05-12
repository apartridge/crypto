module crypto.asymmetric.rsa;

private import crypto.prng.d;
private import crypto.prng.insecure;
import crypto.asymmetric.bigint;
import std.stdio;


struct RSAKeyPair
{
    public BigInt n;
    public BigInt d;
    public BigInt e;
    public BigInt p;
    public BigInt q;

    private bool _hasPrivateKey = true;

    public @property hasPrivateKey()
    {
        return _hasPrivateKey;
    }
}


/* 
* Generates a 
*/

class RSAKeyGenerator
{
    private static auto zero = BigInt("0");
    private static auto one = BigInt("0x1");

    private uint bitLength;
    private IRandom randomGenerator;
    this(uint bitlength, IRandom randomGenerator)
    {
        this.bitLength = bitLength;
        this.randomGenerator = randomGenerator;
    }

    public static RSAKeyPair newKeyPair()
    {
        //BigInt p = newPrime(bitlength, randomGenerator);

        auto p = BigInt("61");
        auto q = BigInt("53");
        auto n = BigInt("3233");
        auto one = BigInt("1");
        auto totient = (p-one)*(q-one);
        BigInt e = 17;
        auto d = modularMultiplicativeInverse(e, totient);
        RSAKeyPair keypair =  {n, d, e, p, q};

        return keypair;

    }

    private static BigInt newPrime()
    {
        return BigInt("11");
    }


    // Returns a^-1 mod m
    private static BigInt modularMultiplicativeInverse(BigInt a, BigInt m)
    {
        //BigInt a2 = a;
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

    // Solves ax + by = gcd(a, b) and returns x
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
    RSAKeyPair keypair;

    this(RSAKeyPair keypair)
    {
        this.keypair = keypair;
    }

    // Encryption (m^e)
    BigInt encrypt(BigInt m)
    {
        BigInt result = m.powMod(keypair.e, keypair.n);

        //writefln("%s^%s mod %s is %s", m, bige, keypair.n, result);

        return result;
    }

    // Decryption (m^d)
    BigInt decrypt(BigInt m)
    {
        BigInt res = m.powMod(keypair.d, keypair.n);
        return res;
    }

    /*
    // Test RSA encryption and decryption
    */

    unittest
    {
        BigInt n = "3233";
        BigInt p = "61";
        BigInt q = "53";
        BigInt one = "1";
        BigInt totient = (p-one)*(q-one);
        BigInt e = "17";
        BigInt d = RSAKeyGenerator.modularMultiplicativeInverse(e, totient);
        RSAKeyPair fixed_pair = {n, d, e, p, q};
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

// Should be moved to bigint or something

unittest
{
    BigInt base = "4";
    BigInt exp = "13";
    BigInt modulus = "497";
    BigInt result = base.powMod(exp, modulus);
    BigInt answer = "445";
    assert(result == answer);
}


void main()
{
    IRandom prng = new InsecurePRNG();
    auto generator = new RSAKeyGenerator(2048, prng);

    RSAKeyPair myfirstpair = generator.newKeyPair();

    RSA rsaobj = new RSA(myfirstpair);

    BigInt input = "3231";

    writeln("Input value is ", input);
    BigInt encrypted = rsaobj.encrypt(input);
    writeln("Encrypted value is ", encrypted);
    BigInt original = rsaobj.decrypt(encrypted);
    writeln("Recovered input value is ", original);

    std.process.system("pause");

}