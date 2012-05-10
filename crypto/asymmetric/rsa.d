module crypto.asymmetric.rsa;

private import crypto.prng.d;
private import crypto.prng.insecure;
import crypto.asymmetric.bigint;
import std.stdio;


struct RSAKeyPair
{
    public BigInt n;
    public BigInt d;
    public long e;
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

        auto e = 17;
        BigInt bige = e;

        auto d = modularMultiplicativeInverse(bige, totient);
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
        return (m ^^ keypair.e) % keypair.n;
    }

    // Decryption (m^d)
    BigInt decrypt(BigInt m)
    {

        BigInt res = (m, keypair.d, keypair.n);
        return res;

    }

}

unittest
{
    // 5^2 mod 4 = 25%4 = 1
    BigInt base = "5";
    BigInt exp = "2";
    BigInt modulus = "4";

    BigInt result = base.powModulus(exp, modulus);
    writeln("Result of 5^2 (mod 4) = ", result);
}





void main22()
{
    IRandom prng = new InsecurePRNG();
    auto generator = new RSAKeyGenerator(2048, prng);

    RSAKeyPair myfirstpair = generator.newKeyPair();
    //RSAKeyPair mysecondpair = generator.newKeyPair();

    RSA rsaobj = new RSA(myfirstpair);

    BigInt input = "6565465465465132132";
    BigInt encrypted = rsaobj.encrypt(input);

    writeln("Encrypted value is ", encrypted);

    BigInt original = rsaobj.decrypt(encrypted);

    writeln(original);




}