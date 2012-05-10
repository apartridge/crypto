module crypto.prng.d;

/*
A Interface for Psuedo Random Number Generators.
Clients should create their own interface using some sort of randomness, ie using
mouse movement or actions from the client.

We should create some basic classes that manages internal state from some initial source of user
provided randomness or OS random function.
*/

interface IRandom
{
    ubyte nextByte();
    void nextBytes(ubyte[] buffer);
}

abstract class PRNG : IRandom
{
    ubyte nextByte()
    {
        ubyte[1] a;
        nextBytes(a);
        return a[0];
    }

    abstract void nextBytes(ubyte[] buffer);
}