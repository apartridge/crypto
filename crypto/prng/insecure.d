module crypto.prng.insecure;

import crypto.prng.d;

class InsecurePRNG : PRNG
{
    void nextBytes(ubyte[] buffer){
        buffer[] = 0x01;
    }
}