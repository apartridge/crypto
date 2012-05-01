module main;

import crypto.hash.sha1;
import crypto.blockcipher.aes;
import std.stdio;

int main(string[] argv)
{
	auto sha1 = new SHA1;
	sha1.put("A");
	writeln(sha1.digestHex());


    auto aes = new AES128( cast(ubyte[16]) x"f6cc34cdc555c5418254260203ad3ecd" );
    auto message = aes.Encrypt(cast(ubyte[16]) x"7483765489aab73affeedd88aebfc876" );
    write("AES: "); writeln(message); // 9c 33 df 29 3e d6 55 b5 f0 a6 1e bc 70 5f 6f 5a



    ubyte[4] bs = [0x00, 0x11, 0x22, 0x33];

    uint* a = cast(uint*) &bs;
    writeln("Integers");
    writeln(0x00112233);
    writeln(0x33221100);
    writeln(*a);



	return 0;
}


