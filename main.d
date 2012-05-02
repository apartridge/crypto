module main;

import crypto.hash.sha1;
import crypto.blockcipher.aes;
import crypto.mode.ecb;
import std.stdio;

int main(string[] argv)
{
	auto sha1 = new SHA1;
	sha1.put("A");
	writeln(sha1.digestHex());


    auto aes = new AES128( cast(ubyte[16]) x"f6cc34cdc555c5418254260203ad3ecd" );
    auto ecb = new ECB(aes);
    writeln("Encrypting file ...");
    ecb.encryptFile("test/sbox_format.py", "test/cipher.dat");
    writeln("Decrypting file ...");
    ecb.decryptFile("test/cipher.dat", "test/decr.dat");

	return 0;
}


