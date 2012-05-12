/*
Speedtests
*/
import std.stdio;
import std.datetime;
import crypto.hash.sha1;

void main222()
{
    auto string1 = "The quick brown fox jumps over the lazy dog";
    auto string2 = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

    const int REPEATS = 100_000;

    writeln(hashHex!SHA1(string1));


    StopWatch sw;
    sw.start();

    //ubyte[40] hash1; 

    for(int i = 0; i < REPEATS; i++)
    {
        auto hash1 = hash!SHA1(string1);
       
        auto hash2 = hash!SHA1(string2);
        //writeln(hash2);
    }

    //writeln(hash1);

    sw.stop();

    version(unittest)
    {
        writefln("Debug mode: ");
    }

    writefln("%d rounds of 2X SHA1 completed in %d msecs.\n", REPEATS, sw.peek().msecs );
    
   // writefln("Elapsed time from StopWatch timings: %d msecs.\n", timings.peek().msecs );




}