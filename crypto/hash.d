module crypto.hash.d;
import std.traits;



abstract class Hash
{
    public abstract @property uint digestBytes();

    protected abstract void putData(const(ubyte)[]);

    public final void put(T)(in T data)
    {
        putData(cast(const(ubyte)[]) data);
    }

    public abstract void reset();

    protected abstract ubyte[] digestBuffer(ubyte[] outputbuffer);

    public ubyte[] digest(ubyte[] buffer = null)
    {
        if(buffer == null)
        {
            buffer = new ubyte[digestBytes()];
        }
        buffer = digestBuffer(buffer);
        return buffer;
    }

    public final string digestHex()
    {
        ubyte[] digestbytes = digest();

        char[] digestHex = new char[digestbytes.length*2];

        foreach(i, byt; digestbytes){
            const char[16] lookup = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'];
            digestHex[2*i] = lookup[byt >> 4];
            digestHex[2*i+1] = lookup[byt & 0x0F];
        }

        delete digestbytes;

        return cast(string)digestHex;
    }

}

template hash(H : Hash)
{
    ubyte[] hash(T)(in T data)
    {
        auto h = new H;
        h.put(data);
        return h.digest();
    }
}

template hashHex(H : Hash)
{
    string hashHex(T)(in T data)
    {
        auto h = new H;
        h.put(data);
        return h.digestHex();
    }
}