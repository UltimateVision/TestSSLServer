using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

public class IpRange
{
    private IPAddress from;
    private IPAddress to;
    private byte mask;

    public IpRange(String raw)
    {
        String[] split = raw.Split('/');
        @from = IPAddress.Parse(split[0]);
        int bytes = int.Parse(split[1]);

        uint mask = ~(uint.MaxValue >> bytes);

        byte[] ipBytes = @from.GetAddressBytes();
        byte[] maskBytes = BitConverter.GetBytes(mask).Reverse().ToArray();

        byte[] startIPBytes = new byte[ipBytes.Length];
        byte[] endIPBytes = new byte[ipBytes.Length];

        // Calculate the bytes of the start and end IP addresses.
        for (int i = 0; i < ipBytes.Length; i++)
        {
            startIPBytes[i] = (byte)(ipBytes[i] & maskBytes[i]);
            endIPBytes[i] = (byte)(ipBytes[i] | ~maskBytes[i]);
        }

        @from = new IPAddress(startIPBytes);
        to = new IPAddress(endIPBytes);
    }

    public IPAddress GetFrom()
    {
        return from;
    }

    public IPAddress GetTo()
    {
        return to;
    }

    public string GetStartingAddress()
    {
        return @from.ToString();
    }

    public string GetEndingAddress()
    {
        return to.ToString();
    }
}