﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net;

/* ====================================================================================
                    C# IP address range finder helper class (C) Nahum Bazes
 * Free for private & commercial use - no restriction applied, please leave credits.
 *                              DO NOT REMOVE THIS COMMENT
 * ==================================================================================== */


public class IpRangeEnumerator
{
    public IEnumerable<string> GetIPRange(IpRange range)
    {
        uint sIP = IpToUint(range.GetFrom().GetAddressBytes());
        uint eIP = IpToUint(range.GetTo().GetAddressBytes());
        while (sIP <= eIP)
        {
            yield return new IPAddress(ReverseBytesArray(sIP)).ToString();
            sIP++;
        }
    }


    /* reverse byte order in array */
    protected uint ReverseBytesArray(uint ip)
    {
        byte[] bytes = BitConverter.GetBytes(ip);
        bytes = bytes.Reverse().ToArray();
        return (uint)BitConverter.ToInt32(bytes, 0);
    }


    /* Convert bytes array to 32 bit long value */
    protected uint IpToUint(byte[] ipBytes)
    {
        ByteConverter bConvert = new ByteConverter();
        uint ipUint = 0;

        int shift = 24; // indicates number of bits left for shifting
        foreach (byte b in ipBytes)
        {
            if (ipUint == 0)
            {
                ipUint = (uint)bConvert.ConvertTo(b, typeof(uint)) << shift;
                shift -= 8;
                continue;
            }

            if (shift >= 8)
                ipUint += (uint)bConvert.ConvertTo(b, typeof(uint)) << shift;
            else
                ipUint += (uint)bConvert.ConvertTo(b, typeof(uint));

            shift -= 8;
        }

        return ipUint;
    }
}