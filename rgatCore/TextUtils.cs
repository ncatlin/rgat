﻿using System;

namespace rgat
{
    internal class TextUtils
    {
        public static string IllustrateASCIIBytes(byte[] input, int len)
        {
            string result = "";
            for (var i = 0; i < len; i++)
            {
                byte c = input[i];
                if (c < 0x20)
                {
                    switch (c)
                    {
                        case 0x9:
                            result += "\\t";
                            break;
                        case 0xa:
                            result += "\\n";
                            break;
                        case 0xd:
                            result += "\\r";
                            break;
                        default:
                            result += "..";
                            break;
                    }
                }
                else if (c > 0x7E)
                {
                    result += "..";
                }
                else
                {
                    result += Convert.ToChar(c) + " ";
                }
                result += " ";
            }
            return result;
        }

        public static string IllustrateASCIIBytesCompact(byte[] input, int len)
        {
            string result = "";
            for (var i = 0; i < len; i++)
            {
                byte c = input[i];
                if (c < 0x20)
                {
                    switch (c)
                    {
                        case 0x9:
                            result += ".";
                            break;
                        case 0xa:
                            result += ".";
                            break;
                        case 0xd:
                            result += ".";
                            break;
                        default:
                            result += ".";
                            break;
                    }
                }
                else if (c > 0x7E)
                {
                    result += ".";
                }
                else
                {
                    result += Convert.ToChar(c);
                }
            }
            return result;
        }

        public static DateTime UnixTimeStampToDateTime(double unixTimeStamp)
        {
            // Unix timestamp is seconds past epoch
            System.DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
            dtDateTime = dtDateTime.AddSeconds(unixTimeStamp).ToLocalTime();
            return dtDateTime;
        }

    }
}
