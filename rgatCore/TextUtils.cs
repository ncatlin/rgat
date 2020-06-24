using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{
    class TextUtils
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
    }
}
