using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace rgatCore
{
    class OSHelpers
    {
        public static class OperatingSystem
        {
            public static bool IsWindows() =>
                RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

            public static bool IsMacOS() =>
                RuntimeInformation.IsOSPlatform(OSPlatform.OSX);

            public static bool IsLinux() =>
                RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }

    }
}
