using System;
using System.Collections.Generic;
using System.Text;
using static rgat.GlobalConfig;

namespace rgat.Config
{
    class RemoteConfigMirror
    {
        static readonly object _lock = new object();


        static List<CachedPathData> _cachedRecentBins = new List<CachedPathData>();
        public static void SetRecentPaths(List<CachedPathData> entries)
        {
            lock (_lock)
            {
                _cachedRecentBins = entries;
            }
        }

        public static List<CachedPathData> GetRecentBins()
        {
            lock (_lock)
            {
                return new List<CachedPathData>(_cachedRecentBins);
            }
        }
    }
}
