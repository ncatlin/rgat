﻿using System.Collections.Generic;
using System.Linq;

namespace rgat
{
    public class BinaryTargets
    {
        private Dictionary<string, BinaryTarget> targets = new Dictionary<string, BinaryTarget>();
        public BinaryTargets() { }
        public int count() => targets.Count;

        public List<string> GetTargetPaths()
        {
            lock (targetslock)
            { return new List<string>(targets.Keys); }
        }

        //Get a BinaryTarget object for a path.
        public bool GetTargetByPath(string path, out BinaryTarget result)
        {
            lock (targetslock)
            {
                if (targets.TryGetValue(path, out BinaryTarget existingEntry))
                {
                    result = existingEntry;
                    return true;
                }
                result = null;

                return false;
            }
        }

        public List<BinaryTarget> GetBinaryTargets()
        {
            lock (targetslock)
            {
                return targets.Values.ToList();
            }
        }

        public BinaryTarget AddTargetByPath(string path, int arch = 0, string remoteAddr = null)
        {
            lock (targetslock)
            {
                BinaryTarget target = null;
                if (!targets.TryGetValue(path, out target))
                {
                    target = new BinaryTarget(path, arch, remoteAddr);
                    targets.Add(path, target);
                }
                return target;
            }
        }
                
    


        private readonly object targetslock = new object();

    }
}
