using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;

namespace rgatCore
{
    class BinaryTargets
    {
        private Dictionary<string, BinaryTarget> targets = new Dictionary<string, BinaryTarget>();
        public BinaryTargets() { }
        public int count() => targets.Count;
        
        public List<string> GetTargetPaths()
        {
            return new List<string>(targets.Keys);
        }

        //Get a BinaryTarget object for a path.
        public bool GetTargetByPath(string path, out BinaryTarget result)
        {
            if (targets.TryGetValue(path, out BinaryTarget existingEntry)) {
                result = existingEntry;
                return true; 
            }
            result = null;
            return false;
        }

        public BinaryTarget AddTargetByPath(string path, int arch = 0)
        {
            BinaryTarget target = null;
            if (!targets.TryGetValue(path, out target))
            {
                target = new BinaryTarget(path, arch);
                targets.Add(path, target);
            }
            return target;
        }

        

    }
}
