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

        public bool GetTargetByPath(string path, out BinaryTarget result)
        {
            if (targets.TryGetValue(path, out BinaryTarget existingEntry)) {
                result = existingEntry;
                return true; 
            }
            result = null;
            return false;
        }

        public void AddTargetByPath(string path)
        {
            if (!targets.ContainsKey(path))
            {

                Console.WriteLine(path);
                targets[path] = new BinaryTarget(path);
            }
        }

        

    }
}
