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

        //Get a BinaryTarget object for a path. Returns true if a new record had to be created
        public bool GetTargetByPath(string path, out BinaryTarget result)
        {
            if (targets.TryGetValue(path, out BinaryTarget existingEntry)) {
                result = existingEntry;
                return false; 
            }
            result = new BinaryTarget(path);
            targets.Add(path, result);
            return true;
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
