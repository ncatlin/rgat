using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace rgat
{
    public class BinaryTargets
    {
        private readonly Dictionary<string, BinaryTarget> targets = new Dictionary<string, BinaryTarget>();
        private readonly Dictionary<string, BinaryTarget> sha1s = new Dictionary<string, BinaryTarget>();
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
                if (targets.TryGetValue(path, out BinaryTarget? existingEntry))
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

        public BinaryTarget AddTargetByPath(string path, bool isLibrary = false, int arch = 0, string remoteAddr = null)
        {
            lock (targetslock)
            {
                BinaryTarget? target = null;
                if (!targets.TryGetValue(path, out target))
                {
                    target = new BinaryTarget(path, arch, remoteAddr, isLibrary: isLibrary);
                    targets.Add(path, target);
                }
                return target;
            }
        }

        public void RegisterTargetSHA1(string sha1, BinaryTarget target)
        {
            lock (targetslock)
            {
                if (!this.sha1s.TryGetValue(sha1, out BinaryTarget? existingTarget))
                {
                    this.sha1s.Add(sha1, target);
                }
                else
                {
                    Debug.Assert(existingTarget.GetSHA1Hash() == sha1);
                }
            }
        }

        public bool GetTargetBySHA1(string sha1, out BinaryTarget target)
        {
            target = null;
            lock (targetslock)
            {
                return sha1s.TryGetValue(sha1, out target);
            }
        }

        private readonly object targetslock = new object();

    }
}
