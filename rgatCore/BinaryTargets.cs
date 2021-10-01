using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace rgat
{
    /// <summary>
    /// Manages the collection of loaded binary targets
    /// </summary>
    public class BinaryTargets
    {
        class HOSTTARGETS
        {
            public Dictionary<string, BinaryTarget> targetbins = new();
            public Dictionary<string, BinaryTarget> sha1s = new();
        }
        // null is local host
        private readonly Dictionary<string, HOSTTARGETS> targets = new Dictionary<string, HOSTTARGETS>();
        private readonly Dictionary<string, HOSTTARGETS> sha1s = new Dictionary<string, HOSTTARGETS>();

        /// <summary>
        /// Number of loaded BinaryTargets
        /// </summary>
        public int Count => targets.Count;


        /// <summary>
        /// List of all the paths of loaded BinaryTargets
        /// </summary>
        /// <returns>List of filesystem paths</returns>
        public List<string> GetTargetPaths()
        {
            List<string> result = new();
            lock (targetslock)
            {
                foreach (var host in targets)
                {
                    foreach( var target in host.Value.targetbins)
                    {
                        result.Add(target.Value.FilePath);
                    }
                }
                return result;
            }
        }


        /// <summary>
        /// Get a BinaryTarget object for a filesystem path.
        /// </summary>
        /// <param name="path">Fileystem path string</param>
        /// <param name="result">Binarytarget for the path, if already loaded</param>
        /// <returns>bool target was akready loaded</returns>
        public bool GetTargetByPath(string path, out BinaryTarget? result)
        {
            lock (targetslock)
            {
                if (targets.TryGetValue(rgatState.TargetsAddress, out HOSTTARGETS? hostTargets) && hostTargets is not null)
                {
                    if (hostTargets.targetbins.TryGetValue(path, out BinaryTarget? existingEntry) && existingEntry is not null)
                    {
                        result = existingEntry;
                        return true;
                    }
                }
                result = null;
                return false;
            }
        }

        /// <summary>
        /// Fetch a thread-safe copy of the list of loaded BinaryTargets
        /// </summary>
        /// <returns>List of BinaryTargets</returns>
        public List<BinaryTarget> GetBinaryTargets()
        {
            List<BinaryTarget> result = new();
            lock (targetslock)
            {
                foreach(var host in targets)
                {
                    result.AddRange(host.Value.targetbins.Values);
                }
                return result;
            }
        }


        /// <summary>
        /// Initialise and record a BinaryTarget object from a filesystem path
        /// </summary>
        /// <param name="path">Filesystem path of the target</param>
        /// <param name="isLibrary">true if a DLL</param>
        /// <param name="arch">32 or 64 bit, or 0 if unknown (remote)</param>
        /// <param name="remoteAddr">Optional remote address of the system this binary is on</param>
        /// <returns>Created BinaryTarget object</returns>
        public BinaryTarget AddTargetByPath(string path, bool isLibrary = false, int arch = 0)
        {
            lock (targetslock)
            {
                string addr = rgatState.TargetsAddress;
                if (!targets.TryGetValue(addr, out HOSTTARGETS? hostTargs))
                {
                    hostTargs = new HOSTTARGETS() { sha1s = new(), targetbins = new() };
                    targets.Add(addr, hostTargs); 
                }
                if (!hostTargs.targetbins.TryGetValue(path, out BinaryTarget? target))
                {
                    target = new BinaryTarget(path, arch, addr, isLibrary: isLibrary);
                    hostTargs.targetbins.Add(path, target);
                }
                return target;
            }
        }


        /// <summary>
        /// Add a pre-constructed BinaryTarget
        /// </summary>
        /// <param name="target">BinaryTarget to add</param>
        public void RegisterTarget( BinaryTarget target)
        {
            lock (targetslock)
            {
                string addr = rgatState.TargetsAddress;
                if (!targets.TryGetValue(addr, out HOSTTARGETS? hostTargs))
                {
                    hostTargs = new HOSTTARGETS() { sha1s = new(), targetbins = new() };
                    targets.Add(addr, hostTargs);
                }

                string sha1 = target.GetSHA1Hash();
                if (!hostTargs.sha1s.TryGetValue(sha1, out BinaryTarget? existingTarget))
                {
                    hostTargs.sha1s.Add(sha1, target);
                }
                else
                {
                    Debug.Assert(existingTarget.GetSHA1Hash() == sha1);
                }
            }
        }


        /// <summary>
        /// Fetch a BinaryTarget by its SHA1 hash
        /// </summary>
        /// <param name="sha1">SHA1 hash to find</param>
        /// <param name="target">BinaryTarget, if found</param>
        /// <returns>true if found</returns>
        public bool GetTargetBySHA1(string sha1, out BinaryTarget? target)
        {
            target = null;
            lock (targetslock)
            {
                if (targets.TryGetValue(rgatState.TargetsAddress, out HOSTTARGETS? hostTargs))
                {
                    return hostTargs.sha1s.TryGetValue(sha1, out target);
                }
                return false;
            }
        }

        private readonly object targetslock = new object();

    }
}
