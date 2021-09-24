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
        private readonly Dictionary<string, BinaryTarget> targets = new Dictionary<string, BinaryTarget>();
        private readonly Dictionary<string, BinaryTarget> sha1s = new Dictionary<string, BinaryTarget>();

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
            lock (targetslock)
            {
                return new List<string>(targets.Keys);
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
                if (targets.TryGetValue(path, out BinaryTarget? existingEntry))
                {
                    result = existingEntry;
                    return true;
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
            lock (targetslock)
            {
                return targets.Values.ToList();
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
        public BinaryTarget AddTargetByPath(string path, bool isLibrary = false, int arch = 0, string? remoteAddr = null)
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


        /// <summary>
        /// Add a pre-constructed BinaryTarget
        /// </summary>
        /// <param name="target">BinaryTarget to add</param>
        public void RegisterTarget(BinaryTarget target)
        {
            lock (targetslock)
            {
                string sha1 = target.GetSHA1Hash();
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
                return sha1s.TryGetValue(sha1, out target);
            }
        }

        private readonly object targetslock = new object();

    }
}
