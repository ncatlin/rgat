using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace rgat
{
    /// <summary>
    /// This is for buncling up all the user settings from the 
    /// trace launch tab and using it in local trace, remote trace or serialising
    /// it to settings or for command line launching
    /// </summary>
    class ProcessLaunchSettings
    {
        public enum TracingMode { Continuous, SingleShot };

        public ProcessLaunchSettings(string path) => BinaryPath = path;
        
        public string BinaryPath;

        /// <summary>
        /// Command line arguments passed to the target binary
        /// </summary>
        public string? CommandLineArgs;

        /// <summary>
        /// Custom DLL loader name
        /// </summary>
        public string LoaderName = "LoadDLL";

        /// <summary>
        /// 32 or 64 bit loader
        /// </summary>
        public BitWidth LoaderWidth;

        /// <summary>
        /// DLL ordinal to execute
        /// </summary>
        public int? DLLOrdinal = 0; //default dllmain

        /// <summary>
        /// Level of instrumentation to use. Only continuous is implemented at the moment
        /// </summary>
        public TracingMode tracingMode = 0;

        /// <summary>
        /// How to choose which modules to trace
        /// </summary>
        public bool DefaultIgnore = false;

        /// <summary>
        /// Modules to ignore in default trace mode
        /// </summary>
        public List<string> IgnoredFiles = new();
        /// <summary>
        /// Directories to ignore in default trace mode
        /// </summary>
        public List<string> IgnoredDirectories = new();
        /// <summary>
        /// Modules to trace in default ignore mode
        /// </summary>
        public List<string> TracedFiles = new();
        /// <summary>
        /// Directories to trace in default ignore mode
        /// </summary>
        public List<string> TracedDirectories = new();

        /// <summary>
        /// Passed to instrumentation tool
        /// </summary>
        public Dictionary<string, string> TraceSettings = new();
    }
}
