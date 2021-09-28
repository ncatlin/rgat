using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace rgat
{
    /// <summary>
    /// This is for buncling up all the user settings from the 
    /// trace launch tab and using it in local trace, remote trace or serialising
    /// it to settings or for command line launching
    /// </summary>
    public class ProcessLaunchSettings
    {
        /// <summary>
        /// Unimplemented trace mode
        /// </summary>
        public enum TracingMode {
            /// <summary>
            /// Instrumenting every path continuously
            /// </summary>
            Continuous, 
            /// <summary>
            /// Stop instrumenting blocks after all possible paths seen
            /// </summary>
            SingleShot 
        };

        /// <summary>
        /// Create launch config
        /// </summary>
        /// <param name="BinaryPath">Path of target</param>
        public ProcessLaunchSettings(string BinaryPath) => this.BinaryPath = BinaryPath;

        /// <summary>
        /// Path of the binary on disk
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
        public string BinaryPath { get; set; }

        /// <summary>
        /// Command line arguments passed to the target binary
        /// </summary>
        public string? CommandLineArgs { get; set; } = "";

        /// <summary>
        /// Custom DLL loader name
        /// </summary>
        public string LoaderName { get; set; } = "LoadDLL";

        /// <summary>
        /// 32 or 64 bit loader
        /// </summary>
        public BitWidth LoaderWidth { get; set; }

        /// <summary>
        /// DLL ordinal to execute
        /// </summary>
        public int? DLLOrdinal { get; set; } = 0; //default dllmain

        /// <summary>
        /// Level of instrumentation to use. Only continuous is implemented at the moment
        /// </summary>
        public TracingMode tracingMode { get; set; } = 0;



        /// <summary>
        /// Settings for which modules are instrumented/ignored
        /// </summary>
        public TraceChoiceSettings TraceChoices { get; set; } = new TraceChoiceSettings();


        /// <summary>
        /// Passed to instrumentation tool
        /// </summary>
        public Dictionary<string, string> InstrumentationToolSettings { get; set; } = new();

        /// <summary>
        /// Get the tracing configuration settings as a dictrionary of keyvaluepair strings
        /// </summary>
        /// <returns>Settings dictionary</returns>
        public Dictionary<string, string> GetCurrentTraceConfiguration()
        {
            lock (_lock)
            {
                return new Dictionary<string, string>(InstrumentationToolSettings);
            }
        }


        /// <summary>
        /// Set a tracing configuration value to be sent to the instrumentation tool
        /// </summary>
        /// <param name="key">Setting to set</param>
        /// <param name="value">Value of the setting</param>
        public void SetTraceConfig(string key, string value)
        {
            //this probably doesnt matter anymore
            if (key.Contains('@') || value.Contains('@')) { Logging.RecordError("invalid character '@' in config item"); return; }
            lock (_lock)
            {
                InstrumentationToolSettings[key] = value;
            }
        }


        private readonly object _lock = new object();
    }
}
