using CommandLine;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;

namespace rgat.Config
{
    /// <summary>
    /// rgat operation configuration based on command line options
    /// </summary>
    public class LaunchConfig
    {

        // usage modes


        /// <summary>
        /// if present - trace target file and exit
        /// this mode does not require a GPU, unless paired with the draw or mp4 options
        /// </summary>
        [Option('t', "target", SetName = "HeadlessMode", MetaValue = "\"path_to_binary\"", Required = false,
            HelpText = "Run rgat in Headless tracing mode. Requires the file path of the target binary to generate a trace for.\n" +
            "Traces are saved to the standard save directory, unless accompanied by the -o option.\n" +
            "This mode does not require a GPU, unless accompanied by the 'draw' and/or 'mp4' options"
            )]
        public string? TargetPath { get; set; }


        /// <summary>
        /// if present - go into headless bridge mode and act as a proxy for the specified rgat instance on a remote machine
        /// </summary>
        [Option('r', "remote", SetName = "ConnectMode", Required = false, MetaValue = "address:port",
            HelpText = "Run rgat in headless network mode (connecting out) which allows the rgat to control tracing from another computer.\n" +
            "Requires the address:port of an rgat instance in GUI mode with listening activated.\n" +
            "Not compatible with the listening mode optins. --key parameter is mandatory if no preconfigured key is set.\n" +
            "This mode does not require a GPU.")]
        public string? ConnectModeAddress { get; set; }


        /// <summary>
        /// if present - go into headless bridge mode and act as a proxy for the next rgat instance to connect to this port
        /// this mode does not require a GPU
        /// </summary>
        [Option('p', "port", SetName = "ListenMode", Required = false, MetaValue = "[port number]",
            HelpText = "Run rgat in headless network bridge mode (listening) which allows an rgat client to connect and control tracing on this computer.\n" +
            "Takes an  optional TCP port to listen on, or chooses a random available port.\n" +
            "Not compatible with the 'remote' option. See notes for the --key parameter, which is optional for this mode.\n" +
            "This mode does not require a GPU")]
        public int? ListenPort { get; set; }


        //network bridge mode modifiers

        /// <summary>
        /// The interface to use for network connections
        /// </summary>
        [Option('i', "interface", Required = false, MetaValue = "IP/ID/MAC/name",
            HelpText = "A network interface to use for remote control options (r or p).\n" +
            "By default all available interfaces will be used, so it's a good idea to pick the one you will be using.\n" +
            "The argument can be an interface name, ID, MAC or IP address.\n" +
            "Use without an argument to list valid interfaces.")]
        public string? Interface { get; set; }


        /// <summary>
        /// The encryption key to use for network connections
        /// </summary>
        [Option('k', "key", Required = false,
            HelpText = "Pre-shared key for remote control tracing. This key is stored so it is not required in future invocations.\n" +
            "------Security note------\n" +
            "\tNetwork tracing is intended to facilitate tracing between VM Host/Guest or between machines on a private analysis network.\n" +
            "\tWhile rgat expects malicious traffic and heavily rate-limits connection attempts, exposing the listener port to the internet is not advisable. " +
            "Anyone able to connect to this port with the specified key can execute abitrary code. Standard sensible password choice warnings apply.")]
        public string NetworkKey { get; set; } = "";


        // tracing mode modifiers

        /// <summary>
        /// Write the collected trace to this path, for opening later by rgat in UI mode
        /// </summary>
        [Option('o', "output", SetName = "HeadlessMode", Required = false, MetaValue = "\"filepath\"",
            HelpText = "Optional destination directory for saving the output traces, videos and images when in headless tracing mode")]
        public string? TraceSaveDirectory { get; set; }

        /// <summary>
        /// draw the rendered graph to a png image
        /// </summary>
        [Option('d', "draw", Hidden = true, Required = false, HelpText = "[Not implemented]Draw a png of the final rendering of the trace. Requires GPU access with Vulkan drivers.")]
        public bool DrawImage { get; set; }

        /// <summary>
        /// once tracing and graph layout is complete, record playback to an mp4 video. 
        /// </summary>
        [Option('M', "mp4_playback", Hidden = true, Required = false, HelpText = "[Not implemented]Record a video of a playback of the final trace. Requires FFMpeg.")]
        public bool RecordVideoReplay { get; set; }

        /// <summary>
        /// record a video of tracing and layout.
        /// </summary>
        [Option('m', "mp4_recording", Hidden = true, Required = false, HelpText = "[Not implemented]Record a video of the trace as it is being generated. Requires FFMpeg.")]
        public bool RecordVideoLive { get; set; }

        /// <summary>
        /// Path to ffmpeg.exe to use for video captures
        /// </summary>
        [Option("ffmpeg", Required = false, Hidden = true, MetaValue = "[\"path_to_ffmpeg.exe\"]", HelpText = "[Not implemented]Provide a path to FFMpeg.exe to enable video recording if one is not configured. With no argument, prints status of configured FFMpeg.")]
        public string? FFmpegPath { get; set; }

        /// <summary>
        /// if set to true, rgat will not trace child processes
        /// </summary>
        [Option("nofollow", Required = false, HelpText = "If specified, rgat will not trace new processes spawned by the initial process")]
        public bool NoFollowDescendants { get; set; } = false;


        //general options applicable to all headless modes

        /// <summary>
        /// Provide config options in a file to support automation
        /// </summary>
        [Option('c', "configfile", Required = false, MetaValue = "[\"path_to_config.json\"]", HelpText = "A path or current directory filename of a file containing a JSON configuration blob. Values in this configuration can be used instead of (or be overidden by) command line arguments.")]
        public string? ConfigPath { get; set; } = null;



        /// <summary>
        /// The network interface being used for listening or connecting
        /// </summary>
        public NetworkInterface? ActiveNetworkInterface;

        /// <summary>
        /// Modes rgat can operate in
        /// </summary>
        public enum eRunMode
        {
            /// <summary>
            /// Full GPU rendered GUI mode
            /// </summary>
            GUI,
            /// <summary>
            /// Performs a full trace + graph rendering, without the UI. 
            /// Results drawn to an image and/or video
            /// </summary>
            GPURenderCommand,
            /// <summary>
            /// Lightweight proxy mode which does little more than spawn processes and feed results back to
            /// a connected rgat instance
            /// </summary>
            Bridged,
            /// <summary>
            /// Generates a trace file that can be read by rgat in GUI mode
            /// </summary>
            NoGPUTraceCommand,
            /// <summary>
            /// The provided command line arguments were not valid for any supported mode of operation
            /// </summary>
            Invalid
        };

        /// <summary>
        /// The basic mode of operation for this rgat run
        /// </summary>
        public eRunMode RunMode = eRunMode.GUI;

        /// <summary>
        /// Initialise the configuration
        /// </summary>
        /// <param name="originalParams">The commandline parameters</param>
        public void Init(string[] originalParams)
        {
            DeNullifyArgumentless(originalParams);
            SetRunMode();
        }


        /// <summary>
        /// nothing => null
        /// -M => null
        /// This makes it so -M => ""
        /// Allows us to react to arguments with no value provided (eg: thing with no path -> do the thing but use a default path)
        /// </summary>
        /// <param name="originalParams"></param>
        void DeNullifyArgumentless(string[] originalParams)
        {
            if (Interface == null && (originalParams.Contains("-i") || originalParams.Contains("-interface") || originalParams.Contains("--interface")))
            {
                Interface = "";
            }

            if (ListenPort == null && originalParams.Contains("-p"))
            {
                ListenPort = int.MinValue;
            }
        }

        /// <summary>
        /// Work out what the user wants to do based on the arguments
        /// </summary>
        void SetRunMode()
        {

            if (ListenPort != null || ConnectModeAddress != null)
            {
                RunMode = eRunMode.Bridged;
                return;
            }

            if (TargetPath != null)
            {
                if (RecordVideoLive || RecordVideoReplay || DrawImage)
                {
                    RunMode = eRunMode.GPURenderCommand;
                }
                else
                {
                    RunMode = eRunMode.NoGPUTraceCommand;
                }
                return;
            }

            RunMode = eRunMode.GUI;
        }

        bool ParseConfigJSON(JObject jsn, out string? error)
        {

            foreach (var kvp in jsn)
            {
                if (kvp.Value is null) continue;
                string keyname = kvp.Key.ToLower();

                switch (keyname)
                {
                    case "nofollow":
                        if (TryGetBool(kvp.Value, out bool boolitem))
                        {
                            if (keyname == "nofollow") NoFollowDescendants = boolitem;
                        }
                        else
                        {
                            error = $"Config item '{kvp.Key}' has an unexpected value '{kvp.Value}'. Should be (true/false).";
                            return false;
                        }
                        break;


                    case "port":
                        if (kvp.Value.Type == JTokenType.Integer)
                        {
                            ListenPort = kvp.Value.ToObject<int>();
                            break;
                        }
                        else if (int.TryParse(kvp.Value.ToString(), out int ListenPort))
                        {
                            break;
                        }
                        else
                        {
                            error = $"Config item '{kvp.Key}' has an unexpected value '{kvp.Value}'. Should be an integer.";
                            return false;
                        }

                    default:
                        {
                            if (kvp.Value.Type == JTokenType.String && kvp.Value.ToString().Length > 0)
                            {
                                string valuestring = kvp.Value.ToString();
                                switch (kvp.Key)
                                {
                                    case "target":
                                        TargetPath = valuestring;
                                        break;
                                    case "savedirectory":
                                        TraceSaveDirectory = valuestring;
                                        break;
                                    case "remote":
                                        ConnectModeAddress = valuestring;
                                        break;
                                    case "interface":
                                        Interface = valuestring;
                                        break;
                                    case "key":
                                        NetworkKey = valuestring;
                                        break;
                                    case "ffmpeg":
                                        FFmpegPath = valuestring;
                                        break;
                                    default:
                                        Console.WriteLine($"\tWarning: Ignoring unknown config option '{kvp.Key}':'{kvp.Value}'");
                                        break;
                                }
                            }
                            else
                            {
                                Console.WriteLine($"Warning: Ignoring config item '{kvp.Key}' with unexpected key or invalid value '{kvp.Value}' type [{kvp.Value.Type}]");
                            }
                            break;
                        }
                }
            }

            error = "";
            return true;
        }


        /// <summary>
        /// Merges a JSON options blob into the command line options
        /// </summary>
        /// <param name="error">any error message produced by the operation</param>
        /// <returns>success or failure</returns>
        public bool ExtractJSONOptions(out string? error)
        {
            error = "";

            if (ConfigPath != null)
            {
                return ExtractJSONFileOptions(ConfigPath, out error);
            }

            return true;
        }


        bool ExtractJSONFileOptions(string path, out string? error)
        {
            error = "";
            if (File.Exists(this.ConfigPath))
            {
                try
                {
                    string filetext = File.ReadAllText(this.ConfigPath);
                    JObject jsn = JObject.Parse(filetext);
                    return ParseConfigJSON(jsn, out error);

                }
                catch (Exception e)
                {

                    error = $"Bad JSON file {this.ConfigPath}: {e.Message}";
                    return false;
                }
            }
            else
            {
                string currentDirConfigPath = Path.Combine(Directory.GetCurrentDirectory(), this.ConfigPath);
                if (File.Exists(currentDirConfigPath))
                {
                    try
                    {
                        string filetext = File.ReadAllText(currentDirConfigPath);
                        JObject jsn = JObject.Parse(filetext);
                        return ParseConfigJSON(jsn, out error);

                    }
                    catch (Exception e)
                    {
                        error = $"Bad JSON file {currentDirConfigPath}: {e.Message}";
                        return false;
                    }

                }
                else
                {
                    error = $"JSON config file {path} not found";
                    return false;
                }
            }
        }

        bool TryGetBool(JToken jtok, out bool result)
        {
            if (jtok.Type == JTokenType.Boolean)
            {
                result = jtok.ToObject<bool>();
                return true;
            }
            else if (jtok.Type == JTokenType.String && bool.TryParse(jtok.ToString(), out bool guibool))
            {
                result = guibool;
                return true;
            }
            else
            {
                result = false;
                return false;
            }
        }


    }
}
