using CommandLine;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;

namespace rgat.Config
{
    class LaunchConfig
    {

        [Option('n', "nogui", Required = false, HelpText = "Do not launch GUI. Requires further commandline arguments.")]
        public bool NoGUI { get; set; }

        [Option('t', "target", SetName = "HeadlessMode", Required = false, HelpText = "The file path of the target binary to execute and generate a trace for")]
        public string TargetPath { get; set; }

        [Option('o', "output", SetName = "HeadlessMode", Required = false, HelpText = "Optional file path or directory to save the output trace to. Only valid with the -t option.")]
        public string OutputPath { get; set; }

        [Option('d', "draw", Required = false, HelpText = "Draw a png of the final rendering of the trace")]
        public string DrawPath { get; set; }       
        
        [Option('V', "video_replay", Required = false, HelpText = "Record a video of a playback of the final trace. Takes an optional mp4 file outout path.  Requires FFMpeg.")]
        public string VideoReplayPath { get; set; }       
        
        [Option('v', "video_live", Required = false, HelpText = "Record a video of the trace as it is being reecorded. Takes an optional mp4 file outout path. Requires FFMpeg.")]
        public string VideoTracingPath { get; set; }        
        
        [Option('M', "ffmpeg", Required = false, HelpText = "Provide a path to FFMpeg.exe to enable video recording if one is not configured. With no argument, prints status of configured FFMpeg.")]
        public string FFmpegPath { get; set; }


        [Option('c', "configfile", Required = false, HelpText = "A path or current directory filename of a file containing a JSON configuration blob. Values in this configuration can be used instead of (or be overidden by) command line arguments.")]
        public string ConfigPath { get; set; }

        [Option('r', "remote", SetName = "ConnectMode", Required = false, HelpText = "Network address of an rgat instance running in server mode to connect to. Allows remote control of tracing on this computer. Not compatible with the listen option. --key parameter is mandatory if no preconfigured key is set.")]
        public string ConnectModeAddress { get; set; }

        [Option('p', "port", Default=-1, SetName = "ListenMode", Required = false, HelpText = "A TCP port to listen on. Allows remote control of tracing on this computer. Not compatible with the port option. --key parameter is mandatory if no preconfigured key is set.")]
        public int ListenPort { get; set; }

        [Option('i', "interface", SetName = "Interface", Required = false, HelpText = "A network interface to use for remote control options (r or p). By default all available interfaces will be used. Argument '?' will list valid interfaces and exit.")]
        public string Interface { get; set; }


        [Option('k', "key", Required = false, HelpText = "Pre-shared key for remote control tracing. Required with the 'listen' or 'server' options unless a saved key exists.")]
        public string NetworkKey { get; set; }


        [Option("nofollow", Required = false, HelpText = "If specified, rgat will not trace new processes spawned by the initial process")]
        public bool NoFollowDescendants { get; set; }



        public NetworkInterface ActiveNetworkInterface;


        public enum eRunMode { GUI, Bridged, GPURenderCommand, NoGPUTraceCommand, Invalid};
        public eRunMode RunMode;

        public void Init(string[] originalParams)
        {
            SetRunMode();
            DeNullifyArgumentless(originalParams);
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
            if (FFmpegPath == null && originalParams.Contains("-M"))
            {
                FFmpegPath = "";
            }

            if (OutputPath == null && originalParams.Contains("-o"))
            {
                OutputPath = "";
            }

            if (VideoReplayPath == null && originalParams.Contains("-V"))
            {
                VideoReplayPath = "";
            }

            if (VideoTracingPath == null && originalParams.Contains("-v"))
            {
                VideoTracingPath = "";
            }

            if (DrawPath == null && originalParams.Contains("-d"))
            {
                DrawPath = "";
            }
        }


        void SetRunMode()
        {
            if (!NoGUI)
            {
                RunMode = eRunMode.GUI;
                return;
            }

            if (NetworkKey != null)
            {
                RunMode = eRunMode.Bridged;
                return;
            }

            if (TargetPath != null)
            {
                if (VideoReplayPath != null || DrawPath != null)
                {
                    RunMode = eRunMode.GPURenderCommand;
                    return;
                }

                RunMode = eRunMode.NoGPUTraceCommand;
            }

            RunMode = eRunMode.Invalid;
        }

        bool ParseConfigJSON(JObject jsn, out string error)
        {
            foreach (var kvp in jsn)
            {
                string keyname = kvp.Key.ToLower();

                switch (keyname)
                {
                    case "nogui":
                    case "nofollow":
                        if (TryGetBool(kvp.Value, out bool boolitem))
                        {
                            if (keyname == "nogui") NoGUI = boolitem;
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
                                    case "output":
                                        OutputPath = valuestring;
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


        //this merges a JSON options blob into the command line options
        public bool ExtractJSONOptions(out string error)
        {
            error = "";

            if (ConfigPath != null)
            {
                return ExtractJSONFileOptions(ConfigPath, out error);
            }

            return true;
        }


        bool ExtractJSONFileOptions(string path, out string error)
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
                    error = $"File {path} not found";
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
