using CommandLine;
using rgat;
using rgat.Config;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Veldrid;
using Veldrid.Sdl2;
using Veldrid.StartupUtilities;

namespace ImGuiNET
{
    class Program
    {

        static rgatState _rgatState = new rgatState();

        static void Main(string[] args)
        {
            // Bad arguments given or an info argument that is supposed to exit immediately
            if (!InitOptions(args) || HandleImmediateExitOptions())
            {
                return;
            }

            InitialSetup();

            if (!GlobalConfig.StartOptions.NoGUI)
            {
                rgat.OperationModes.ImGuiRunner Ui = new rgat.OperationModes.ImGuiRunner(_rgatState);
                Ui.Run();
            }
            else if (GlobalConfig.StartOptions.NetworkKey != null)
            {
                BridgedMain();
            }
            else
            {
                CommandLineGPU();
            }
        }

        static bool InitOptions(string[] cmdlineParams)
        {
            var parser = new Parser(with =>
            {
                with.GetoptMode = true;
            });
            parser.ParseArguments<LaunchConfig>(cmdlineParams)
               .WithParsed(cmdlineOpts =>
               {
                   if (!cmdlineOpts.ExtractJSONOptions(out string error))
                   {
                       Console.WriteLine($"Error: Bad JSON configuration blob - {error}");
                   }
                   else
                   {
                       cmdlineOpts.Init(cmdlineParams);
                       GlobalConfig.StartOptions = cmdlineOpts;
                   }
               });
            

            if (GlobalConfig.StartOptions.RunMode == LaunchConfig.eRunMode.Invalid)
            {
                Console.WriteLine($"Error: With GUI disabled and no valid network configuration or target to trace, I could not work out what to do. Quitting.");
            }
            return GlobalConfig.StartOptions != null;
        }


        static bool HandleImmediateExitOptions()
        {
            bool exit = false;
            //list valid network interfaces if the -i param was provided with a list arg or invalid interface
            string interfaceOption = GlobalConfig.StartOptions.Interface;
            if (interfaceOption != null)
            {
                switch (interfaceOption)
                {
                    case "list all":
                    case "show all":
                    case "print all":
                        RemoteTracing.PrintInterfaces(PrintInvalid: true);
                        exit = true;
                        break;

                    case "help":
                    case "list":
                    case "show":
                    case "print":
                    case "?":
                        RemoteTracing.PrintInterfaces();
                        exit = true;
                        break;

                    default:
                        GlobalConfig.StartOptions.ActiveNetworkInterface = RemoteTracing.ValidateNetworkInterface(interfaceOption);
                        if (GlobalConfig.StartOptions.ActiveNetworkInterface == null)
                        {
                            Console.WriteLine($"Error: Specified network interface '{interfaceOption}' could not be matched to a valid network interface\n");
                            RemoteTracing.PrintInterfaces();
                            exit = true;
                        }
                        break;
                }
            }

            if (GlobalConfig.StartOptions.FFmpegPath != null)
            {
                HandleFFmpegParam(GlobalConfig.StartOptions.FFmpegPath, ref exit);
            }

            return exit;
        }

        static void HandleFFmpegParam(string ffmpegopt, ref bool exit)
        {
            if (ffmpegopt == "")
            {
                if (!GlobalConfig.GetAppSetting("FFmpegPath", out string configuredPath))
                {
                    Console.WriteLine($"The FFmpeg encoder is not configured. Supply a path to FFmpeg.exe with the -M option");
                }
                else
                {
                    if (System.IO.File.Exists(configuredPath))
                    {
                        Console.WriteLine($"The FFmpeg encoder is configured: '{configuredPath}'");
                    }
                    else
                    {
                        Console.WriteLine($"The FFmpeg encoder is configured but does not exist: '{configuredPath}'");
                    }
                }
                exit = true;
            }
            else
            {
                if (System.IO.File.Exists(ffmpegopt))
                {
                    GlobalConfig.FFmpegPath = ffmpegopt;
                    GlobalConfig.AddUpdateAppSettings("FFmpegPath", ffmpegopt);
                    Console.WriteLine($"The FFmpeg encoder is now set to ('{GlobalConfig.FFmpegPath}')");
                }
                else
                {
                    Console.WriteLine($"The FFmpeg encoder file supplied cannot be found: {ffmpegopt}");
                }
            }
        }



        //initialise things that are used in all types of tracing (ui, bridged, commandline)
        static void InitialSetup()
        {
            rgat.Threads.TraceProcessorWorker.SetRgatState(_rgatState);
        }



        /// <summary>
        /// Runs in headless mode which either connects to (command line -r) or waits for connections
        /// from (command line -p) a controlling UI mode rgat instance
        /// This does not use the GPU
        /// </summary>
        static void BridgedMain()
        {
            if (GlobalConfig.StartOptions.TargetPath != null)
            {
                Console.WriteLine("Starting headless file output mode");
                return;
            }

            if (GlobalConfig.StartOptions.ListenPort != -1)
            {
                Console.WriteLine("Starting headless listen mode");
                return;
            }

            if (GlobalConfig.StartOptions.ConnectModeAddress != null)
            {
                Console.WriteLine("Starting headless conenct mode");
                return;
            }

        }


        /// <summary>
        /// Run a single trace operation and then quits
        ///
        /// </summary>
        static void CommandLineGPU()
        {

        }

        /// <summary>
        /// Run a single trace operation and then quits
        ///
        /// </summary>
        static void CommandLineNoGPU()
        {

        }



    }
}
