using CommandLine;
using rgat;
using rgat.Config;
using rgat.OperationModes;
using System;

[assembly: System.Reflection.AssemblyTitleAttribute("An instruction trace visualisation tool")]

namespace ImGuiNET
{
    internal class Program
    {
        private static readonly rgatState _rgatState = new rgatState();

        private static void Main(string[] args)
        {
            // Bad arguments given or an info argument that is supposed to exit immediately
            if (!InitOptions(args) || HandleImmediateExitOptions())
            {
                return;
            }

            InitialSetup();

            switch (GlobalConfig.StartOptions!.ActiveRunMode)
            {
                case LaunchConfig.RunMode.GUI:
                    rgatState.NetworkBridge.GUIMode = true;
                    ImGuiRunner Ui = new ImGuiRunner(_rgatState);
                    try
                    {
                        Ui.Run();
                    }
                    catch (Exception e)
                    {
                        Logging.RecordException($"Exception in outer GUI Runner: {e.Message}", e);
                    }
                    break;

                case LaunchConfig.RunMode.Bridged:
                    rgatState.NetworkBridge.GUIMode = false;
                    BridgedRunner bridge = new BridgedRunner();
                    try
                    {
                        bridge.RunHeadless(rgatState.NetworkBridge);
                    }
                    catch (Exception e)
                    {
                        Logging.RecordException($"Exception in outer RunHeadless: {e.Message}", e);

                    }
                    finally
                    {
                        Logging.WriteConsole("Headless mode complete");
                        rgatState.Shutdown();
                    }
                    break;

                case LaunchConfig.RunMode.NoGPUTraceCommand: //...did i implement this already? when did that happpen??
                    if (GlobalConfig.StartOptions.TargetPath is null)
                    {
                        Logging.RecordError("No target path"); return;
                    }
                    rgatState.NetworkBridge.GUIMode = false;
                    CommandLineRunner runner = new CommandLineRunner();
                    runner.InitNoGPU();
                    CommandLineRunner.TraceBinary(GlobalConfig.StartOptions.TargetPath, saveDirectory: GlobalConfig.StartOptions.TraceSaveDirectory, recordVideo: false);
                    break;

                case LaunchConfig.RunMode.GPURenderCommand://not supported in 0.6.0
                    rgatState.NetworkBridge.GUIMode = false;
                    Logging.RecordError("Command line media output not yet implemented");
                    return;
                //runner = new CommandLineRunner();
                //runner.InitGPU();
                //runner.TraceBinary(GlobalConfig.StartOptions.TargetPath, saveDirectory: GlobalConfig.StartOptions.TraceSaveDirectory, recordVideo: GlobalConfig.StartOptions.RecordVideoLive);
                //break;


                default:
                    Logging.RecordError($"Bad Run Mode: {GlobalConfig.StartOptions.ActiveRunMode}");
                    break;
            }
        }

        private static bool InitOptions(string[] cmdlineParams)
        {

            var parser = new Parser(with =>
            {
                with.GetoptMode = true;
                with.AutoHelp = true;
                with.AutoVersion = true;
                with.CaseSensitive = true;
                with.EnableDashDash = false;
            });

            ParserResult<LaunchConfig> result = Parser.Default.ParseArguments<LaunchConfig>(cmdlineParams)
               .WithParsed(cmdlineOpts =>
               {
                   if (!cmdlineOpts.ExtractJSONOptions(out string? error))
                   {
                       Logging.WriteConsole($"Error: Bad JSON configuration blob - {error}");
                   }
                   else
                   {
                       cmdlineOpts.Init(cmdlineParams);

                       GlobalConfig.StartOptions = cmdlineOpts;
                       if (GlobalConfig.StartOptions.ActiveRunMode == LaunchConfig.RunMode.Invalid)
                       {
                           Logging.WriteConsole($"Error: With GUI disabled and no valid network configuration or target to trace, I could not work out what to do. Quitting.");
                       }
                   }
               });



            return result.Tag != ParserResultType.NotParsed && GlobalConfig.StartOptions != null;
        }


        private static bool HandleImmediateExitOptions()
        {
            bool exit = false;
            //list valid network interfaces if the -i param was provided with a list arg or invalid interface
            string? interfaceOption = GlobalConfig.StartOptions!.Interface;
            if (interfaceOption != null)
            {
                HandleInterfaceParam(interfaceOption, ref exit);
            }

            if (GlobalConfig.StartOptions.FFmpegPath != null)
            {
                HandleFFmpegParam(GlobalConfig.StartOptions.FFmpegPath, ref exit);
            }

            return exit;
        }


        private static void HandleInterfaceParam(string interfaceOption, ref bool exit)
        {
            LaunchConfig startOpts = GlobalConfig.StartOptions!;
            switch (interfaceOption)
            {
                case "list all":
                case "show all":
                case "print all":
                    NetworkUtilities.PrintInterfaces(PrintInvalid: true);
                    exit = true;
                    break;

                case "":
                case "help":
                case "list":
                case "show":
                case "print":
                case "?":
                    NetworkUtilities.PrintInterfaces();
                    exit = true;
                    break;

                case "all":
                case "any":
                    if (startOpts.ActiveRunMode == LaunchConfig.RunMode.Bridged)
                    {
                        startOpts.Interface = "0.0.0.0";
                    }
                    break;

                default:
                    {
                        if (startOpts.ActiveRunMode != LaunchConfig.RunMode.Bridged)
                        {
                            return;
                        }

                        if (!System.Net.IPAddress.TryParse(startOpts.Interface, out System.Net.IPAddress? address) ||
                            int.TryParse(startOpts.Interface, out int ipInt) && ipInt > 0 && ipInt < 128)
                        {
                            //see if it matches a property from the interface list
                            startOpts.ActiveNetworkInterface = NetworkUtilities.ValidateNetworkInterface(interfaceOption);
                            if (startOpts.ActiveNetworkInterface == null)
                            {
                                Logging.WriteConsole($"Error: Specified network interface '{interfaceOption}' could not be matched to a valid network interface\n");
                                NetworkUtilities.PrintInterfaces();
                                exit = true;
                            }
                        }
                        break;
                    }
            }
        }

        private static void HandleFFmpegParam(string ffmpegopt, ref bool exit)
        {
            if (ffmpegopt == "")
            {
                string fpmpath = GlobalConfig.GetSettingPath(CONSTANTS.PathKey.FFmpegPath);

                if (System.IO.File.Exists(fpmpath))
                {
                    Logging.WriteConsole($"The FFmpeg encoder is configured: '{fpmpath}'");
                }
                else
                {
                    Logging.WriteConsole($"The FFmpeg encoder is not correctly configured. Path: '{fpmpath}'");
                }

                exit = true;
            }
            else
            {
                if (System.IO.File.Exists(ffmpegopt))
                {
                    GlobalConfig.SetBinaryPath(CONSTANTS.PathKey.FFmpegPath, ffmpegopt);
                    Logging.WriteConsole($"The FFmpeg encoder is now set to ('{ffmpegopt}')");
                }
                else
                {
                    Logging.WriteConsole($"The FFmpeg encoder file supplied cannot be found: {ffmpegopt}");
                }
            }
        }



        //initialise things that are used in all types of tracing (ui, bridged, commandline)
        private static void InitialSetup()
        {

            AppDomain currentDomain = AppDomain.CurrentDomain;
            currentDomain.UnhandledException += new UnhandledExceptionEventHandler(UnhandledExceptionHandler);

            rgat.Threads.TraceProcessorWorker.SetRgatState(_rgatState);
        }

        private static void UnhandledExceptionHandler(object sender, UnhandledExceptionEventArgs args)
        {
            Exception e = (Exception)args.ExceptionObject;
            Logging.RecordError($"Unhandled Exception: {e.Source}:{e.Message}");
        }

    }
}
