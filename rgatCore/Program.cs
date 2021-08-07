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
        private static Sdl2Window _window;
        private static GraphicsDevice _gd;
        private static CommandList _cl;
        private static ImGuiController _controller;
        static rgatState _rgatState = new rgatState();

        private static rgatUI _rgatui = null;

        // UI state
        private static Vector3 _clearColor = new Vector3(0.15f, 0.15f, 0.16f);
        private static bool _showDemoWindow = true;
        static Vector2 _lastMousePos;

        static List<Key> HeldResponsiveKeys = new List<Key>();

        static System.Timers.Timer _housekeepingTimer;
        static bool _housekeepingTimerFired;


        static void Main(string[] args)
        {

            if (!InitOptions(args))
            {
                return;
            }

            if (HandleImmediateExitOptions()) return;

            InitialSetup();

            if (!GlobalConfig.StartOptions.NoGUI)
            {
                GUIMain();
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
        /// Runs a standard UI window loop using ImGui
        /// </summary>
        static void GUIMain()
        {
            GUISetup();

            while (_window.Exists)
            {
                GUIUpdate();
            }

            GUICleanup();
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



        private static void GUISetup()
        {
            System.Threading.Thread.CurrentThread.Name = "rgatUIMain";
            Logging.RecordLogEvent("rgat is starting", Logging.LogFilterType.TextDebug);

            GraphicsDeviceOptions options = new GraphicsDeviceOptions(
            debug: true,
            swapchainDepthFormat: PixelFormat.R8_UNorm,
            syncToVerticalBlank: true,
            resourceBindingModel: ResourceBindingModel.Improved,
            preferDepthRangeZeroToOne: true,
            preferStandardClipSpaceYDirection: false);

            VeldridStartup.CreateWindowAndGraphicsDevice(
                new WindowCreateInfo(50, 50, 1800, 900, WindowState.Normal, "rgat"),
                //new GraphicsDeviceOptions(true, null, true, ResourceBindingModel.Improved, true, true),
                options,
                preferredBackend: GraphicsBackend.Vulkan,
                out _window,
                out _gd);

            _lastMousePos = new Vector2(0, 0);

            _window.Resized += () =>
            {
                _gd.MainSwapchain.Resize((uint)_window.Width, (uint)_window.Height);
                _controller.WindowResized(_window.Width, _window.Height);
                _rgatui?.AlertResized(new Vector2(_window.Width, _window.Height));
            };
            _cl = _gd.ResourceFactory.CreateCommandList();
            _controller = new ImGuiController(_gd, _gd.MainSwapchain.Framebuffer.OutputDescription, _window.Width, _window.Height);

            _rgatui = new rgatUI(_rgatState, _controller, _gd, _cl);

            _window.KeyDown += (KeyEvent k) =>
            {
                if (GlobalConfig.ResponsiveKeys.Contains(k.Key))
                {
                    if (!HeldResponsiveKeys.Contains(k.Key))
                        HeldResponsiveKeys.Add(k.Key);
                }
                else
                {
                    _rgatui.AlertKeyEvent(new Tuple<Key, ModifierKeys>(k.Key, k.Modifiers));
                }
            };
            _window.KeyUp += (KeyEvent k) =>
            {
                HeldResponsiveKeys.RemoveAll(key => key == k.Key);
            };


            _window.MouseWheel += (MouseWheelEventArgs mw) => _rgatui.AlertMouseWheel(mw);
            _window.MouseMove += (MouseMoveEventArgs mm) =>
            {
                _rgatui.AlertMouseMove(mm.State, _lastMousePos - mm.MousePosition);
                _lastMousePos = mm.MousePosition;
            };


            _housekeepingTimer = new System.Timers.Timer(60000);
            _housekeepingTimer.Elapsed += FireTimer;
            _housekeepingTimer.AutoReset = false;
            _housekeepingTimer.Start();

            ImGui.GetIO().ConfigWindowsMoveFromTitleBarOnly = true;
        }

        private static void FireTimer(object sender, System.Timers.ElapsedEventArgs e) { _housekeepingTimerFired = true; }

        private static void GUIUpdate()
        {
            InputSnapshot snapshot = _window.PumpEvents();
            if (!_window.Exists) { return; }

            HeldResponsiveKeys.ForEach(key => _rgatui.AlertResponsiveKeyEvent(key));

            _controller.Update(1f / 60f, snapshot); // Feed the input events to our ImGui controller, which passes them through to ImGui.

            if (!_rgatui.DrawUI())
            {
                _window.Close();
            }

            if (_controller.ShowDemoWindow)
            {
                ImGui.ShowDemoWindow(ref _showDemoWindow);
            }
            _gd.WaitForIdle();
            _cl.Begin();
            _cl.SetFramebuffer(_gd.MainSwapchain.Framebuffer);
            _cl.ClearColorTarget(0, new RgbaFloat(_clearColor.X, _clearColor.Y, _clearColor.Z, 1f));
            _controller.Render(_gd, _cl);

            _cl.End();

            _gd.SubmitCommands(_cl);
            _gd.SwapBuffers(_gd.MainSwapchain);

            _gd.WaitForIdle();

            _rgatui.ProcessFramebuffer(_gd.MainSwapchain.Framebuffer, _cl);


            if (_housekeepingTimerFired)
            {
                _controller.ClearCachedImageResources();
                _housekeepingTimerFired = false;
                _housekeepingTimer.Start();
            }

        }

        private static void GUICleanup()
        {
            _rgatui.Exit();
            // Clean up Veldrid resources
            _gd.WaitForIdle();
            _controller.Dispose();
            _cl.Dispose();
            _gd.Dispose();
        }
    }
}
