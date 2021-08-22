using ImGuiNET;
using rgat.Threads;
using rgat.Widgets;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Veldrid;
using Veldrid.Sdl2;

namespace rgat.OperationModes
{
    /// <summary>
    /// Creates and manages a Veldrid/ImGui based rgat GUI
    /// This requires access to a GPU (with Vulkan drivers)
    /// </summary>
    class ImGuiRunner
    {

        //rgat ui state

        private ImGuiController _controller = null;

        //rgat program state
        private rgatState _rgatState;

        Threads.HeatRankingThread heatRankThreadObj = null;

        rgatUI _rgatUI;

        Vector2 WindowStartPos = new Vector2(100f, 100f);
        Vector2 WindowOffset = new Vector2(0, 0);


        public ImGuiRunner(rgatState state)
        {
            _rgatState = state;
        }


        private Sdl2Window _window;
        private GraphicsDevice _gd;
        private CommandList _cl;

        // UI state
        private static Vector3 _clearColor = new Vector3(0.15f, 0.15f, 0.16f);
        private static bool _showDemoWindow = true;
        static Vector2 _lastMousePos;

        static List<Key> HeldResponsiveKeys = new List<Key>();


        //perform rare events like freeing resources which havent been used in a while
        static System.Timers.Timer _longTimer;
        static bool _housekeepingTimerFired;
        private void FireLongTimer(object sender, System.Timers.ElapsedEventArgs e) { _housekeepingTimerFired = true; }

        //perform regular events
        System.Timers.Timer _shortTimer;
        bool _frameTimerFired = false;
        private void FireShortTimer(object sender, System.Timers.ElapsedEventArgs e) { _frameTimerFired = true; }

        /// <summary>
        /// Runs a standard UI window loop using ImGui
        /// </summary>
        public void Run()
        {
            Console.WriteLine("Runstart");
            Logging.RecordLogEvent("rgat is starting in GUI mode", Logging.LogFilterType.TextDebug);

            if (!Setup())
            {
                Console.WriteLine($"------------------------------------------------------------------------------------");
                Console.WriteLine($"The rgat UI and graph layout engine is GPU based, requiring access to the Vulkan API");
                Console.WriteLine($"If https://github.com/skeeto/vulkan-test doesn't work then neither will rgat rendering.");
                Console.WriteLine($"If your GPU or analysis environment does does not support this then you can still perform\n" +
                    $"tracing and load the result using rgat on another machine, or perform tracing directly over a network."); 
                Console.WriteLine("Run 'rgat.exe ?' for the available options");
                Console.WriteLine($"------------------------------------------------------------------------------------");
                return;
            }

            while (_window.Exists && !_rgatUI.ExitFlag)
            {
                Update();
            }

            Cleanup();
        }

        private bool Setup()
        {
            System.Threading.Thread.CurrentThread.Name = "rgatUIMain";

            GraphicsDeviceOptions options = new GraphicsDeviceOptions(
            debug: true,
            swapchainDepthFormat: PixelFormat.R8_UNorm,
            syncToVerticalBlank: true,
            resourceBindingModel: ResourceBindingModel.Improved,
            preferDepthRangeZeroToOne: true,
            preferStandardClipSpaceYDirection: false);
            bool loadSuccess = false;
            try
            {
                Veldrid.StartupUtilities.VeldridStartup.CreateWindowAndGraphicsDevice(
                    new Veldrid.StartupUtilities.WindowCreateInfo(50, 50, 1800, 900, WindowState.Normal, "rgat"),
                    //new GraphicsDeviceOptions(true, null, true, ResourceBindingModel.Improved, true, true),
                    options,
                    preferredBackend: GraphicsBackend.Vulkan,
                    out _window,
                    out _gd);
                loadSuccess = true;
            }
            catch (System.TypeInitializationException e)
            {
                if (e.InnerException != null)
                {
                    if (e.InnerException.GetType() == typeof(System.InvalidOperationException))
                    {
                        Logging.RecordLogEvent($"Error: Unable to initialise the Vulkan graphics driver: {e.InnerException.Message}", Logging.LogFilterType.TextError);
                    }
                }
                else
                {
                    Logging.RecordLogEvent($"Error: Unable to initialise the Vulkan graphics driver. {e.Message}", Logging.LogFilterType.TextError);
                }
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Error 2: unable to initialise the Vulkan drivers. {e.Message}", Logging.LogFilterType.TextError);
            }

            if (!loadSuccess) return false;

            _cl = _gd.ResourceFactory.CreateCommandList();
            _rgatState.InitVeldrid(_gd, _cl);
            _controller = new ImGuiController(_gd, _gd.MainSwapchain.Framebuffer.OutputDescription, _window.Width, _window.Height);
            MediaDrawing.SetController(_controller);

            _rgatUI = new rgatUI(_rgatState, _controller);

            //load in a thread to keep things interactive
            Task.Run(() => LoadingThread(_controller, _gd));

            InitEventHandlers();

            ImGui.GetIO().ConfigWindowsMoveFromTitleBarOnly = true;
            return true;
        }

        void InitEventHandlers()
        {

            _window.Resized += () =>
            {
                _gd.MainSwapchain.Resize((uint)_window.Width, (uint)_window.Height);
                _controller.WindowResized(_window.Width, _window.Height);
                AlertResized(new Vector2(_window.Width, _window.Height));
            };

            _window.KeyDown += (KeyEvent k) =>
            {
                if (GlobalConfig.ResponsiveKeys.Contains(k.Key))
                {
                    if (!HeldResponsiveKeys.Contains(k.Key)) HeldResponsiveKeys.Add(k.Key);
                }
                else
                {
                    AlertKeyEvent(new Tuple<Key, ModifierKeys>(k.Key, k.Modifiers));
                }
            };

            _window.KeyUp += (KeyEvent k) => HeldResponsiveKeys.RemoveAll(key => key == k.Key);
            _window.MouseWheel += (MouseWheelEventArgs mw) => AlertMouseWheel(mw);
            _window.MouseMove += (MouseMoveEventArgs mm) => AlertMouseMove(mm, _lastMousePos - mm.MousePosition);
            _window.DragDrop += (DragDropEvent dd) => AlertDragDrop(dd);

            _lastMousePos = new Vector2(0, 0);

            _shortTimer = new System.Timers.Timer(RGAT_CONSTANTS.UI.UI_SHORT_TIMER_INTERVAL);
            _shortTimer.Elapsed += FireShortTimer;
            _shortTimer.AutoReset = true;
            _shortTimer.Start();

            _longTimer = new System.Timers.Timer(RGAT_CONSTANTS.UI.UI_LONG_TIMER_INTERVAL);
            _longTimer.Elapsed += FireLongTimer;
            _longTimer.AutoReset = false;
            _longTimer.Start();
        }


        private void Update()
        {
            InputSnapshot snapshot = _window.PumpEvents();
            if (!_window.Exists) { return; }

            HeldResponsiveKeys.ForEach(key => AlertResponsiveKeyEvent(key));

            _controller.Update(1f / 60f, snapshot); // Feed the input events to our ImGui controller, which passes them through to ImGui.

            if (!DrawUI())
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

            RecordFramebuffer(_gd.MainSwapchain.Framebuffer, _cl);

            if (_housekeepingTimerFired)
            {
                _controller.ClearCachedImageResources();
                _housekeepingTimerFired = false;
                _longTimer.Start();
            }

        }

        unsafe public void RecordFramebuffer(Framebuffer fbuf, CommandList cl)
        {
            //exit if no video capture or screenshot pending
            VideoEncoder recorder = rgatState.VideoRecorder;
            if ((recorder == null || !recorder.Recording) && _rgatUI.PendingScreenshot == VideoEncoder.CaptureContent.Invalid) return;


            if (rgatState.VideoRecorder.Recording && !rgatState.VideoRecorder.CapturePaused)
            {

                _rgatUI.GetFrameDimensions(rgatState.VideoRecorder.GetCapturedContent(), out int startX, out int startY, out int width, out int height);
                System.Drawing.Bitmap videoBmp = MediaDrawing.CreateRecordingFrame(fbuf, startX, startY, width, height);
                rgatState.VideoRecorder.QueueFrame(videoBmp, _rgatState.ActiveGraph);
            }

            if (_rgatUI.PendingScreenshot != VideoEncoder.CaptureContent.Invalid)
            {
                try
                {
                    _rgatUI.GetFrameDimensions(_rgatUI.PendingScreenshot, out int startX, out int startY, out int width, out int height);
                    System.Drawing.Bitmap screenBmp = MediaDrawing.CreateRecordingFrame(fbuf, startX, startY, width, height);
                    rgatState.VideoRecorder.TakeScreenshot(_rgatState.ActiveGraph, screenBmp);
                }
                catch (Exception e)
                {
                    Logging.RecordLogEvent($"Unhandled exception while taking screenshot {_rgatUI.PendingScreenshot}: {e.Message}");
                }
                _rgatUI.PendingScreenshot = VideoEncoder.CaptureContent.Invalid;
            }
        }

        private void Cleanup()
        {
            Exit();
            // Clean up Veldrid resources
            _gd.WaitForIdle();
            _controller.Dispose();
            _cl.Dispose();
            _gd.Dispose();
        }





        //todo - make Exit wait until this returns
        void LoadingThread(ImGuiController imguicontroller, GraphicsDevice _gd)
        {

            Logging.RecordLogEvent("Constructing rgatUI: Initing/Loading Config", Logging.LogFilterType.TextDebug); //about 800 ish ms
            double currentUIProgress = _rgatUI.StartupProgress;
            Task confloader = Task.Run(() => GlobalConfig.LoadConfig());
            while (!confloader.IsCompleted)
            {
                _rgatUI.StartupProgress = currentUIProgress + 0.3 * GlobalConfig.LoadProgress;
                Thread.Sleep(10);
            }

            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
            {
                WinAPIDetails.Load(System.IO.Path.Combine(AppContext.BaseDirectory, "APIData.json"));
            }

            Logging.RecordLogEvent("Startup: Config Inited", Logging.LogFilterType.TextDebug);
            _rgatUI.StartupProgress = 0.4;

            Logging.RecordLogEvent("Startup: Initing State Object", Logging.LogFilterType.TextDebug);


            Logging.RecordLogEvent("Startup: State created", Logging.LogFilterType.TextDebug);
            _rgatUI.StartupProgress = 0.5;


            Logging.RecordLogEvent("Startup: Initing Settings Window", Logging.LogFilterType.TextDebug);

            _rgatUI.InitWidgets();



            rgatState.VideoRecorder.Load();

            Logging.RecordLogEvent("Startup: Initing graph rendering threads", Logging.LogFilterType.TextDebug);



            heatRankThreadObj = null;// new HeatRankingThread(_rgatstate);           

            //todo - conditional thread here instead of new trace
            rgatState.processCoordinatorThreadObj = new ProcessCoordinatorThread();
            rgatState.processCoordinatorThreadObj.Begin();
            _rgatUI.StartupProgress = 0.95;

            Logging.RecordLogEvent("Startup: Initing layout engines", Logging.LogFilterType.TextDebug);
            _rgatUI.StartupProgress = 0.99;


            Logging.RecordLogEvent("Startup: rgatUI created", Logging.LogFilterType.TextDebug);

            _rgatState.LoadSignatures();

            Logging.RecordLogEvent("Startup: Signatures Loaded", Logging.LogFilterType.TextDebug);

            _rgatUI.StartupProgress = 1;

        }


        public void Exit()
        {
            if (GlobalConfig.BulkLogging)
                Logging.RecordLogEvent("rgat Exit() triggered", Logging.LogFilterType.BulkDebugLogFile);

            rgatState.Shutdown();

            //wait for the ui stop stop and the main renderer to quit
            while (
                (!_UIStopped && Thread.CurrentThread.Name != "rgatUIMain") || _rgatUI.ThreadsRunning)
            {
                Thread.Sleep(10);
            }

        }


        public void AlertResized(Vector2 size)
        {

        }


        public void AlertKeyEvent(Tuple<Key, ModifierKeys> keyCombo) => _rgatUI.AddKeyPress(keyCombo);

        public void AlertResponsiveKeyEvent(Key key) => _rgatUI.AddKeyPress(new Tuple<Key, ModifierKeys>(key, ModifierKeys.None));

        public void AlertDragDrop(DragDropEvent dd)
        {
            _rgatUI.LoadSelectedBinary(dd.File, false);
        } 

        public void AlertMouseWheel(MouseWheelEventArgs mw)
        {
            float thisDelta = mw.WheelDelta;
            if (ImGui.GetIO().KeyShift) { thisDelta *= 10; }
            _rgatUI.AddMouseWheelDelta(thisDelta);
        }

        public void AlertMouseMove(MouseMoveEventArgs mm, Vector2 delta)
        {
            if (mm.State.IsButtonDown(MouseButton.Left) || mm.State.IsButtonDown(MouseButton.Right))
            {
                if (ImGui.GetIO().KeyShift) { delta = new Vector2(delta.X * 10, delta.Y * 10); }
                _rgatUI.AddMouseDragDelta(delta);
            }
            _lastMousePos = mm.MousePosition;
        }


        bool _UIStopped = false;
        public bool DrawUI()
        {
            if (rgatState.RgatIsExiting)
            {
                _UIStopped = true;
                return false;
            }

            var timer = new System.Diagnostics.Stopwatch();
            timer.Start();

            bool hasActiveTrace = _rgatState?.ActiveTarget != null;

            ImGuiWindowFlags window_flags = ImGuiWindowFlags.None;
            window_flags |= ImGuiWindowFlags.NoDecoration;
            if (hasActiveTrace)
            {
                window_flags |= ImGuiWindowFlags.MenuBar;
            }
            window_flags |= ImGuiWindowFlags.DockNodeHost;
            window_flags |= ImGuiWindowFlags.NoBringToFrontOnFocus;

            ImGui.GetIO().ConfigWindowsMoveFromTitleBarOnly = true;
            //ImGui.GetIO().ConfigWindowsResizeFromEdges = true;

            ImGui.SetNextWindowPos(new Vector2(0, 0), ImGuiCond.Always);

            ImGui.SetNextWindowSize(new Vector2(_controller._windowWidth, _controller._windowHeight), ImGuiCond.Always);
            //ImGui.SetNextWindowSize(new Vector2(1200, 800), ImGuiCond.Appearing);

            Themes.ApplyThemeColours();

            ImGui.Begin("rgat Primary Window", window_flags);

            {
                WindowOffset = ImGui.GetWindowPos() - WindowStartPos;

                _rgatUI.HandleUserInput();
                _rgatUI.DrawMain();
                _rgatUI.DrawDialogs();
                _rgatUI.CleanupFrame();
                


                Themes.ResetThemeColours();
            }
            ImGui.End();

            timer.Stop();
            _rgatUI.UpdateFrameStats(timer.ElapsedMilliseconds);

            if (_frameTimerFired)
            {
                _frameTimerFired = false;
                _rgatUI.ShortTimerFired();
            }



            return true;
        }



    }
}
