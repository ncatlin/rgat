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
        private static MemoryEditor _memoryEditor;

        private static rgatUI _rgatui = null;

        // UI state
        private static float _f = 0.0f;
        private static int _counter = 0;
        private static int _dragInt = 0;
        private static Vector3 _clearColor = new Vector3(0.15f, 0.15f, 0.16f);
        private static bool _showDemoWindow = true;
        private static bool _showAnotherWindow = false;
        private static bool _showMemoryEditor = false;
        private static byte[] _memoryEditorData;
        private static uint s_tab_bar_flags = (uint)ImGuiTabBarFlags.Reorderable;
        static bool[] s_opened = { true, true, true, true }; // Persistent user state
        static Vector2 _lastMousePos;

        static void SetThing(out float i, float val) { i = val; }
        static List<Key> HeldResponsiveKeys = new List<Key>();

        static System.Timers.Timer _housekeepingTimer;
        static bool _housekeepingTimerFired;


        static void Main(string[] args)
        {

            if (!InitOptions(args))
            {
                Console.WriteLine($"Bad Launch options. Exiting");
                return;
            }

            if (HandleImmediateExitOptions()) return;


            if (!GlobalConfig.StartOptions.NoGUI)
            {
                ImGuiMain();
            }
            else
            {
                NoGuiMain();
            }
        }

        static bool InitOptions(string [] cmdlineParams)
        {
            Parser.Default.ParseArguments<LaunchConfig>(cmdlineParams)
               .WithParsed(cmdlineOpts =>
               {
                   if (!cmdlineOpts.ExtractJSONOptions(out string error))
                   {
                       Console.WriteLine($"Error: Bad configuration blob - {error}");
                   }

                   GlobalConfig.StartOptions = cmdlineOpts;
               });
            
            return GlobalConfig.StartOptions != null;
        }

        static bool HandleImmediateExitOptions()
        {
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
                        return true;

                    case "help":
                    case "list":
                    case "show":
                    case "print":
                    case "?":
                        RemoteTracing.PrintInterfaces();
                        return true;

                    default:
                        GlobalConfig.StartOptions.ActiveNetworkInterface = RemoteTracing.ValidateNetworkInterface(interfaceOption);
                        if (GlobalConfig.StartOptions.ActiveNetworkInterface == null)
                        {
                            Console.WriteLine($"Error: Specified network interface '{interfaceOption}' could not be matched to a valid network interface");
                            Console.WriteLine("");
                            RemoteTracing.PrintInterfaces();
                            return true;
                        }
                        break;
                }
            }
            return false;
        }

        static void ImGuiMain()
        {
            Setup();

            while (_window.Exists)
            {
                Update();
            }

            Cleanup();
        }
                
        static void NoGuiMain()
        {
            Console.WriteLine("Starting command line mode");
        }





        private static void Setup()
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
            _memoryEditor = new MemoryEditor();
            Random random = new Random();
            _memoryEditorData = Enumerable.Range(0, 1024).Select(i => (byte)random.Next(255)).ToArray();

            _rgatui = new rgatUI(_controller, _gd, _cl);

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

        private static void Update()
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
                SubmitDemoUI();
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

        private static void Cleanup()
        {
            _rgatui.Exit();
            // Clean up Veldrid resources
            _gd.WaitForIdle();
            _controller.Dispose();
            _cl.Dispose();
            _gd.Dispose();
        }


        private static unsafe void SubmitDemoUI()
        {

            // Demo code adapted from the official Dear ImGui demo program:
            // https://github.com/ocornut/imgui/blob/master/examples/example_win32_directx11/main.cpp#L172

            // 1. Show a simple window.
            // Tip: if we don't call ImGui.BeginWindow()/ImGui.EndWindow() the widgets automatically appears in a window called "Debug".
            {
                ImGui.Text("Hello, world!");                                        // Display some text (you can use a format string too)
                ImGui.SliderFloat("float", ref _f, 0, 1, _f.ToString("0.000"));  // Edit 1 float using a slider from 0.0f to 1.0f    
                                                                                 //ImGui.ColorEdit3("clear color", ref _clearColor);                   // Edit 3 floats representing a color

                ImGui.Text($"Mouse position: {ImGui.GetMousePos()}");

                ImGui.SetNextWindowPos(new Vector2(800, 200));
                ImGui.Checkbox("Demo Window", ref _showDemoWindow);                 // Edit bools storing our windows open/close state
                ImGui.Checkbox("Another Window", ref _showAnotherWindow);
                ImGui.Checkbox("Memory Editor", ref _showMemoryEditor);
                if (ImGui.Button("Button"))                                         // Buttons return true when clicked (NB: most widgets return true when edited/activated)
                    _counter++;
                ImGui.SameLine(0, -1);
                ImGui.Text($"counter = {_counter}");

                ImGui.DragInt("Draggable Int", ref _dragInt);

                float framerate = ImGui.GetIO().Framerate;
                ImGui.Text($"Application average {1000.0f / framerate:0.##} ms/frame ({framerate:0.#} FPS)");
            }
            // 2. Show another simple window. In most cases you will use an explicit Begin/End pair to name your windows.
            if (_showAnotherWindow)
            {
                ImGui.Begin("Another Window", ref _showAnotherWindow);
                ImGui.Text("Hello from another window!");
                if (ImGui.Button("Close Me"))
                    _showAnotherWindow = false;
                ImGui.End();
            }

            // 3. Show the ImGui demo window. Most of the sample code is in ImGui.ShowDemoWindow(). Read its code to learn more about Dear ImGui!
            if (_showDemoWindow)
            {
                // Normally user code doesn't need/want to call this because positions are saved in .ini file anyway.
                // Here we just want to make the demo initial state a bit more friendly!
                ImGui.SetNextWindowPos(new Vector2(650, 20), ImGuiCond.FirstUseEver);
                ImGui.ShowDemoWindow(ref _showDemoWindow);
            }

            if (ImGui.TreeNode("Tabs"))
            {
                if (ImGui.TreeNode("Basic"))
                {
                    ImGuiTabBarFlags tab_bar_flags = ImGuiTabBarFlags.None;
                    if (ImGui.BeginTabBar("MyTabBar", tab_bar_flags))
                    {
                        if (ImGui.BeginTabItem("Avocado"))
                        {
                            ImGui.Text("This is the Avocado tab!\nblah blah blah blah blah");
                            ImGui.EndTabItem();
                        }
                        if (ImGui.BeginTabItem("Broccoli"))
                        {
                            ImGui.Text("This is the Broccoli tab!\nblah blah blah blah blah");
                            ImGui.EndTabItem();
                        }
                        if (ImGui.BeginTabItem("Cucumber"))
                        {
                            ImGui.Text("This is the Cucumber tab!\nblah blah blah blah blah");
                            ImGui.EndTabItem();
                        }
                        ImGui.EndTabBar();
                    }
                    ImGui.Separator();
                    ImGui.TreePop();
                }

                if (ImGui.TreeNode("Advanced & Close Button"))
                {
                    // Expose a couple of the available flags. In most cases you may just call BeginTabBar() with no flags (0).
                    ImGui.CheckboxFlags("ImGuiTabBarFlags_Reorderable", ref s_tab_bar_flags, (uint)ImGuiTabBarFlags.Reorderable);
                    ImGui.CheckboxFlags("ImGuiTabBarFlags_AutoSelectNewTabs", ref s_tab_bar_flags, (uint)ImGuiTabBarFlags.AutoSelectNewTabs);
                    ImGui.CheckboxFlags("ImGuiTabBarFlags_NoCloseWithMiddleMouseButton", ref s_tab_bar_flags, (uint)ImGuiTabBarFlags.NoCloseWithMiddleMouseButton);
                    if ((s_tab_bar_flags & (uint)ImGuiTabBarFlags.FittingPolicyMask) == 0)
                        s_tab_bar_flags |= (uint)ImGuiTabBarFlags.FittingPolicyDefault;
                    if (ImGui.CheckboxFlags("ImGuiTabBarFlags_FittingPolicyResizeDown", ref s_tab_bar_flags, (uint)ImGuiTabBarFlags.FittingPolicyResizeDown))
                        s_tab_bar_flags &= ~((uint)ImGuiTabBarFlags.FittingPolicyMask ^ (uint)ImGuiTabBarFlags.FittingPolicyResizeDown);
                    if (ImGui.CheckboxFlags("ImGuiTabBarFlags_FittingPolicyScroll", ref s_tab_bar_flags, (uint)ImGuiTabBarFlags.FittingPolicyScroll))
                        s_tab_bar_flags &= ~((uint)ImGuiTabBarFlags.FittingPolicyMask ^ (uint)ImGuiTabBarFlags.FittingPolicyScroll);

                    // Tab Bar
                    string[] names = { "Artichoke", "Beetroot", "Celery", "Daikon" };

                    for (int n = 0; n < s_opened.Length; n++)
                    {
                        if (n > 0) { ImGui.SameLine(); }
                        ImGui.Checkbox(names[n], ref s_opened[n]);
                    }

                    // Passing a bool* to BeginTabItem() is similar to passing one to Begin(): the underlying bool will be set to false when the tab is closed.
                    if (ImGui.BeginTabBar("MyTabBar", (ImGuiTabBarFlags)s_tab_bar_flags))
                    {
                        for (int n = 0; n < s_opened.Length; n++)
                            if (s_opened[n] && ImGui.BeginTabItem(names[n], ref s_opened[n]))
                            {
                                ImGui.Text($"This is the {names[n]} tab!");
                                if ((n & 1) != 0)
                                    ImGui.Text("I am an odd tab.");
                                ImGui.EndTabItem();
                            }
                        ImGui.EndTabBar();
                    }
                    ImGui.Separator();
                    ImGui.TreePop();
                }
                ImGui.TreePop();
            }

            ImGuiIOPtr io = ImGui.GetIO();

            SetThing(out io.DeltaTime, 2f);

            if (_showMemoryEditor)
            {
                _memoryEditor.Draw("Memory Editor", _memoryEditorData, _memoryEditorData.Length);
            }
        }
    }
}
