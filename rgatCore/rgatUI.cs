using ImGuiNET;
using SharpDX.DXGI;
using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Xml.Linq;
using Veldrid.SPIRV;


using Veldrid;
using Veldrid.Sdl2;
using Veldrid.StartupUtilities;
using System.Linq;
using rgatCore.Threads;
using Microsoft.VisualBasic;

namespace rgatCore
{
    class rgatUI
    {
        //rgat ui state
        private bool _settings_window_shown = false;
        private bool _show_select_exe_window = false;
        private bool _show_load_trace_window = false;
        private ImGuiController _ImGuiController = null;

        //rgat program state
        private rgatState _rgatstate = null;
        private int _selectedInstrumentationEngine = 0;

        Threads.MainGraphRenderThread mainRenderThreadObj = null;
        ProcessCoordinatorThread processCoordinatorThreadObj = null;

        GraphPlotWidget MainGraphWidget = null;
        PreviewGraphsWidget PreviewGraphWidget = null;
        Vector2 WindowStartPos = new Vector2(100f, 100f);
        Vector2 WindowOffset = new Vector2(0, 0);

        public rgatUI(ImGuiController imguicontroller, GraphicsDevice _gd, CommandList _cl)
        {
            _rgatstate = new rgatState(_gd, _cl);
            GlobalConfig.InitDefaultConfig();

            _ImGuiController = imguicontroller;


            mainRenderThreadObj = new Threads.MainGraphRenderThread(_rgatstate);

            processCoordinatorThreadObj = new ProcessCoordinatorThread(_rgatstate);

            MainGraphWidget = new GraphPlotWidget();
            PreviewGraphWidget = new PreviewGraphsWidget();

        }

        public void Exit()
        {
            _rgatstate.ShutdownRGAT();
        }

        public void AlertResized(Vector2 size)
        {
            MainGraphWidget?.AlertResized(size);
        }


        private bool finit = false;
        public void DrawUI()
        {

            if (!finit)
            {


                finit = true;
            }


            //Console.WriteLine(ImGui.GetWindowViewport());

            ImGuiWindowFlags window_flags = ImGuiWindowFlags.None;
            //window_flags |= ImGuiWindowFlags.NoTitleBar;
            window_flags |= ImGuiWindowFlags.MenuBar;
            window_flags |= ImGuiWindowFlags.DockNodeHost;

            ImGui.SetNextWindowPos(new Vector2(50,50), ImGuiCond.Appearing);

            //ImGui.SetNextWindowSize(new Vector2(_ImGuiController._windowWidth, _ImGuiController._windowHeight), ImGuiCond.Appearing);
            ImGui.SetNextWindowSize(new Vector2(1200,800), ImGuiCond.Appearing);

            ImGui.Begin("rgat Primary Window", window_flags);

            WindowOffset = ImGui.GetWindowPos() - WindowStartPos;

            DrawMainMenu();
            DrawTargetBar();
            DrawTabs();
            if (_settings_window_shown) DrawSettingsWindow();
            if (_show_select_exe_window) DrawFileSelectBox();
            if (_show_load_trace_window) DrawTraceLoadBox();
            ImGui.End();
            
        }

        private void DrawTraceTab_FileInfo(BinaryTarget activeTarget, float width)
        {
            ImGui.BeginChildFrame(22, new Vector2(width, 300), ImGuiWindowFlags.AlwaysAutoResize);
            ImGui.BeginGroup();
            {
                ImGui.Columns(2);
                ImGui.SetColumnWidth(0, 120);
                ImGui.SetColumnWidth(1, width - 120);
                ImGui.Separator();

                byte[] _dataInput = null;

                ImGui.AlignTextToFramePadding();
                ImGui.Text("File"); ImGui.NextColumn();
                string fileStr = String.Format("{0} ({1})", activeTarget.FileName, activeTarget.GetFileSizeString());
                _dataInput = Encoding.UTF8.GetBytes(fileStr);
                ImGui.InputText("##filenameinp", _dataInput, 400, ImGuiInputTextFlags.ReadOnly); ImGui.NextColumn();

                ImGui.AlignTextToFramePadding();
                ImGui.Text("SHA1 Hash"); ImGui.NextColumn();
                _dataInput = Encoding.UTF8.GetBytes(activeTarget.GetSHA1Hash());
                ImGui.InputText("##s1hash", _dataInput, 400, ImGuiInputTextFlags.ReadOnly); ImGui.NextColumn();

                ImGui.AlignTextToFramePadding();
                ImGui.Text("SHA256 Hash"); ImGui.NextColumn();
                _dataInput = Encoding.UTF8.GetBytes(activeTarget.GetSHA256Hash());
                ImGui.InputText("##s256hash", _dataInput, 400, ImGuiInputTextFlags.ReadOnly); ImGui.NextColumn();

                ImGui.Text("Hex Preview"); ImGui.NextColumn();
                
                _ImGuiController.PushOriginalFont(); //it's monospace and UTF8
                {
                    _dataInput = Encoding.UTF8.GetBytes(activeTarget.HexPreview);
                    ImGui.InputText("##hexprev", _dataInput, 400, ImGuiInputTextFlags.ReadOnly); ImGui.NextColumn();
                    ImGui.PopFont();
                }

                ImGui.Text("ASCII Preview"); ImGui.NextColumn();
                _ImGuiController.PushOriginalFont();
                {
                    _dataInput = Encoding.ASCII.GetBytes(activeTarget.ASCIIPreview);
                    ImGui.InputText("##ascprev", _dataInput, 400, ImGuiInputTextFlags.ReadOnly); ImGui.NextColumn();
                    ImGui.PopFont();
                }
                
                ImGui.Text("Format"); ImGui.NextColumn();
                string formatNotes = activeTarget.FormatNotes;
                ImGui.InputTextMultiline("##fmtnote", ref formatNotes, 400, new Vector2(0, 80), ImGuiInputTextFlags.ReadOnly); ImGui.NextColumn();
            }

            ImGui.Columns(1);
            ImGui.EndGroup();
            ImGui.EndChildFrame();
        }

        private void DrawTraceTab_DiagnosticSettings(float width)
        {
            ImGui.BeginGroup();
            {
                ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFF998800);
                ImGui.BeginChildFrame(9, new Vector2(width, 300));
                {
                    ImGui.Button("DynamoRIO Test");
                    ImGui.Button("PIN Test");

                    if (ImGui.BeginCombo("##loglevel", "Essential"))
                    {

                        if (ImGui.Selectable("Essential", true))
                        {
                            Console.Write("Esel");
                        }
                        if (ImGui.Selectable("Verbose", false))
                        {
                            Console.Write("vbsel");
                        }
                        ImGui.EndCombo();
                    }


                }
                ImGui.EndChildFrame();

                ImGui.PopStyleColor();
            }
            ImGui.EndGroup();
        }

        private void DrawTraceTab_InstrumentationSettings(BinaryTarget activeTarget, float width)
        {
            ImGui.BeginGroup();
            ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFF992200);
            ImGui.BeginChildFrame(18, new Vector2(width, 200));
            ImGui.Text("Instrumentation Settings");


            ImGui.AlignTextToFramePadding();
            ImGui.Text("Instrumentation Engine");
            ImGui.SameLine();
            ImGui.RadioButton("Intel Pin", ref _selectedInstrumentationEngine, 0);
            ImGui.SameLine();
            ImGui.RadioButton("DynamoRIO", ref _selectedInstrumentationEngine, 1);
            ImGui.EndChildFrame();

            ImGui.BeginChildFrame(18, new Vector2(width, 200));
            ImGui.AlignTextToFramePadding();
            ImGui.Text("Module Tracing");
            ImGui.SameLine();
            ImguiUtils.HelpMarker("Customise which libraries rgat will instrument. Tracing more code affects performance and makes resulting graphs more complex.");
            ImGui.SameLine();
            string TraceLabel = $"Tracelist [{activeTarget.traceChoices.traceDirCount + activeTarget.traceChoices.traceFilesCount}]";
            if(ImGui.RadioButton(TraceLabel, ref activeTarget.traceChoices._tracingModeRef, 0)){
                activeTarget.traceChoices.TracingMode = (eModuleTracingMode) activeTarget.traceChoices._tracingModeRef;
            };
            ImGui.SameLine();
            ImguiUtils.HelpMarker("Only specified libraries will be traced");
            ImGui.SameLine();
            string IgnoreLabel = $"IgnoreList [{activeTarget.traceChoices.ignoreDirsCount + activeTarget.traceChoices.ignoreFilesCount}]";
            if(ImGui.RadioButton(IgnoreLabel, ref activeTarget.traceChoices._tracingModeRef, 1)){
                activeTarget.traceChoices.TracingMode = (eModuleTracingMode)activeTarget.traceChoices._tracingModeRef;
            };
            ImGui.SameLine();
            ImguiUtils.HelpMarker("All libraries will be traced except for those specified");
            ImGui.EndChildFrame();


            ImGui.BeginChildFrame(18, new Vector2(width, 200));
            ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFFdddddd);

            if (ImGui.BeginChildFrame(ImGui.GetID("exclusionlist_contents"), ImGui.GetContentRegionAvail()))
            {
                ImGui.PushStyleColor(ImGuiCol.Text, 0xFF000000);
                if ((eModuleTracingMode)activeTarget.traceChoices.TracingMode == eModuleTracingMode.eDefaultTrace)
                {
                    if (ImGui.TreeNode($"Ignored Directories ({activeTarget.traceChoices.ignoreDirsCount})"))
                    {
                        List<string> names = activeTarget.traceChoices.GetIgnoredDirs();
                        foreach (string fstr in names) ImGui.Text(fstr);
                        ImGui.TreePop();
                    }
                    if (ImGui.TreeNode($"Ignored Files ({activeTarget.traceChoices.ignoreFilesCount})"))
                    {
                        List<string> names = activeTarget.traceChoices.GetIgnoredFiles();
                        foreach (string fstr in names)  ImGui.Text(fstr);
                        ImGui.TreePop();
                    }
                }

                else if ((eModuleTracingMode)activeTarget.traceChoices.TracingMode == eModuleTracingMode.eDefaultIgnore)
                {
                    if (ImGui.TreeNode($"Included Directories ({activeTarget.traceChoices.traceDirCount})"))
                    {
                        List<string> names = activeTarget.traceChoices.GetTracedDirs();
                        foreach (string fstr in names) ImGui.Text(fstr);
                        ImGui.TreePop();
                    }
                    if (ImGui.TreeNode($"Included Files ({activeTarget.traceChoices.traceFilesCount})"))
                    {
                        List<string> names = activeTarget.traceChoices.GetTracedFiles();
                        foreach (string fstr in names) ImGui.Text(fstr);
                        ImGui.TreePop();
                    }
                }
                ImGui.PopStyleColor();
                ImGui.EndChildFrame();
                ImGui.PopStyleColor();
            }
            if (ImGui.BeginPopupContextItem("exclusionlist_contents", ImGuiMouseButton.Right))
            {
                ImGui.Selectable("Add files/directories");
                ImGui.EndPopup();
            }

            ImGui.EndChildFrame();

            ImGui.PopStyleColor();
            ImGui.EndGroup();

        }

        private void DrawTraceTab_ExecutionSettings(float width)
        {
            ImGui.BeginGroup();
            {
                ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFF222200);
                ImGui.BeginChildFrame(10, new Vector2(width, 200));
                ImGui.Text("Execution Settings");


                ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFF998880);
                ImGui.AlignTextToFramePadding();

                ImGui.Text("Command Line");
                ImGui.SameLine();
                ImguiUtils.HelpMarker("Command line arguments passed to the program being executed");
                ImGui.SameLine();

                byte[] _dataInput = new byte[1024];
                ImGui.InputText("##cmdline", _dataInput, 1024);
                ImGui.PopStyleColor();
                ImGui.Button("Start Trace");
                ImGui.EndChildFrame();
                ImGui.PopStyleColor();
            }
            ImGui.EndGroup();
        }





       



        public void AddGraphicsCommands(CommandList _cl, GraphicsDevice _gd)
        {
            if (_rgatstate.ActiveGraph == null) return;
            MainGraphWidget.AddGraphicsCommands(_cl, _gd);
            PreviewGraphWidget.AddGraphicsCommands(_cl, _gd);
        }

      

























        private void DrawTraceTab()
        {

            BinaryTarget activeTarget = _rgatstate.ActiveTarget;
            if (activeTarget == null)
            {
                String msg = "No target binary is selected\nOpen a binary or saved trace from the target menu фä洁ф";
                ImguiUtils.DrawCenteredText(msg);
                return;
            }

            ImGui.BeginGroup();
            DrawTraceTab_FileInfo(activeTarget, ImGui.GetContentRegionAvail().X - 200);
            ImGui.SameLine();
            DrawTraceTab_DiagnosticSettings(200);
            ImGui.EndGroup();

            ImGui.BeginGroup();
            DrawTraceTab_InstrumentationSettings(activeTarget, 400);
            ImGui.SameLine();
            DrawTraceTab_ExecutionSettings(ImGui.GetContentRegionAvail().X - 400);
            ImGui.EndGroup();

            return;
        }

        private void DrawVisualiserGraphs(float height)
        {
            float tracesGLFrameWidth = 300;
            {
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF000000);
                Vector2 graphSize = new Vector2(ImGui.GetContentRegionAvail().X - tracesGLFrameWidth, height);
                if (ImGui.BeginChild(ImGui.GetID("GLVisMain"), graphSize))
                {
                    MainGraphWidget.Draw(graphSize, _ImGuiController, _rgatstate._GraphicsDevice);
                    if (_rgatstate.ActiveGraph != null) 
                        ImGui.Text($"Displaying thread {_rgatstate.ActiveGraph.tid}");
                    else
                        ImGui.Text($"No active graph to display");
                    ImGui.EndChild();

                }
                ImGui.PopStyleColor();
                ImGui.SameLine();
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0x10253880);
                Vector2 previewPaneSize = new Vector2(tracesGLFrameWidth, height);
                if (ImGui.BeginChild(ImGui.GetID("GLVisThreads"), previewPaneSize, true))
                {
                    ImGui.Text("GLVisThreads");
                    PreviewGraphWidget.Draw(previewPaneSize, _ImGuiController, _rgatstate._GraphicsDevice);

                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();
            }

        }

        float sliderPosX = -1;

        private unsafe void DrawReplaySlider(float replayControlsSize)
        {
            int progressBarPadding = 6;
            Vector2 progressBarSize = new Vector2(replayControlsSize - (progressBarPadding * 2), 30);

            ImGui.InvisibleButton("Replay Progress", progressBarSize);
            Vector2 AnimationProgressBarPos = ImGui.GetItemRectMin();
            AnimationProgressBarPos.X += progressBarPadding;
           
            if (ImGui.IsItemActive())
            {
                sliderPosX = ImGui.GetIO().MousePos.X - ImGui.GetWindowPos().X;
            }


            Vector2 SliderRectStart = new Vector2(AnimationProgressBarPos.X, AnimationProgressBarPos.Y);
            Vector2 SliderRectEnd = new Vector2(AnimationProgressBarPos.X + progressBarSize.X, AnimationProgressBarPos.Y + progressBarSize.Y);

            Vector2 SliderArrowDrawPos = new Vector2(AnimationProgressBarPos.X + sliderPosX, AnimationProgressBarPos.Y);
            if (SliderArrowDrawPos.X < SliderRectStart.X) SliderArrowDrawPos.X = AnimationProgressBarPos.X;
            if (SliderArrowDrawPos.X > SliderRectEnd.X) SliderArrowDrawPos.X = SliderRectEnd.X;

            float sliderBarPosition = (SliderArrowDrawPos.X - SliderRectStart.X) / progressBarSize.X;
            if (ImGui.IsItemActive())
                Console.WriteLine($"User changed animation position to: {sliderBarPosition * 100}%");

            ImGui.GetWindowDrawList().AddRectFilledMultiColor(SliderRectStart, SliderRectEnd, 0xff004400, 0xfff04420, 0xff994400, 0xff004477);
            if (sliderBarPosition <= 0.05) SliderArrowDrawPos.X += 1;
            if (sliderBarPosition >= 99.95) SliderArrowDrawPos.X -= 1;
            ImguiUtils.RenderArrowsForHorizontalBar(ImGui.GetForegroundDrawList(),
                SliderArrowDrawPos, 
                new Vector2(3, 7), progressBarSize.Y, 240f);

        }
        private void DrawScalePopup() 
        {
            if (ImGui.BeginChild(ImGui.GetID("SizeControlsb"), new Vector2(200, 200)))
            {

                if (ImGui.DragFloat("Horizontal Stretch", ref _rgatstate.ActiveGraph.main_scalefactors.pix_per_A, 0.005f, 0.05f, 4f, "%f%%")){
                    _rgatstate.ActiveGraph.NeedReplotting = true;
                    Console.WriteLine($"Needreplot { _rgatstate.ActiveGraph.main_scalefactors.pix_per_A}");
                };
                if (ImGui.DragFloat("Vertical Stretch", ref _rgatstate.ActiveGraph.main_scalefactors.pix_per_B, 1.0f, 0.1f, 200f, "%f%%")){
                    _rgatstate.ActiveGraph.NeedReplotting = true;
                };
                if (ImGui.DragFloat("Plot Size", ref _rgatstate.ActiveGraph.main_scalefactors.plotSize, 1.0f, 0.1f, 500f, "%f%%")){
                    _rgatstate.ActiveGraph.NeedReplotting = true;
                };

                ImGui.EndChild();
            }
        }

        private void DrawCameraPopup()
        {
            if (ImGui.BeginChild(ImGui.GetID("CameraControlsb"), new Vector2(200, 200)))
            {
                
                ImGui.DragFloat("FOV", ref MainGraphWidget.dbg_FOV, 0.005f, 0.05f, (float)Math.PI, "%f%%");
                ImGui.DragFloat("Near Clipping", ref MainGraphWidget.dbg_near, 1.0f, 0.1f, 200f, "%f%%");
                ImGui.DragFloat("Far Clipping", ref MainGraphWidget.dbg_far, 1.0f, 0.1f, 20000f, "%f%%");
                ImGui.DragFloat("X Shift", ref MainGraphWidget.dbg_camX, 1f, -400, 400, "%f%%");
                ImGui.DragFloat("Y Position", ref MainGraphWidget.dbg_camY, 1, -400, 1000, "%f%%");
                ImGui.DragFloat("Zoom", ref MainGraphWidget.dbg_camZ, 5, -20000, 0, "%f%%");
                ImGui.DragFloat("Rotation", ref MainGraphWidget.dbg_rot, 0.05f, -5, 5, "%f%%");
                


                ImGui.EndChild();
            }
        }



        private void drawVisToolBar(float height)
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF0000ff);
            ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 3);
            if (ImGui.BeginChild(ImGui.GetID("ControlTopBar"), new Vector2(ImGui.GetContentRegionAvail().X, height)))
            {
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 3);
                ImGui.PushItemWidth(100);
                if (ImGui.BeginCombo("##GraphTypeSelectCombo", "Cylinder"))
                {
                    if (ImGui.Selectable("Cylinder", true))
                    {
                        Console.WriteLine("Cylinder selected");
                    }
                    if (ImGui.Selectable("Tree", false))
                    {
                        Console.WriteLine("Tree selected");
                    }
                    if (ImGui.Selectable("Bars", false))
                    { //sections, events, heat, conditionals?
                        Console.WriteLine("Bars selected");
                    }
                    ImGui.EndCombo();
                }
                ImGui.PopItemWidth();
                ImGui.SameLine();
                ImGui.Button("Lines");
                ImGui.SameLine();
                ImGui.Button("Nodes");
                ImGui.SameLine();
                ImGui.Button("Wireframe");
                ImGui.SameLine();
                ImGui.Button("Symbols");
                ImGui.SameLine();
                ImGui.Button("Instructions");
                ImGui.SameLine();
                ImGui.PushItemWidth(100);
                if (ImGui.BeginCombo("##TraceTypeSelectCombo", "Trace"))
                {
                    if (ImGui.Selectable("Trace", true))
                    {
                        Console.WriteLine("Trace selected");
                    }
                    if (ImGui.Selectable("Heatmap", false))
                    {
                        Console.WriteLine("Heatmap selected");
                    }
                    if (ImGui.Selectable("Conditionals", false))
                    {
                        Console.WriteLine("Conditionals selected");
                    }
                    ImGui.EndCombo();
                }
                ImGui.PopItemWidth();
                ImGui.SameLine();
                ImGui.Button("Highlight");
                ImGui.SameLine();

                if (ImGui.Button("Scale"))
                {
                    ImGui.OpenPopup("##ScaleGraph");
                }

                if (this._rgatstate.ActiveGraph != null && ImGui.BeginPopup("##ScaleGraph", ImGuiWindowFlags.AlwaysAutoResize))
                {
                    DrawScalePopup();
                    ImGui.EndPopup();
                }

                ImGui.SameLine();
                if (ImGui.Button("Camera"))
                {
                    ImGui.OpenPopup("##CameraBtn");
                }

                if (ImGui.BeginPopup("##CameraBtn", ImGuiWindowFlags.AlwaysAutoResize))
                {
                    DrawCameraPopup();
                    ImGui.EndPopup();
                }

                ImGui.SameLine();
                ImGui.Button("Rerender");

                ImGui.EndChild();
            }
            ImGui.PopStyleColor();
        }

        private unsafe void DrawPlaybackControls(float otherControlsHeight)
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF555555);

            float replayControlsSize = ImGui.GetContentRegionAvail().X - 300f;
            if (ImGui.BeginChild(ImGui.GetID("ReplayControls"), new Vector2(replayControlsSize, otherControlsHeight)))
            {

                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 6);
                ImGui.Text("Trace Replay: Paused");

                DrawReplaySlider(replayControlsSize);

                ImGui.SetCursorPos(new Vector2(ImGui.GetCursorPosX() + 6, ImGui.GetCursorPosY() + 6));

                if (ImGui.BeginChild("ctrls2354"))
                {
                    ImGui.BeginGroup();
                    if (ImGui.Button("Play", new Vector2(36, 36))) Console.WriteLine("Play clicked");
                    if (ImGui.Button("Reset", new Vector2(36, 36))) Console.WriteLine("Reset clicked");
                    ImGui.EndGroup();

                    ImGui.SameLine(); //pointless?
                    ImGui.SetNextItemWidth(60f);
                    if (ImGui.BeginCombo("Replay Speed", " x1", ImGuiComboFlags.HeightLargest))
                    {
                        if (ImGui.Selectable("x1/4")) Console.WriteLine("Speed changed");
                        if (ImGui.Selectable("x1/2")) Console.WriteLine("Speed changed");
                        if (ImGui.Selectable("x1")) Console.WriteLine("Speed changed");
                        if (ImGui.Selectable("x2")) Console.WriteLine("Speed changed");
                        if (ImGui.Selectable("x4")) Console.WriteLine("Speed changed");
                        if (ImGui.Selectable("x8")) Console.WriteLine("Speed changed");
                        if (ImGui.Selectable("x16")) Console.WriteLine("Speed changed");
                        ImGui.EndCombo();
                    }

                    ImGui.EndChild();
                }



                ImGui.EndChild();
            }

            ImGui.PopStyleColor();
        }
        private unsafe void DrawLiveTraceControls(float otherControlsHeight)
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF555555);

            float replayControlsSize = ImGui.GetContentRegionAvail().X - 300f;
            if (ImGui.BeginChild(ImGui.GetID("LiveControls"), new Vector2(replayControlsSize, otherControlsHeight)))
            {

                ImGui.SetCursorPos(new Vector2(ImGui.GetCursorPosX() + 6, ImGui.GetCursorPosY() + 6));

                if (ImGui.BeginChild("RenderingBox"))
                {
                    ImGui.Columns(2);
                    ImGui.SetColumnWidth(0, 200);
                    ImGui.SetColumnWidth(1, 200);

                    ImGui.BeginGroup();
                    if (ImGui.RadioButton("Static", false)) Console.WriteLine("Static clicked");
                    if (ImGui.RadioButton("Animated", true)) Console.WriteLine("Animated clicked");
                    ImGui.EndGroup();

                    ImGui.BeginGroup();
                    if (ImGui.Button("Kill")) Console.WriteLine("Kill clicked");
                    ImGui.SameLine();
                    if (ImGui.Button("Kill All")) Console.WriteLine("Kill All clicked");
                    ImGui.EndGroup();

                    ImGui.NextColumn(); 

                    ImGui.BeginGroup();
                    if (ImGui.Button("Pause/Break")) Console.WriteLine("Kill clicked");
                    ImGui.EndGroup();

                    ImGui.Columns(1);

                    ImGui.EndChild();
                }



                ImGui.EndChild();
            }

            ImGui.PopStyleColor();
        }

        private void DrawTraceSelector(float frameHeight)
        {

            float vpadding = 4;
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF552120);

            if (ImGui.BeginChild(ImGui.GetID("TraceSelect"), new Vector2(300, frameHeight)))
            {

                float combosHeight = 60 - vpadding;
                if (ImGui.BeginChild(ImGui.GetID("TraceSelect"), new Vector2(280, combosHeight)))
                {
                    if (_rgatstate.ActiveTarget != null)
                    {
                        var tracelist = _rgatstate.ActiveTarget.GetTracesUIList();
                        string selString = (_rgatstate.ActiveGraph != null) ? "PID " + _rgatstate.ActiveGraph.pid : "";
                        if (ImGui.BeginCombo("Process (0/1)", selString))
                        {
                            foreach (var timepid in tracelist)
                            {
                                ImGui.Selectable("PID " + timepid.Item2, _rgatstate.ActiveGraph.pid == timepid.Item2);
                                //ImGui.Selectable("PID 12345 (xyz.exe)");
                            }
                            ImGui.EndCombo();
                        }

                        if (_rgatstate.ActiveTrace != null)
                        {
                            selString = (_rgatstate.ActiveGraph != null) ? "TID " + _rgatstate.ActiveGraph.tid : "";
                            uint activeTID = (_rgatstate.ActiveGraph != null) ? +_rgatstate.ActiveGraph.tid : 0;
                            List <PlottedGraph> graphs = _rgatstate.ActiveTrace.GetPlottedGraphsList();
                            if (ImGui.BeginCombo($"Thread ({graphs.Count})", selString))
                            {
                                foreach (PlottedGraph graph in graphs)
                                {
                                    ImGui.Selectable("TID " + graph.tid, activeTID == graph.tid);
                                }
                                ImGui.EndCombo();
                            }
                        }
                    }
                    ImGui.EndChild();
                }

                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 6);
                ImGui.Text("Active Thread ID: 12345");
                float metricsHeight = 80;
                ImGui.Columns(3, "smushes");
                ImGui.SetColumnWidth(0, 20);
                ImGui.SetColumnWidth(1, 130);
                ImGui.SetColumnWidth(2, 90);
                ImGui.NextColumn();

                
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff110022);
                
                if (ImGui.BeginChild("ActiveTraceMetrics", new Vector2(130, metricsHeight)))
                {
                    ImGui.Text("Edges: 123");ImGui.Text("Nodes: 456");ImGui.Text("Updates: 498496");ImGui.Text("Backlog: 441");
                    ImGui.EndChild();
                }

                ImGui.NextColumn();
                
                if (ImGui.BeginChild("OtherMetrics", new Vector2(90, metricsHeight)))
                {
                    ImGui.Text("X: 123");ImGui.Text("Y: 456");ImGui.Text("Z: 496");ImGui.Text("Q: 41");
                    ImGui.EndChild();
                }  
                ImGui.PopStyleColor();
              
                ImGui.Columns(1, "smushes");
                ImGui.EndChild();
            }
            ImGui.PopStyleColor();
        }

        private unsafe void DrawVisualiserControls(float controlsHeight)
        {
            float topControlsBarHeight = 30;
            float otherControlsHeight = controlsHeight - topControlsBarHeight;
            float vpadding = 10;


            drawVisToolBar(topControlsBarHeight);


            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF553180);
            float frameHeight = otherControlsHeight - vpadding;
            if (ImGui.BeginChild(ImGui.GetID("ControlsOhter"), new Vector2(ImGui.GetContentRegionAvail().X, frameHeight)))
            {
                //DrawLiveTraceControls(frameHeight);
                DrawPlaybackControls(frameHeight);
                ImGui.SameLine();
                DrawTraceSelector(frameHeight);
                ImGui.EndChild();
            }
            ImGui.PopStyleColor();

        }

      




        private void DrawVisTab()
        {
            if (_rgatstate.ActiveGraph == null)
            {
                if (_rgatstate.ChooseActiveGraph())
                { 
                    MainGraphWidget.SetActiveGraph(_rgatstate.ActiveGraph, _rgatstate._GraphicsDevice);
                    PreviewGraphWidget.SetActiveTrace(_rgatstate.ActiveTrace);
                }
                
            }
            
            

            float controlsHeight = 230;

            DrawVisualiserGraphs(ImGui.GetContentRegionAvail().Y - controlsHeight);

            DrawVisualiserControls(controlsHeight);

        }
        private void DrawAnalysisTab()
        {
            ImGui.Text("Trace start stuff here");
        }
        private void DrawCompareTab()
        {
            ImGui.Text("Trace start stuff here");
        }
        private unsafe void DrawSettingsTab()
        {
            ImGui.Text("Trace start stuff here");
        }

        private unsafe void DrawMainMenu()
        {
            if (ImGui.BeginMenuBar())
            {
                if (ImGui.BeginMenu("Target"))
                {
                    if (ImGui.MenuItem("Select Target Executable")) { _show_select_exe_window = !_show_select_exe_window; }
                    if (ImGui.MenuItem("Recent Targets")) { }
                    if (ImGui.MenuItem("Open Saved Trace")) { _show_load_trace_window = !_show_load_trace_window; }
                    ImGui.Separator();
                    if (ImGui.MenuItem("Save Thread Trace")) { }
                    if (ImGui.MenuItem("Save Process Traces")) { }
                    if (ImGui.MenuItem("Save All Traces")) { }
                    ImGui.Separator();
                    if (ImGui.MenuItem("Exit")) { }
                    ImGui.EndMenu();
                }


                if (ImGui.MenuItem("Settings", null, ref _settings_window_shown)) { }

                ImGui.EndMenuBar();
            }
        }

        private unsafe void DrawTargetBar()
        {
            if (_rgatstate.targets.count() == 0)
            {
                ImGui.Text("No target selected or trace loaded");
                return;
            }

            BinaryTarget activeTarget = _rgatstate.ActiveTarget;
            string activeString = (activeTarget == null) ? "No target selected" : activeTarget.FilePath;
            List<string> paths = _rgatstate.targets.GetTargetPaths();
            ImGuiComboFlags flags = 0;
            if (ImGui.BeginCombo("Selected Binary", activeString, flags))
            {
                foreach (string path in paths)
                {
                    bool is_selected = activeTarget != null && activeTarget.FilePath == path;
                    if (ImGui.Selectable(path, is_selected))
                    {
                        _rgatstate.SetActiveTarget(path);
                    }

                    // Set the initial focus when opening the combo (scrolling + keyboard navigation focus)
                    if (is_selected)
                        ImGui.SetItemDefaultFocus();
                }
                ImGui.EndCombo();
            }
        }

        private unsafe void DrawTabs()
        {
            bool dummy = true;
            ImGuiTabBarFlags tab_bar_flags = ImGuiTabBarFlags.AutoSelectNewTabs;
            if (ImGui.BeginTabBar("Primary Tab Bar", tab_bar_flags))
            {
                if (ImGui.BeginTabItem("Start Trace"))
                {
                    DrawTraceTab();
                    ImGui.EndTabItem();
                }

                if (ImGui.BeginTabItem("Visualiser"))
                {
                    DrawVisTab();
                    ImGui.EndTabItem();
                }
                if (ImGui.BeginTabItem("Trace Analysis"))
                {
                    DrawAnalysisTab();
                    ImGui.EndTabItem();
                }
                if (ImGui.BeginTabItem("Graph Comparison"))
                {
                    DrawCompareTab();
                    ImGui.EndTabItem();
                }

                ImGui.EndTabBar();
            }


        }

        private unsafe void DrawSettingsWindow()
        {
            ImGui.SetNextWindowPos(new Vector2(200, 200), ImGuiCond.Appearing);

            ImGuiWindowFlags window_flags = ImGuiWindowFlags.None;

            ImGui.Begin("Settings", ref _settings_window_shown, window_flags);
            ImGui.InputText("f", Encoding.ASCII.GetBytes("CHUNK THE FUNK"), 120);
            ImGui.Text("Here be settings");
            ImGui.End();
        }

        private unsafe void DrawFileSelectBox()
        {
            ImGui.OpenPopup("Select Executable");

            if (ImGui.BeginPopupModal("Select Executable", ref _show_select_exe_window, ImGuiWindowFlags.None))
            {
                var picker = rgatFilePicker.FilePicker.GetFilePicker(this, Path.Combine(Environment.CurrentDirectory));
                rgatFilePicker.FilePicker.PickerResult result = picker.Draw(this);
                if (result != rgatFilePicker.FilePicker.PickerResult.eNoAction)
                {
                    if (result == rgatFilePicker.FilePicker.PickerResult.eTrue)
                    {
                        _rgatstate.AddTargetByPath(picker.SelectedFile);
                    }
                    rgatFilePicker.FilePicker.RemoveFilePicker(this);
                    _show_select_exe_window = false;
                }
                ImGui.EndPopup();
            }
        }

        private void LoadTraceByPath(string filepath)
        {
            if (!_rgatstate.LoadTraceByPath(filepath, out TraceRecord trace)) return;
            
            launch_all_trace_threads(trace, _rgatstate);

            _rgatstate.ActiveTarget = trace.binaryTarg;
            _rgatstate.SwitchTrace = trace;

            //ui.dynamicAnalysisContentsTab.setCurrentIndex(eVisualiseTab);
            
        }
        void launch_all_trace_threads(TraceRecord trace, rgatState clientState)
        {
            ProcessLaunching.launch_saved_process_threads(trace, clientState);

            foreach (TraceRecord childTrace in trace.children)
	        {
                launch_all_trace_threads(childTrace, clientState);
            }
        }

        private void DrawTraceLoadBox()
        {
            ImGui.OpenPopup("Select Trace File");

            if (ImGui.BeginPopupModal("Select Trace File", ref _show_load_trace_window, ImGuiWindowFlags.None))
            {
                var picker = rgatFilePicker.FilePicker.GetFilePicker(this, Path.Combine(Environment.CurrentDirectory));
                rgatFilePicker.FilePicker.PickerResult result = picker.Draw(this);
                if (result != rgatFilePicker.FilePicker.PickerResult.eNoAction)
                {
                    if (result == rgatFilePicker.FilePicker.PickerResult.eTrue)
                    {
                        LoadTraceByPath(picker.SelectedFile);

                    }
                    rgatFilePicker.FilePicker.RemoveFilePicker(this);
                    _show_load_trace_window = false;
                }
                ImGui.EndPopup();
            }
        }
    }
}
