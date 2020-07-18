using ImGuiNET;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace rgatCore
{
    class rgatState
    {
        public BinaryTargets targets = new BinaryTargets();
		public BinaryTarget ActiveTarget = null;// { get; private set; } = null;
		public TraceRecord ActiveTrace = null;
		public PlottedGraph ActiveGraph { get; private set; } = null;
		public Veldrid.GraphicsDevice _GraphicsDevice;
		public Veldrid.CommandList _CommandList;
		
		public rgatState(Veldrid.GraphicsDevice _gd, Veldrid.CommandList _cl) {
			_GraphicsDevice = _gd;
			_CommandList = _cl;
			PlottedGraph.clientState = this;
		}

		public PlottedGraph SwitchGraph = null;
		public TraceRecord SwitchTrace = null;
		public bool rgatIsExiting { private set; get; } = false;
		public bool WaitingForNewTrace = false;
		public int AnimationStepRate = 1;
		public graphLayouts newGraphLayout = graphLayouts.eCylinderLayout;

		public bool showNodes = true;
		public bool showEdges = true;


		Dictionary<TraceRecord, PlottedGraph> LastGraphs = new Dictionary<TraceRecord, PlottedGraph>();
		Dictionary<TraceRecord, uint> LastSelectedTheads = new Dictionary<TraceRecord, uint>();

		public void ShutdownRGAT()
        {
			rgatIsExiting = true;
        }

		public BinaryTarget AddTargetByPath(string path, int arch = 0, bool selectIt = true)
        {
			BinaryTarget targ = targets.AddTargetByPath(path, arch);
            if (selectIt) SetActiveTarget(targ);
			return targ;
        }

        public void SetActiveTarget(string path)
        {
            targets.GetTargetByPath(path, out BinaryTarget newTarget);
            if (newTarget != null && newTarget != ActiveTarget)
            {
                ActiveTarget = newTarget;
            };
        }
		public void SetActiveTarget(BinaryTarget newTarget)
		{
			if (newTarget != null && newTarget != ActiveTarget)
			{
				ActiveTarget = newTarget;
			};
		}

		public void ClearActiveGraph()
		{
			//activeGraphLock.lock () ;
			if (ActiveGraph == null)
			{
				//activeGraphLock.unlock();
				return;
			}

			//ActiveGraph.decrease_thread_references(50);
			ActiveGraph = null;
			//activeGraphLock.unlock();
		}


		public void SelectActiveTrace(TraceRecord trace = null)
        {
			ActiveGraph = null;

			if (trace == null && ActiveTarget != null)
			{
				//waiting for a shiny new trace that the user just launched
				if (WaitingForNewTrace)
					return;
				trace = ActiveTarget.GetFirstTrace();
			}

			ActiveTrace = trace;
		}

		bool initialiseTarget(Newtonsoft.Json.Linq.JObject saveJSON, BinaryTargets targets, out BinaryTarget targetResult)
		{
			BinaryTarget target = null;
			targetResult = null;

			string binaryPath = (string)saveJSON.GetValue("BinaryPath");
			if (binaryPath == null) return false;
	
			if(!targets.GetTargetByPath(binaryPath, out target))
            {
				target = targets.AddTargetByPath(binaryPath);
            }
			//myui.targetListCombo.addTargetToInterface(target, newBinary);

			targetResult = target; 
			return true;

		}

		void SwitchToGraph(PlottedGraph graph)
		{
			//valid target or not, we assume current graph is no longer fashionable
			ClearActiveGraph();

			if (graph == null || graph.NeedReplotting || graph.beingDeleted) return;

			TraceRecord trace = ActiveTrace;
			if (trace == null) return;

			if (SetActiveGraph(graph))
			{
				LastGraphs[trace] = graph;
				LastSelectedTheads[trace] = graph.tid;
			}
			//setGraphUIControls(graph);
		}
			
		public bool ChooseActiveGraph()
		{
			if (SwitchTrace != null)
			{
				SelectActiveTrace(SwitchTrace);
				SwitchTrace = null;
				//ui->dynamicAnalysisContentsTab->updateVisualiserUI(true);
			}

			PlottedGraph switchGraph = SwitchGraph;
			if (SwitchGraph != null && switchGraph.beingDeleted && !switchGraph.NeedReplotting)
			{
				SwitchToGraph(switchGraph);
				SwitchGraph = null;
			}

			if (ActiveGraph != null)
			{
				if (ActiveGraph.beingDeleted)
				{
					//ActiveGraph.decrease_thread_references(141);
					ActiveGraph = null;
					return false;
				}

				return true;
			}

			if (ActiveGraph == null && !WaitingForNewTrace)
			{
				if (ActiveTrace != null)
					SelectActiveTrace();


				selectGraphInActiveTrace();
			}


			return (ActiveGraph != null);

		}
	
		//activate a graph in the active trace
		//selects the last one that was active in this trace, or the first seen
		void selectGraphInActiveTrace()
		{
			TraceRecord selectedTrace = ActiveTrace;
			if (selectedTrace == null) return;

			if(LastGraphs.TryGetValue(selectedTrace, out PlottedGraph foundGraph))
			{
				bool found = false;
				List<PlottedGraph> traceGraphs = selectedTrace.GetPlottedGraphsList();
				if (traceGraphs.Contains(foundGraph))
                {
					SwitchToGraph(foundGraph);
					found = true;
				}
				else
				{
					uint lastTID = LastSelectedTheads[selectedTrace];
					PlottedGraph lastgraph = traceGraphs.Find(pg => pg.tid == lastTID);
					if (lastgraph != null)
                    {
						SwitchToGraph(lastgraph);
						found = true;
					}
				}

				//foreach (graph, traceGraphs){ graph->decrease_thread_references(144); }
				if (found) return;
			}

			PlottedGraph firstgraph = selectedTrace.GetFirstGraph();
			if (firstgraph != null)
			{
				Console.WriteLine("Got first graph "+firstgraph.tid);
				SwitchToGraph(firstgraph);
				//firstgraph->decrease_thread_references(33);
			}
		}
		
		

		public bool SetActiveGraph(PlottedGraph graph)
		{

			if (ActiveGraph != null && !ActiveGraph.beingDeleted)
				return false;

			ClearActiveGraph();

			Debug.Assert(ActiveGraph == null);

			//activeGraphLock.lock () ;
			//if (((plotted_graph*)graph)->increase_thread_references(50))
			//{
				ActiveGraph = graph;
			//}
			//activeGraphLock.unlock();
			return true;
		}
		public PlottedGraph getActiveGraph(bool increaseReferences)
		{
			if (ActiveGraph != null && ActiveGraph.beingDeleted) return null;

			//activeGraphLock.lock () ;

			if (ActiveGraph == null)
			{
				//activeGraphLock.unlock();
				return null;
			}

			/*
			 * todooooooooooooo
			 * 
			if (increaseReferences)
			{
				bool success = activeGraph.increase_thread_references(52);
				if (!success)
				{
					activeGraphLock.unlock();
					return NULL;
				}
				//cout << "[+1: "<< ((plotted_graph *)activeGraph).threadReferences << "]increased refs to graph " << activeGraph << endl;
			}
			*/
			PlottedGraph tmp = ActiveGraph;
			//activeGraphLock.unlock();

			return tmp;
		}

		public PlottedGraph CreateNewPlottedGraph(ProtoGraph protoGraph)
		{
			PlottedGraph newGraph = null;

			switch (newGraphLayout)
			{
				case graphLayouts.eCylinderLayout:
					{
						newGraph = new CylinderGraph(protoGraph, GlobalConfig.defaultGraphColours);
						break;
					}
					/*
				case eTreeLayout:
					{
						//newGraph = new tree_graph(protoGraph.get_TID(), protoGraph, &config.graphColours);
						newGraph = new blocktree_graph(protoGraph.get_TID(), protoGraph, &config.graphColours);
						break;
					}
					*/
				default:
					{
						Console.WriteLine("Bad graph layout: " + newGraphLayout);
						Debug.Assert(false);
						break;
					}
			}
			newGraph.InitialiseDefaultDimensions();
			return newGraph;
		}

		public static DateTime UnixTimeStampToDateTime(double unixTimeStamp)
		{
			// Unix timestamp is seconds past epoch
			System.DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
			dtDateTime = dtDateTime.AddSeconds(unixTimeStamp).ToLocalTime();
			return dtDateTime;
		}

		//return true if a new trace was created, false if failed or duplicate
		//todo should have 3 returns
		bool initialiseTrace(Newtonsoft.Json.Linq.JObject saveJSON, BinaryTarget target, out TraceRecord traceResult)
		{

			bool valid = true;
			valid = valid & saveJSON.TryGetValue("PID", out JToken jPID);
			valid = valid & saveJSON.TryGetValue("PID_ID", out JToken jID);
			valid = valid & saveJSON.TryGetValue("StartTime", out JToken jTime);
			
			if (valid == false || jPID.Type != JTokenType.Integer ||
				jID.Type != JTokenType.Integer)
			{
				Console.WriteLine("[rgat]Warning: Bad trace metadata. Load failed.");
				traceResult = null;
				return false;
			}


			//temporary loading of unix ts in old save files. TODO: move to new format
			DateTime StartTime;
			if (jTime.Type == JTokenType.Integer)
				StartTime = UnixTimeStampToDateTime((ulong)jTime);
			else if (jTime.Type == JTokenType.String)
			{
				StartTime = DateTime.MinValue;
				Console.WriteLine("TODO DESERIALISE DATETIME");
			}
			else
			{
				Console.WriteLine("BAD DATETIME");
				traceResult = null;
				return false;
			}

			
			bool newTrace = target.CreateNewTrace(StartTime, (uint)jPID, (uint)jID, out traceResult);
			if (!newTrace)
			{
				//updateActivityStatus("Trace already loaded", 15000);
				Console.WriteLine("[rgat] Trace already loaded");
				return false;
			}

			//updateActivityStatus("Loaded saved process: " + QString::number(tracePID), 15000);
			return true;
		}

		public bool LoadTraceByPath(string path, out TraceRecord trace)
        {
			//display_only_status_message("Loading save file...", clientState);
			//updateActivityStatus("Loading " + QString::fromStdString(traceFilePath.string()) + "...", 2000);

			Newtonsoft.Json.Linq.JObject saveJSON = null;
			using (StreamReader file = File.OpenText(path))
			{
				string jsnfile = file.ReadToEnd();
				try
				{
					saveJSON = Newtonsoft.Json.Linq.JObject.Parse(jsnfile);
				}
				catch (Newtonsoft.Json.JsonReaderException e)
				{
					Console.WriteLine("Failed to parse trace file - invalid JSON.");
					Console.WriteLine("\t->\t"+e.Message);
					trace = null;
					return false;
				}
				catch (Exception e)
				{
					Console.WriteLine("Failed to parse trace file: "+e.Message);
					trace = null;
					return false;
				}
			}

			BinaryTarget target;
			if (!initialiseTarget(saveJSON, targets, out target))
			{
				//updateActivityStatus("Process data load failed - possibly corrupt trace file", 15000);
				trace = null;
				return false;
			}
			
			if (!initialiseTrace(saveJSON, target, out trace))
			{
				if (trace != null) //already existed
				{
					SwitchTrace = trace;
				}
				return false;
			}
			
			if (!trace.load(saveJSON))//, config.graphColours))
				return false;

			//updateActivityStatus("Loaded " + QString::fromStdString(traceFilePath.filename().string()), 15000);
			ExtractChildTraceFilenames(saveJSON, out List<string> childrenFiles);
			if (childrenFiles.Count > 0)
				LoadChildTraces(childrenFiles, trace);
			
            return true;
        }

		void ExtractChildTraceFilenames(JObject saveJSON, out List<string> childrenFiles)
		{
			childrenFiles = new List<string>();
			if (saveJSON.TryGetValue("Children", out JToken jChildren) && jChildren.Type == JTokenType.Array)
            {
				JArray ChildrenArray = (JArray)jChildren;
				foreach (JToken fname in ChildrenArray)
				{
					childrenFiles.Add(fname.ToString());
				}
			}
		}

		void LoadChildTraces(List<string> childrenFiles, TraceRecord trace)
		{
			
			string saveDir = "C:\\";//config.saveDir; //should be same dir as loaded trace?
			foreach (string file in childrenFiles)
			{
				
				string childFilePath = Path.Combine(saveDir, file);

				if (Path.GetDirectoryName(childFilePath) != saveDir) //or a children subdir?
					return; //avoid directory traversal

				if (!File.Exists(childFilePath))
				{
					Console.WriteLine("[rgat] Warning: Unable to find child save file "+childFilePath);
					return;
				}

				LoadTraceByPath(childFilePath, out TraceRecord childTrace);
				trace.children.Add(childTrace);
				childTrace.ParentTrace = trace;
			}
			
		}
	}
}
