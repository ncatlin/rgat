using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace rgatCore
{
    class rgatState
    {
        public BinaryTargets targets = new BinaryTargets();
        public BinaryTarget ActiveTarget { get; private set; } = null;

        public rgatState() { }

		public TraceRecord switchTrace = null;

        public void AddTargetByPath(string path, bool selectIt = true)
        {
            targets.AddTargetByPath(path);
            if (selectIt) SetActiveTarget(path);
        }

        public void SetActiveTarget(string path)
        {
			BinaryTarget newTarget = null;
            if (targets.GetTargetByPath(path, out newTarget) && newTarget != ActiveTarget)
            {
                ActiveTarget = newTarget;
            };
        }

		bool initialiseTarget(Newtonsoft.Json.Linq.JObject saveJSON, BinaryTargets targets, out BinaryTarget targetResult)
		{
			BinaryTarget target = null;
			targetResult = null;

			string binaryPath = (string)saveJSON.GetValue("BinaryPath");
			if (binaryPath == null) return false;
	
			bool newBinary = targets.GetTargetByPath(binaryPath, out target);
			//myui->targetListCombo->addTargetToInterface(target, newBinary);

			targetResult = target; 
			return true;

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
				saveJSON = Newtonsoft.Json.Linq.JObject.Parse(jsnfile);
				//if error - ret false
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
					switchTrace = trace;
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
			
			string saveDir = "C:\\";//config.saveDir;
			foreach (string file in childrenFiles)
			{
				
				string childFilePath = Path.Combine(saveDir, file);

				if (Path.GetDirectoryName(childFilePath) != saveDir)
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
