using Gee.External.Capstone.PowerPc;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.Dynamic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Vulkan;

namespace rgatCore.Threads
{
    class ProcessCoordinatorThread
    {
		private Thread runningThread = null;
		rgatState _clientState = null;
		byte[] buf = new byte[1024];
		NamedPipeServerStream coordPipe = null;


		public ProcessCoordinatorThread(rgatState _rgatstate) 
		{
			_clientState = _rgatstate;
			runningThread = new Thread(Listener);
			runningThread.Name = "ProcessCoordinator";
			runningThread.Start();
		}


		void GotMessage(IAsyncResult ir)
        {

			int bytesRead = coordPipe.EndRead(ir);
			bytesRead = Array.FindIndex(buf, elem => elem == 0);

			if (bytesRead > 0 && bytesRead < 1024)
			{

				string csString = System.Text.Encoding.UTF8.GetString(buf[0..bytesRead]);

				string[] fields = csString.Split(',');
				Logging.RecordLogEvent($"Coordinator thread read: {bytesRead} bytes, {fields.Length} fields: {fields}", Logging.LogFilterType.TextDebug);

				if (fields.Length == 5)
				{
					bool success = true;
					if (fields[0] != "PID") success = false;
					if (!uint.TryParse(fields[1], out uint PID)) success = false;
					if (!int.TryParse(fields[2], out int arch)) success = false;
					if (!long.TryParse(fields[3], out long randno)) success = false;
					if (success)
					{
						string programName = fields[4];
						string cmdPipeName = ModuleHandlerThread.GetCommandPipeName(PID, randno);
						string eventPipeName = ModuleHandlerThread.GetEventPipeName(PID, randno);
						string response = $"CM@{cmdPipeName}@CR@{eventPipeName}@BB@{GetBBPipeName(PID, randno)}@\x00";
						byte[] outBuffer = System.Text.Encoding.UTF8.GetBytes(response);
						coordPipe.Write(outBuffer);
						Task startTask = Task.Run(() => process_new_pin_connection(PID, arch, randno, programName));
						Logging.RecordLogEvent($"Coordinator connection initiated", Logging.LogFilterType.TextDebug);
					}
					else
					{
						Logging.RecordLogEvent($"Coordinator got bad data from client: " + csString, Logging.LogFilterType.TextError);
					}
				}
			}

			if (coordPipe.IsConnected) coordPipe.Disconnect();
		}

		void ConnectCallback(IAsyncResult ar)
		{
			NamedPipeServerStream nps = (NamedPipeServerStream)ar.AsyncState;

			try
			{
				nps.EndWaitForConnection(ar);
				Logging.RecordLogEvent($"Incoming connection on coordinator pipe", Logging.LogFilterType.TextDebug);
			}
			catch (Exception e)
			{
				Logging.RecordLogEvent($"Coordinator pipe callback exception {e.Message}", Logging.LogFilterType.TextError);
			}
			
		}


        public void Listener()
        {
            try { 

				coordPipe = new NamedPipeServerStream("rgatCoordinator", PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.WriteThrough);
			} catch ( System.IO.IOException e)
			{
				string errmsg = $"Error: Failed to start bootstrap thread '{e.Message}' so rgat will not process incoming traces";
				Logging.RecordLogEvent(errmsg, Logging.LogFilterType.TextAlert);
				//todo: does this happen outside of debugging? if so A: figure out why, B:give visual indication
				return;
            }

			while (!_clientState.rgatIsExiting)
            {
				IAsyncResult res1 = coordPipe.BeginWaitForConnection(new AsyncCallback(ConnectCallback), coordPipe);

				while (!coordPipe.IsConnected)
				{
					if (_clientState.rgatIsExiting) return;
					Thread.Sleep(100);
				}


				Logging.RecordLogEvent($"rgatCoordinator pipe connected", Logging.LogFilterType.TextDebug);

				var readres = coordPipe.BeginRead(buf, 0, 1024, new AsyncCallback(GotMessage), null);

				Logging.RecordLogEvent("rgatCoordinator began read", Logging.LogFilterType.TextDebug);

				int mush = WaitHandle.WaitAny(new WaitHandle[] { readres.AsyncWaitHandle }, 2000);

				if (!readres.IsCompleted)
				{
					Logging.RecordLogEvent("Warning: Read timeout for coordinator connection, abandoning");
				}
				while (coordPipe.IsConnected) Thread.Sleep(5);
			}

        }



		static string GetBBPipeName(uint PID, long instanceID)
		{
			return "BB" + PID.ToString() + instanceID.ToString();
		}


		private void process_new_pin_connection(uint PID, int arch, long ID, string programName)
		{
			string shortName = Path.GetFileName(programName).Substring(0, Math.Min(programName.Length, 20));
			string msg = $"New instrumentation connection with {arch}-bit trace: {shortName} (PID:{PID})";

			Logging.RecordLogEvent(msg, Logging.LogFilterType.TextDebug);

			BinaryTarget target;
			if (!_clientState.targets.GetTargetByPath(programName, out target))
            {
				target = _clientState.AddTargetByPath(programName, arch, true);
			}
			
			if (target.BitWidth != arch)
            {
				if (target.BitWidth != 0)
				{
					msg = $"Warning: Incoming process reports different arch {arch} to binary {target.BitWidth}";
					Logging.RecordLogEvent(msg, Logging.LogFilterType.TextError);
                }
				target.BitWidth = arch;
			}
			int ret = 0;

			//TraceRecord tr = new TraceRecord(PID, ID, target, DateTime.Now, TraceRecord.eTracePurpose.eVisualiser, arch);

			_clientState.NewInstrumentationConnection();

			target.CreateNewTrace(DateTime.Now, PID, (uint)ID, out TraceRecord tr);
			ModuleHandlerThread moduleHandler = new ModuleHandlerThread(target, tr, _clientState);
			tr.SetModuleHandlerThread(moduleHandler);
			moduleHandler.Begin(ID);

			tr.RecordTimelineEvent(Logging.eTimelineEvent.ProcessStart, PID);


			BlockHandlerThread blockHandler = new BlockHandlerThread(target, tr, _clientState);
			tr.SetBlockHandlerThread(blockHandler);
			blockHandler.Begin(GetBBPipeName(PID, ID));

			//_clientState.SwitchTrace = tr;

			ProcessLaunching.launch_new_visualiser_threads(target, tr, _clientState);
		}
	}
}
