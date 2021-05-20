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

				_clientState.AddLogMessage($"Coordinator thread read: {bytesRead} bytes, {fields.Length} fields: {fields.ToString()}",
					rgatState.eMessageType.eDebug);

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
						_clientState.AddLogMessage($"Coordinator connection initiated", rgatState.eMessageType.eDebug);
					}
					else
					{
						_clientState.AddLogMessage($"Coordinator got bad data from client: " + csString);
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
				_clientState.AddLogMessage($"Incoming connection on coordinator pipe", rgatState.eMessageType.eDebug);
			}
			catch (Exception e)
			{
				_clientState.AddLogMessage($"Coordinator pipe callback exception {e.Message}", rgatState.eMessageType.eDebug);
			}
			
		}


        public void Listener()
        {
            try { 

				coordPipe = new NamedPipeServerStream("rgatCoordinator", PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.WriteThrough);
			} catch ( System.IO.IOException e)
			{
				_clientState.AddLogMessage($"Error: Failed to start bootstrap thread '{e.Message}' so rgat will not process incoming traces", rgatState.eMessageType.Alert);
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


				_clientState.AddLogMessage($"rgatCoordinator pipe connected", rgatState.eMessageType.eDebug);

				var readres = coordPipe.BeginRead(buf, 0, 1024, new AsyncCallback(GotMessage), null);

				_clientState.AddLogMessage("rgatCoordinator began read", rgatState.eMessageType.eDebug);

				int mush = WaitHandle.WaitAny(new WaitHandle[] { readres.AsyncWaitHandle }, 2000);

				if (!readres.IsCompleted)
				{
					_clientState.AddLogMessage("Warning: Read timeout for coordinator connection, abandoning", rgatState.eMessageType.eLog);
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
			string msg = $"New {arch}-bit trace: {shortName} (PID:{PID})";
			_clientState.AddVisualiserMessage(msg, rgatState.eMessageType.eVisAll, null, new WritableRgbaFloat(System.Drawing.Color.LightGreen));

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
					_clientState.AddLogMessage(msg, rgatState.eMessageType.eLog, null, new WritableRgbaFloat(System.Drawing.Color.Red));
                }
				target.BitWidth = arch;
			}
			int ret = 0;

			//TraceRecord tr = new TraceRecord(PID, ID, target, DateTime.Now, TraceRecord.eTracePurpose.eVisualiser, arch);

			target.CreateNewTrace(DateTime.Now, PID, (uint)ID, out TraceRecord tr);
			ModuleHandlerThread moduleHandler = new ModuleHandlerThread(target, tr, _clientState);
			tr.SetModuleHandlerThread(moduleHandler);
			moduleHandler.Begin(ID);


			BlockHandlerThread blockHandler = new BlockHandlerThread(target, tr, _clientState);
			tr.SetBlockHandlerThread(blockHandler);
			blockHandler.Begin(GetBBPipeName(PID, ID));

			//_clientState.SwitchTrace = tr;


			ProcessLaunching.launch_new_visualiser_threads(target, tr, _clientState);

			return;
		/*



			PID_TID parentPID = getParentPID(PID); //todo: pin can do this

			binaryTarget* target;
			binaryTargets* container;

			if (clientState->testsRunning && clientState->testTargets.exists(binarypath))
				container = &clientState->testTargets;
			else
				container = &clientState->targets;

			container->getTargetByPath(binarypath, &target);

			target->applyBitWidthHint(bitWidth);

			traceRecord* trace = target->createNewTrace(PID, PID_ID, std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
			trace->setTraceType(eTracePurpose::eVisualiser);
			trace->notify_new_pid(PID, PID_ID, parentPID);

			container->registerChild(parentPID, trace);


			launch_new_visualiser_threads(target, trace, clientState, localHandles);

			threadsList->push_back((RGAT_THREADS_STRUCT*)trace->processThreads);

			if (clientState->waitingForNewTrace)
			{
				clientState->updateActivityStatus("New process started with PID: " + QString::number(trace->PID), 5000);
				clientState->switchTrace = trace;
				clientState->waitingForNewTrace = false;
			}
			*/

		}
	}
}
