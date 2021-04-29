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
        public ProcessCoordinatorThread(rgatState _rgatstate) {
			_clientState = _rgatstate;
			runningThread = new Thread(Listener);
			runningThread.Name = "ProcessCoordinator";
			runningThread.Start();
		}

		byte[] buf = new byte[1024];
		NamedPipeServerStream coordPipe = null;

		void GotMessage(IAsyncResult ir)
        {

			int bytesRead = coordPipe.EndRead(ir);
			bytesRead = Array.FindIndex(buf, elem => elem == 0);

			if (bytesRead > 0 && bytesRead < 1024)
			{

				string csString = System.Text.Encoding.UTF8.GetString(buf[0..bytesRead]);

				string[] fields = csString.Split(',');

				Console.WriteLine($"Coordinator thread read: {bytesRead} bytes, {fields.Length} fields: " + fields.ToString());
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
						string response = $"CT@{GetCtrlPipeName(PID, randno)}@BB@{GetBBPipeName(PID, randno)}@\x00";
						byte[] outBuffer = System.Text.Encoding.UTF8.GetBytes(response);
						coordPipe.Write(outBuffer);
						Task startTask = Task.Run(() => process_new_pin_connection(PID, arch, randno, programName));
						Console.WriteLine("Coordinator connection complete");
					}
					else
					{
						Console.WriteLine("Coordinator got bad buf from client: " + csString);
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
				Console.WriteLine("Coordinator pipe connected ");
			}
			catch (Exception e)
			{

			}
			
		}

		rgatState _clientState = null;
        public void Listener()
        {
            try { 

				coordPipe = new NamedPipeServerStream("rgatCoordinator", PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.WriteThrough);
			} catch ( System.IO.IOException e)
            {
				Console.WriteLine($"Error: Failed to start bootstrap thread '{e.Message}' so rgat will not process incoming traces");
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


				Console.WriteLine("rgatCoordinator pipe connected");

				var readres = coordPipe.BeginRead(buf, 0, 1024, new AsyncCallback(GotMessage), null);

				Console.WriteLine("Began read");
				int mush = WaitHandle.WaitAny(new WaitHandle[] { readres.AsyncWaitHandle }, 2000);

				if (!readres.IsCompleted)
				{
					Console.WriteLine($"Warning: Read timeout for coordinator connection, abandoning");
				}
				while (coordPipe.IsConnected) Thread.Sleep(5);
			}

        }

		public string GetCtrlPipeName(uint PID, long instanceID)
		{
			return "CT" + PID.ToString() + instanceID.ToString();
		}
		public string GetBBPipeName(uint PID, long instanceID)
		{
			return "BB" + PID.ToString() + instanceID.ToString();
		}


		private void process_new_pin_connection(uint PID, int arch, long ID, string programName)
		{
			Console.WriteLine($"New Pin connection from {programName} (PID:{PID}, arch:{arch})");

			BinaryTarget target = null;
			if (!_clientState.targets.GetTargetByPath(programName, out target))
            {
				target = _clientState.AddTargetByPath(programName, arch, true);
			}
			if (target.BitWidth != arch)
            {
				if (target.BitWidth != 0) 
                {
					Console.WriteLine($"Warning: Incoming process reports different arch {arch} to binary {target.BitWidth}");
                }
				target.BitWidth = arch;
			}
			int ret = 0;

			//TraceRecord tr = new TraceRecord(PID, ID, target, DateTime.Now, TraceRecord.eTracePurpose.eVisualiser, arch);

			target.CreateNewTrace(DateTime.Now, PID, (uint)ID, out TraceRecord tr);
			ModuleHandlerThread moduleHandler = new ModuleHandlerThread(target, tr, _clientState);
			tr.SetModuleHandlerThread(moduleHandler);
			moduleHandler.Begin(GetCtrlPipeName(PID, ID));


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
