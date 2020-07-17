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
		NamedPipeServerStream nps = null;

		void GotMessage(IAsyncResult ir)
        {


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

            nps = new NamedPipeServerStream("rgatCoordinator", PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.WriteThrough);

            while (!_clientState.rgatIsExiting)
            {
				IAsyncResult res1 = nps.BeginWaitForConnection(new AsyncCallback(ConnectCallback), nps);

				while (!nps.IsConnected)
				{
					if (_clientState.rgatIsExiting) return;
					Thread.Sleep(100);
				}


				Console.WriteLine("rgatCoordinator pipe connected");


				byte[] buf = new byte[1024];
				var readres = nps.BeginRead(buf, 0, 1024, new AsyncCallback(GotMessage), null);

				Console.WriteLine("Began read");
				int mush = WaitHandle.WaitAny(new WaitHandle[] { readres.AsyncWaitHandle }, 2000);

				if (!readres.IsCompleted)
				{
					Console.WriteLine($"Warning: Read timeout for coordinator connection, abandoning");
					
				}
				else
                {
					int bytesRead = Array.FindIndex(buf, elem => elem == 0);

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
							string programName = fields[4];
							if (success)
							{
								string response = "CT@" + GetCtrlPipeName(PID, randno) + "@BB@" +GetBBPipeName(PID,randno) + "@\x00";
								byte[] outBuffer = System.Text.Encoding.UTF8.GetBytes(response);
								nps.Write(outBuffer);
								Task startTask = Task.Run(() => process_new_pin_connection(PID, arch, randno, programName));
								Console.WriteLine("Coordinator connection complete");
							}
							else
							{
								Console.WriteLine("Coordinator got bad buf from client: " + csString);
							}
						}
					}

				}
				nps.EndRead(readres);
				if (nps.IsConnected) nps.Disconnect();

				//process_new_pin_connection(clientState, threadsList, pBuf);
				//read in PID 
				//open pipe/coordinator threads
				//send pipenames for PID

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
			int ret = 0;

			TraceRecord tr = new TraceRecord(PID, ID, target, DateTime.Now, TraceRecord.eTracePurpose.eVisualiser, arch);
			ModuleHandlerThread moduleHandler = new ModuleHandlerThread(target, tr, _clientState);

			moduleHandler.Begin(GetCtrlPipeName(PID, ID));


			BlockHandlerThread blockHandler = new BlockHandlerThread(target, tr, _clientState);
			blockHandler.Begin(GetBBPipeName(PID, ID));
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
