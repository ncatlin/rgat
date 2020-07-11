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
			runningThread.Start();
		}

		byte[] buf = new byte[1024];
		NamedPipeServerStream nps = null;

		void GotMessage(IAsyncResult ir)
        {


		}


		rgatState _clientState = null;
        public void Listener()
        {

            nps = new NamedPipeServerStream("rgatCoordinator", PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.WriteThrough);

            while (!_clientState.rgatIsExiting)
            {
                nps.WaitForConnection();
                Console.WriteLine("rgatCoordinator pipe connected");


				byte[] buf = new byte[1024];
				var readres = nps.BeginRead(buf, 0, 1024, new AsyncCallback(GotMessage), null);
				//int ff = nps.EndRead(readres);
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
							if (!ulong.TryParse(fields[1], out ulong PID)) success = false;
							if (!int.TryParse(fields[2], out int arch)) success = false;
							if (!ulong.TryParse(fields[3], out ulong randno)) success = false;
							string programName = fields[4];
							if (success)
							{
								string response = "NP@" + GetCtrlPipeName(PID, randno) + "@MD@" + GetModulePipeName(PID, randno) + "@BB@" +GetBBPipeName(PID,randno) + "@\x00";
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

		public string GetModulePipeName(ulong PID, ulong instanceID)
		{
			return "MD" + PID.ToString() + instanceID.ToString();
		}

		public string GetCtrlPipeName(ulong PID, ulong instanceID)
		{
			return "CT" + PID.ToString() + instanceID.ToString();
		}
		public string GetBBPipeName(ulong PID, ulong instanceID)
		{
			return "BB" + PID.ToString() + instanceID.ToString();
		}


		private void process_new_pin_connection(ulong PID, int arch, ulong ID, string programName)
        {
			int ret = 0;
			BinaryTarget bt = new BinaryTarget("dfoskdf");
			TraceRecord tr = new TraceRecord(3445, 33424,bt , DateTime.Now);
			ModuleHandlerThread moduleHandler = new ModuleHandlerThread(bt, tr, _clientState, 23213);
			Console.WriteLine("before snepep");
			moduleHandler.OpenPipes(GetCtrlPipeName(PID, ID), GetModulePipeName(PID, ID));
			Console.WriteLine("fsdfs");
			return;
			//spawn_client_listeners()
			/*

			PIN_PIPES localHandles;
			create_pipes_for_pin(PID, PID_ID, sharedMem, localHandles, bitWidth);

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
