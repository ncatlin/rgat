using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.IO.Pipes;
using System.Numerics;
using System.Text;
using System.Threading;

namespace rgatCore
{
    class ThreadTraceIngestThread
    {
        uint TraceBufSize = GlobalConfig.TraceBufferSize;
        ProtoGraph protograph;
        NamedPipeServerStream threadpipe;
        Thread runningThread;

        public bool StopFlag = false;



        private readonly object QueueSwitchLock = new object();
        int readIndex = 0;
        List<string> FirstQueue = new List<string>();
        List<string> SecondQueue = new List<string>();
        List<string> ReadingQueue = null;
        bool ReadingFirstQueue = true;



        public ThreadTraceIngestThread(ProtoGraph newProtoGraph, NamedPipeServerStream _threadpipe)
        {
            TraceBufSize = GlobalConfig.TraceBufferSize;
            protograph = newProtoGraph;
            threadpipe = _threadpipe;

            runningThread = new Thread(Reader);
            runningThread.Start();
        }

        void ReadCallback(IAsyncResult ar)
        {
            int bytesread = 0;
            byte[] buf = (byte[])ar.AsyncState;
            try
            {
                bytesread = threadpipe.EndRead(ar);
            }
            catch (Exception e)
            {
                Console.WriteLine("TraceIngest Readcall back exception " + e.Message);
                return;
            }

            if (bytesread == 0)
            {
                Console.WriteLine($"WARNING: Trace pipe read 0 bytes from RID {protograph.ThreadID}");
                return;
            }

            Console.WriteLine("TraceIngest pipe read unhandled entry from TID " + protograph.ThreadID);
            Console.WriteLine("\t"+System.Text.ASCIIEncoding.ASCII.GetString(buf));
        }


        //thread handler to build graph for a thread
        void Reader()
        {
            if (!threadpipe.IsConnected)
            {
                Console.WriteLine("Error - ThreadTraceIngestThread expected a connected thread pipe");
                return;
            }

            const uint TAGCACHESIZE = 1024 ^ 2;
            char[] TagReadBuffer = new char[TAGCACHESIZE];



            while (!StopFlag && threadpipe.IsConnected)
            {
                byte[] buf = new byte[4096 * 4];
                IAsyncResult res = threadpipe.BeginRead(buf, 0, 2000, new AsyncCallback(ReadCallback), buf);
                WaitHandle.WaitAny(new WaitHandle[] { res.AsyncWaitHandle }, 2000);
                if (!res.IsCompleted)
                {
                    try { threadpipe.EndRead(res); }
                    catch (Exception e)
                    {
                        Console.WriteLine("Exception on threadreader read : " + e.Message);
                    };
                }
            }

            /*

			//DateTime cl;
			ulong itemsRead = 0;
			uint bytesRead = 0;
			long spins = 0;
			DateTime endwait = DateTime.Now.AddSeconds(1);
			while (!StopFlag)
			{
				//should maybe have this as a timer but the QT one is more of a pain to set up
				DateTime secondsnow = DateTime.Now;
				if (secondsnow > endwait)
				{
					endwait = DateTime.Now.AddSeconds(1);
					//if (thisgraph)
					//	thisgraph->setBacklogIn(itemsRead);
					itemsRead = 0;
				}

				bool errorFlag = false;
				if (!data_available(errorFlag))
				{
					if (errorFlag)
						break;
					else
					{
						//sleeping at every fail makes it very slow - tends to be either a few or thousands
						//sleeping on a long wait reduces cpu usage a lot while not impacting performance much
						spins++;
						if (spins > 30)
							Thread.Sleep(1);
						continue;
					}
				}
				spins = 0;

				if (!read_data(tagReadBuf, bytesRead))
					break;
				if (bytesRead >= TAGCACHESIZE)
				{
					Console.WriteLine($"\t\t[rgat]Error: Thread trace messsage exceeded cache size {bytesRead} >= {TAGCACHESIZE}");
					break;
				}

				TagReadBuffer[bytesRead] = 0;
				if ((bytesRead == 0) || TagReadBuffer[bytesRead - 1] != '@')
				{
					StopFlag = true;
					if (bytesRead == 0) break;
					if (TagReadBuffer[0] != 'X')
					{
						string bufstring = TagReadBuffer[0..bytesRead];
						Console.WriteLine($"[rgat]Warning: [threadid {protograph.ThreadID}] Improperly terminated trace message recieved [{bufstring}]. ({bufstring.Length} bytes) Terminating.");
					}

					break;
				}

				//we can improve this if it's a bottleneck
				string* msgbuf = new string(tagReadBuf.begin(), tagReadBuf.begin() + bytesRead);

				add_message(msgbuf);
				++itemsRead;
			}

			*/
            threadpipe.Disconnect();
            threadpipe.Dispose();

            //wait until buffers emptied
            while ((FirstQueue.Count > 0 || SecondQueue.Count > 0) && !StopFlag)
                Thread.Sleep(25);

        }




    }
}
