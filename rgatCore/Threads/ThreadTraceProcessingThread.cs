using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace rgatCore.Threads
{
    class ThreadTraceProcessingThread
    {
        ProtoGraph protograph;
        ThreadTraceIngestThread ingestThread;
        Thread runningThread;

        public ThreadTraceProcessingThread(ProtoGraph newProtoGraph, ThreadTraceIngestThread _ingestionthread)
        {
            protograph = newProtoGraph;
            ingestThread = _ingestionthread;

            runningThread = new Thread(Processor);
            runningThread.Name = "TraceProcessor"+this.protograph.ThreadID;
            runningThread.Start();
        }


        void Processor()
        {
            while (!ingestThread.StopFlag)
            {
                byte[] msg = ingestThread.DeQueueData();
                if (msg == null)
                {
                    Console.WriteLine("Proc got no data, waiting");
                    ingestThread.RequestWakeupOnData();
                    ingestThread.dataReadyEvent.WaitOne();
                    Console.WriteLine("Proc woke");
                    continue;
                }


                switch (msg[0])
                {
                    case (byte)'j':
                        Console.WriteLine("Handle TRACE_TAG_MARKER");
                        break;
                    case (byte)'R':
                        Console.WriteLine("Handle LOOP_MARKER");
                        break;
                    case (byte)'A':
                        Console.WriteLine("Handle ARG_MARKER");
                        break;
                    case (byte)'U':
                        Console.WriteLine("Handle UNLINK_MARKER");
                        break;
                    case (byte)'u':
                        Console.WriteLine("Handle UNCHAIN_MARKER");
                        break;
                    case (byte)'B':
                        Console.WriteLine("Handle EXECUTECOUNT_MARKER");
                        break;
                    case (byte)'s':
                        Console.WriteLine("Handle SATISFY_MARKER");
                        break;
                    case (byte)'X':
                        Console.WriteLine("Handle EXCEPTION_MARKER");
                        break;
                    case (byte)'Z':
                        Console.WriteLine("Handle Thread Terminated");
                        break;
                    default:
                        Console.WriteLine($"Handle unknown tag {(char)msg[0]}");
                        break;
                }

            }
            Console.WriteLine(runningThread.Name + " finished");
        }

    }
}
