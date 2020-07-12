using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore.Threads
{
    class ThreadTraceProcessingThread
    {
        ProtoGraph protograph;
        ThreadTraceIngestThread ingestThread;
        public ThreadTraceProcessingThread(ProtoGraph newProtoGraph, ThreadTraceIngestThread _ingestionthread)
        {
            protograph = newProtoGraph;
            ingestThread = _ingestionthread;
        }



    }
}
