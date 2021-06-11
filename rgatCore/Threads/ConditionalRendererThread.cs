using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore.Threads
{
	public class ConditionalRendererThread
	{
		TraceRecord RenderedTrace = null;
		bool running = false;
		public rgatState rgatState = null;

		public ConditionalRendererThread(TraceRecord _renderedTrace, rgatState _clientState)
		{
			RenderedTrace = _renderedTrace;
			rgatState = _clientState;
		}

		public void ThreadProc()
		{

		}
	}
}
