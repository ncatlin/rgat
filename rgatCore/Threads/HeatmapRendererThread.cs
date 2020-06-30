using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore.Threads
{
	class HeatmapRendererThread
	{
		TraceRecord RenderedTrace = null;
		bool running = false;
		public rgatState rgatState = null;

		public HeatmapRendererThread(TraceRecord _renderedTrace, rgatState _clientState)
		{
			RenderedTrace = _renderedTrace;
			rgatState = _clientState;
		}
		public void ThreadProc()
		{

		}
	}
}
