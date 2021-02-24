using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{
    class EdgeData
	{
		public EdgeData(int index) => EdgeIndex = (uint)index;

		//write to provided file. This class doesn't actually contain the source
		//and the target of the edge, so pass those along too
		public JArray Serialise(uint src, uint targ)
        {
			JArray edgearr = new JArray();
			edgearr.Add(src);
			edgearr.Add(targ);
			edgearr.Add(edgeClass);
			return edgearr;
        }

		//type of edge (call,extern,etc)
		public eEdgeNodeType edgeClass;

		public ulong executionCount { get; private set; } = 0;
		public void SetExecutionCount(ulong value) { executionCount = value; }

		public void IncreaseExecutionCount(ulong value) { SetExecutionCount(executionCount + value); }

		public bool heatComplete = false;

		public uint EdgeIndex = 0;
		public float heatRank = 0; //0-1 least to most busy
	}
}
