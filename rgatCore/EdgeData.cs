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
		//bool serialise(rapidjson::Writer<rapidjson::FileWriteStream>& writer, int source, int target);

		//type of edge (call,extern,etc)
		public eEdgeNodeType edgeClass;

		//number of times executed, temporary variable used by heatmap solver
		public ulong chainedWeight = 0;

		//number of verticies taken up in OpenGL data
		//public int vertSize = 0;
		//position in rendering data structure
		//public int arraypos = 0;
		public uint EdgeIndex = 0;
	}
}
