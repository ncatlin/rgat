using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{
    class EdgeData
	{
		public EdgeData() {; }

		//write to provided file. This class doesn't actually contain the source
		//and the target of the edge, so pass those along too
		//bool serialise(rapidjson::Writer<rapidjson::FileWriteStream>& writer, int source, int target);

		//type of edge (call,extern,etc)
		eEdgeNodeType edgeClass;

		//number of times executed, temporary variable used by heatmap solver
		ulong chainedWeight = 0;

		//number of verticies taken up in OpenGL data
		ulong vertSize = 0;
		//position in rendering data structure
		ulong arraypos = 0;
	}
}
