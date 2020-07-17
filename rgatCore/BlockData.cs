using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{
	class BlockData
	{
		public BlockData(uint firstVert, uint lastVert)
		{
			FirstNodeIdx = firstVert;
			LastNodeIdx = lastVert;
		}

		uint FirstNodeIdx, LastNodeIdx;
	}
}
