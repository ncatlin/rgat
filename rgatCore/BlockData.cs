using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{
	class BlockData
	{
		BlockData(uint firstVert, uint lastVert)
		{
			FirstNodeIdx = firstVert;
			LastNodeIdx = lastVert;
		}

		uint FirstNodeIdx, LastNodeIdx;
	}
}
