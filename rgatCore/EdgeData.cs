using Newtonsoft.Json.Linq;

namespace rgat
{
    public class EdgeData
    {
        public EdgeData(int index, RGAT_CONSTANTS.eEdgeNodeType sourceType, ulong execCount = 0)
        {
            EdgeListIndex = index;
            sourceNodeType = sourceType;
            executionCount = execCount;
        }

        public EdgeData(JArray serialised, int index, RGAT_CONSTANTS.eEdgeNodeType sourceType)
        {
            EdgeListIndex = index;
            edgeClass = (RGAT_CONSTANTS.eEdgeNodeType)serialised[2].ToObject<uint>();
            executionCount = serialised[3].ToObject<ulong>();
            sourceNodeType = sourceType;
        }

        //write to provided file. This class doesn't actually contain the source
        //and the target of the edge, so pass those along too
        public JArray Serialise(uint src, uint targ)
        {
            JArray edgearr = new JArray();
            edgearr.Add(src);
            edgearr.Add(targ);
            edgearr.Add(edgeClass);
            edgearr.Add(executionCount);
            return edgearr;
        }


        //type of edge (call,extern,etc)
        public RGAT_CONSTANTS.eEdgeNodeType edgeClass;
        public RGAT_CONSTANTS.eEdgeNodeType sourceNodeType;

        public ulong executionCount { get; private set; } = 0;
        public void SetExecutionCount(ulong value)
        {
            executionCount = value;
        }

        public void IncreaseExecutionCount(ulong value)
        {
            SetExecutionCount(executionCount + value);
        }

        public bool heatComplete = false;

        public int EdgeListIndex = 0;
        public float heatRank = 0; //0-9 least to most busy
    }
}
