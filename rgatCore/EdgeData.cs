using Newtonsoft.Json.Linq;

namespace rgat
{
    /// <summary>
    /// Data for a Node -> Node Edge
    /// </summary>
    public class EdgeData
    {
        /// <summary>
        /// Create a new edge
        /// </summary>
        /// <param name="index">Index of the edge in the edge list</param>
        /// <param name="sourceType">Type of soure node (jump, etc)</param>
        /// <param name="execCount">Number of edge executions</param>
        public EdgeData(int index, CONSTANTS.EdgeNodeType sourceType, ulong execCount = 0)
        {
            EdgeListIndex = index;
            sourceNodeType = sourceType;
            ExecutionCount = execCount;
        }


        /// <summary>
        /// Create an edge from serialised edge data
        /// </summary>
        /// <param name="serialised">JArray of edge data items</param>
        /// <param name="index">Index of the edge in the edge list</param>
        /// <param name="sourceType">Type of soure node (jump, etc)</param>
        public EdgeData(JArray serialised, int index, CONSTANTS.EdgeNodeType sourceType)
        {
            EdgeListIndex = index;
            edgeClass = (CONSTANTS.EdgeNodeType)serialised[2].ToObject<uint>();
            ExecutionCount = serialised[3].ToObject<ulong>();
            sourceNodeType = sourceType;
        }



        /// <summary>
        /// Convert the edge to JSON that can be saved
        /// </summary>
        /// <param name="src">Source node index</param>
        /// <param name="targ">Target node index</param>
        /// <returns></returns>
        public JArray Serialise(uint src, uint targ)
        {
            JArray edgearr = new JArray();
            edgearr.Add(src);
            edgearr.Add(targ);
            edgearr.Add(edgeClass);
            edgearr.Add(ExecutionCount);
            return edgearr;
        }



        /// <summary>
        /// The type of edge (call,extern,etc)
        /// </summary>
        public CONSTANTS.EdgeNodeType edgeClass;
        /// <summary>
        /// The type of source node
        /// </summary>
        public CONSTANTS.EdgeNodeType sourceNodeType;

        /// <summary>
        /// How many time this edge has executed
        /// </summary>
        public ulong ExecutionCount { get; private set; } = 0;

        /// <summary>
        /// Sethow many times this edge has executed
        /// </summary>
        /// <param name="value"></param>
        public void SetExecutionCount(ulong value)
        {
            ExecutionCount = value;
        }

        /// <summary>
        /// Increase the execution count by a specified amount
        /// </summary>
        /// <param name="value">Amount to increase</param>
        public void IncreaseExecutionCount(ulong value)
        {
            SetExecutionCount(ExecutionCount + value);
        }


        /// <summary>
        /// position of this edge in the edge list
        /// </summary>
        public int EdgeListIndex = 0;

        /// <summary>
        /// Ranking of how busy this edge is relative to other edges, from 0 [least] to 9 [most]
        /// </summary>
        public float heatRank = 0;
    }
}
