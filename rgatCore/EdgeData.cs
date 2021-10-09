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
        /// <param name="edgeType">The control flow class of the edge</param>
        /// <param name="execCount">The number of recorded edge executions</param>
        /// <param name="index">Index of the edge in the edge list</param>
        /// <param name="sourceType">Type of soure node (jump, etc)</param>
        public EdgeData(CONSTANTS.EdgeNodeType edgeType, ulong execCount, int index, CONSTANTS.EdgeNodeType sourceType)
        {
            EdgeListIndex = index;
            edgeClass = edgeType;
            ExecutionCount = execCount;
            sourceNodeType = sourceType;
        }



        /// <summary>
        /// Output the edge tuple and data to the json writer
        /// </summary>
        /// <param name="srctarg">Source/Target node indexes</param>
        /// <param name="writer">Json Writer</param>
        public void Serialise(System.Tuple<uint, uint> srctarg, Newtonsoft.Json.JsonWriter writer)
        {
            writer.WriteValue(srctarg.Item1);
            writer.WriteValue(srctarg.Item2);
            writer.WriteValue(edgeClass);
            writer.WriteValue(ExecutionCount);
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
