using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Text;
using Veldrid;
/*
This class holds (and provides dubiously mutex guarded access to) OpenGl vertex and colour data
*/
namespace rgatCore
{
    struct WritableRgbaFloat
    {
        public WritableRgbaFloat(Color col)
        {
            R = (float)col.R / 255f;
            G = (float)col.G / 255f;
            B = (float)col.B / 255f;
            A = (float)col.A / 255f;
        }

        public Vector4 ToVec4()
        {
            return new Vector4(R, G, B, A);
        }

        public static Vector4 ToVec4(Color col)
        {
            float R = (float)col.R / 255f;
            float G = (float)col.G / 255f;
            float B = (float)col.B / 255f;
            float A = (float)col.A / 255f;
            return new Vector4(R, G, B, A);
        }

        public static RgbaFloat ToRgbaFloat(Color col)
        {
            float R = (float)col.R / 255f;
            float G = (float)col.G / 255f;
            float B = (float)col.B / 255f;
            float A = (float)col.A / 255f;
            return new RgbaFloat(R, G, B, A);
        }

        public float R { get; set; }
        public float G { get; set; }
        public float B { get; set; }
        public float A { get; set; }

    }
    struct VertexPositionColor
    {
        public Vector3 Position;
        public WritableRgbaFloat Color;
        public float ActiveAnimAlpha;
        public const uint SizeInBytes = 32;

        public VertexPositionColor(Vector3 position, WritableRgbaFloat color, float AnimDarkAlpha)
        {
            Position = position;
            Color = color;
            ActiveAnimAlpha = AnimDarkAlpha;
        }
        public void SetAlpha(float alpha) => Color.A = alpha;
        public void SetAnimAlpha(float alpha)
        {
            ActiveAnimAlpha = alpha;
        }

        public VertexPositionColor(Vector3 position, Veldrid.RgbaFloat color, float AnimDarkAlpha)
        {
            Position = position;
            Color = new WritableRgbaFloat()
            {
                A = color.A,
                B = color.B,
                G = color.G,
                R = color.R
            };
            ActiveAnimAlpha = AnimDarkAlpha;
        }
    }

    class GraphDisplayData
    {

        private readonly object ListLock = new object();

        public List<VertexPositionColor> VertList = new List<VertexPositionColor>();
        public int CountVerts() => VertList.Count;

        private List<object> node_coords = new List<object>();
        public int NodeCount { get; private set; } = 0;

        //keep track of which a,b coords are occupied - may need to be unique to each plot
        public Dictionary<Tuple<float, float>, bool> usedCoords = new Dictionary<Tuple<float, float>, bool>();

        public PLOT_TRACK LastRenderedNode;
        public PLOT_TRACK LastAnimatedNode;

        public List<Tuple<int, int>> Edges_VertSizes_ArrayPositions = new List<Tuple<int, int>>();

        public GraphDisplayData(bool preview = false)
        {
            LastRenderedNode.lastVertID = 0;
            LastRenderedNode.lastVertType = eEdgeNodeType.eFIRST_IN_THREAD;
            LastAnimatedNode.lastVertID = 0;
            LastAnimatedNode.lastVertType = eEdgeNodeType.eFIRST_IN_THREAD;
            IsPreview = preview;
        }
        ~GraphDisplayData()
        {
            //acquire_pos_write();vector
            //acquire_col_write();
        }

        public void SetNodeAnimAlpha(uint index, float alpha)
        {
            lock (ListLock) //todo, should be a read lock 
            {
                if (index < VertList.Count)
                {
                    VertexPositionColor vpc = VertList[(int)index];
                    vpc.ActiveAnimAlpha = alpha;
                    VertList[(int)index] = vpc;
                    //Console.WriteLine($"SetNodeAnimAlpha node {index} now {vpc.ActiveAnimAlpha}");
                    DataChanged = true;
                }
            }
        }


        public bool ReduceNodeAnimAlpha(uint index, float alpha)
        {
            lock (ListLock) //todo, should be a read lock
            {
                if (index >= VertList.Count) return false;
                VertexPositionColor vpc = VertList[(int)index];
                vpc.ActiveAnimAlpha = Math.Max(vpc.ActiveAnimAlpha - alpha, GlobalConfig.AnimatedFadeMinimumAlpha);
                VertList[(int)index] = vpc;
                //Console.WriteLine($"ReduceNodeAnimAlpha node {index} now {vpc.ActiveAnimAlpha}");
                DataChanged = true;
                return (vpc.ActiveAnimAlpha <= GlobalConfig.AnimatedFadeMinimumAlpha);
            }
        }


        public void SetEdgeAnimAlpha(int arraystart, int vertcount, float alpha)
        {
            lock (ListLock) //todo, should be a read lock
            {
                Console.WriteLine($"Setting alpha of edge verts {arraystart}->{arraystart + vertcount} to {alpha}");
                for (int index = arraystart; index < arraystart + vertcount; index++)
                {
                    VertexPositionColor vpc = VertList[(int)index];
                    vpc.ActiveAnimAlpha = alpha;
                    VertList[(int)index] = vpc;

                }

                DataChanged = true;
            }
        }

        public void ReduceEdgeAnimAlpha(int arraystart, int vertcount, float alpha)
        {
            lock (ListLock) //todo, should be a read lock
            {
                bool done = false;
                float highestAlpha = -1;
                Console.WriteLine($"Setting alpha of edge verts {arraystart}->{arraystart + vertcount} to {alpha}");
                for (int index = arraystart; index < arraystart + vertcount; index++)
                {
                    VertexPositionColor vpc = VertList[(int)index];
                    vpc.ActiveAnimAlpha = Math.Max(vpc.ActiveAnimAlpha - alpha, GlobalConfig.AnimatedFadeMinimumAlpha);
                    VertList[(int)index] = vpc;
                    if (vpc.ActiveAnimAlpha > highestAlpha) highestAlpha = vpc.ActiveAnimAlpha;
                    if (vpc.ActiveAnimAlpha <= GlobalConfig.AnimatedFadeMinimumAlpha) done = true;
                }
                Debug.Assert(!done || highestAlpha <= GlobalConfig.AnimatedFadeMinimumAlpha);
                DataChanged = true;
            }
        }

        public int safe_add_vert(VertexPositionColor input)
        {
            int newsize = 0;
            lock (ListLock) //todo, should be a read lock
            {
                VertList.Add(input);
                DataChanged = true;
                newsize = VertList.Count;
            }

            return newsize;
        }

        public int safe_add_verts(List<VertexPositionColor> input)
        {
            int oldSize = VertList.Count;
            lock (ListLock) //todo, should be a read lock
            {
                VertList.AddRange(input);
                DataChanged = true;
            }

            return oldSize;
        }


        public bool safe_get_vert_array(out VertexPositionColor[] result)
        {
            lock (ListLock) //todo, should be a read lock
            {
                result = VertList.ToArray();
            }

            return true;
        }


        public bool safe_get_vert_list(out List<VertexPositionColor> result)
        {
            lock (ListLock) //todo, should be a read lock
            {
                result = VertList.Select(n => n).ToList();
            }

            return true;
        }


        public List<VertexPositionColor> acquire_vert_write(int holder = 0)
        {
            //poslock_.lock () ;
            return VertList;
        }

        public void MarkDataChanged()
        {
            DataChanged = true;
        }

        public void inc_edgesRendered() { ++CountRenderedEdges; }
        public uint CountRenderedEdges { get; private set; } = 0;
        public void drawShortLinePoints(Vector3 startC, Vector3 endC, WritableRgbaFloat colour, float alpha, out int arraypos)
        {

            VertexPositionColor vert = new VertexPositionColor()
            {
                Position = startC,
                Color = colour,
                ActiveAnimAlpha = alpha
            };


            arraypos = safe_add_vert(vert);
            vert.Position = endC;
            arraypos = safe_add_vert(vert);


        }

        public int drawLongCurvePoints(Vector3 bezierC, Vector3 startC, Vector3 endC, WritableRgbaFloat colour, eEdgeNodeType edgeType, out int arraypos)
        {
            float[] fadeArray = { 0.4f, 0.4f, 0.5f, 0.5f, 0.7f, 0.7f, 0.6f, 0.8f, 0.8f, 0.7f, 0.9f, 0.9f, 0.9f, 0.7f, 1, 1, 1 };

            int curvePoints = GL_Constants.LONGCURVEPTS + 2;
            List<VertexPositionColor> newVerts = new List<VertexPositionColor>();


            VertexPositionColor startVert = new VertexPositionColor()
            {
                Position = startC,
                Color = colour,
                ActiveAnimAlpha = GlobalConfig.AnimatedFadeMinimumAlpha
            };


            newVerts.Add(startVert);

            // > for smoother lines, less performance
            int dt;
            float fadeA = (float)240;

            int segments = curvePoints / 2;
            for (dt = 1; dt < segments + 1; ++dt)
            {
                fadeA = fadeArray[dt - 1] * 255.0f;
                if (fadeA > 1) fadeA = 1;


                colour.A = fadeA;
                VertexPositionColor nextVert = new VertexPositionColor()
                {
                    Position = GraphicsMaths.bezierPT(startC, bezierC, endC, dt, segments),
                    Color = colour,
                    ActiveAnimAlpha = GlobalConfig.AnimatedFadeMinimumAlpha
                };

                newVerts.Add(nextVert);

                //start new line at same point  
                //todo: use indexing to avoid this

                newVerts.Add(nextVert);
            }

            colour.A = (float)255;
            VertexPositionColor lastVert = new VertexPositionColor()
            {
                Position = endC,
                Color = colour,
                ActiveAnimAlpha = GlobalConfig.AnimatedFadeMinimumAlpha
            };
            newVerts.Add(lastVert);

            arraypos = safe_add_verts(newVerts);


            return curvePoints + 2;
        }

        //This is only for using by the highlight lines, usually better to simply replace the whole thing
        public void Clear()
        {
            VertList.Clear();
            NodeCount = 0;
            CountRenderedEdges = 0;
            Edges_VertSizes_ArrayPositions.Clear();
        }

        public struct PLOT_TRACK
        {
            uint _lastVertID;
            public uint lastVertID
            {
                get => _lastVertID;
                set
                {
                    _lastVertID = value;
                    changed = true;
                }
            }
            public bool changed { get; private set; }
            public void ResetChanged() => changed = false;
            public eEdgeNodeType lastVertType;
        };

        public void GetEdgeDrawData(int EdgeIndex, out int vertcount, out int arraypos)
        {
            Debug.Assert(EdgeIndex < Edges_VertSizes_ArrayPositions.Count);
            vertcount = Edges_VertSizes_ArrayPositions[EdgeIndex].Item1;
            arraypos = Edges_VertSizes_ArrayPositions[EdgeIndex].Item2;
        }

        public void SignalDataRead() { DataChanged = false; } //todo race condition possible here
        public bool DataChanged { get; private set; } = false;
        public bool IsPreview { get; private set; } = false;


        private readonly object coordLock = new object();
        public bool get_node_coord<T>(int nodeidx, out T result)
        {
            lock (coordLock)
            {
                if (nodeidx < node_coords.Count)
                {
                    result = (T)node_coords[nodeidx];
                    return true;
                }
            }

            result = default(T);
            return false;
        }

        public void add_node_coord<T>(T coord)
        {
            lock (coordLock)
            {
                Console.WriteLine($"Adding node coord {node_coords.Count}");
                node_coords.Add(coord);
                NodeCount = node_coords.Count;
            }
        }

        public void SetNodeCoord<T>(uint nodeIdx, T plotCoord, Vector3 XYZCoord)
        {
            lock (coordLock)
            {
                Debug.Assert(nodeIdx < node_coords.Count);
                node_coords[(int)nodeIdx] = plotCoord;
                VertexPositionColor oldvpc = VertList[(int)nodeIdx];
                oldvpc.Position = XYZCoord;
                VertList[(int)nodeIdx] = oldvpc;
                DataChanged = true;
            }
        }


    }
}
