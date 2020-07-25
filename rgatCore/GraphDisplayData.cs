using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
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
            R = (float)col.R/255f;
            G = (float)col.G/255f;
            B = (float)col.B/255f;
            A = (float)col.A/255f;
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
        public float R { get; set; }
        public float G { get; set; }
        public float B { get; set; }
        public float A { get; set; }

    }
    struct VertexPositionColor
    {
        public const uint SizeInBytes = 28;
        public Vector3 Position;
        public WritableRgbaFloat Color;
        
        public VertexPositionColor(Vector3 position, WritableRgbaFloat color)
        {
            Position = position;
            Color = color;
        }
        public void SetAlpha(float alpha) => Color.A = alpha;
        public VertexPositionColor(Vector3 position, Veldrid.RgbaFloat color)
        {
            Position = position;
            Color = new WritableRgbaFloat()
            {
                A = color.A,
                B = color.B,
                G = color.G,
                R = color.R
            };
        }
    }

    class GraphDisplayData
    {

        public GraphDisplayData(bool preview = false) => IsPreview = preview;

        ~GraphDisplayData()
        {
            //acquire_pos_write();vector
            //acquire_col_write();
        }

        private readonly object ListLock = new object();

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
            int newsize = 0;
            lock (ListLock) //todo, should be a read lock
            {
                VertList.AddRange(input);
                DataChanged = true;
                newsize = VertList.Count;
            }

            return newsize;
        }


        public bool safe_get_vert_array(out VertexPositionColor[] result)
        {
            lock (ListLock) //todo, should be a read lock
            {
                result = VertList.ToArray();
            }

            return true;
        }


        public List<VertexPositionColor> acquire_vert_write(int holder = 0)
        {
            //poslock_.lock () ;
            return VertList;
        }


        List<VertexPositionColor> readonly_col() { if (VertList.Count > 0) return VertList; return null; }

        public void release_vert_write()
        {
            DataChanged = true;
            //poslock_.unlock();
        }
        public void release_vert_read()
        {
            //poslock_.unlock_shared();
        }


        void reset()
        {
            /*
			acquire_pos_write(342);
			acquire_col_write();
			//needed? try without
			vposarray.clear();
			vcolarray.clear();
			numVerts = 0;
			edgesRendered = 0;
			release_col_write();
			release_pos_write();
			*/
        }

        public void inc_edgesRendered() { ++CountRenderedEdges; }
        public uint CountRenderedEdges { get; private set; } = 0;
        public void drawShortLinePoints(Vector3 startC, Vector3 endC, WritableRgbaFloat colour, out int arraypos)
        {

            VertexPositionColor vert = new VertexPositionColor()
            {
                Position = startC,
                Color = colour
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


            VertexPositionColor startVert = new VertexPositionColor() {
                Position = startC,
                Color = colour
            };


            newVerts.Add(startVert);

            // > for smoother lines, less performance
            int dt;
            float fadeA = (float)240;

            int segments = curvePoints / 2;
            for (dt = 1; dt < segments + 1; ++dt)
            {
                fadeA = fadeArray[dt - 1]*255.0f;
                if (fadeA > 1) fadeA = 1;


                colour.A = fadeA;
                VertexPositionColor nextVert = new VertexPositionColor()
                {
                    Position = GraphicsMaths.bezierPT(startC, bezierC, endC, dt, segments),
                    Color = colour
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
                Color = colour
            };
            newVerts.Add(lastVert);

            arraypos = safe_add_verts(newVerts);


            return curvePoints + 2;
        }

        //bool get_coord(NODEINDEX index, FCOORD* result);




        //mutable std::shared_mutex poslock_;
        //mutable std::shared_mutex collock_;

        public int CountVerts() => VertList.Count;

        public List<VertexPositionColor> VertList = new List<VertexPositionColor>();

        public ulong vcolarraySize { get; private set; } = 0;

        public void SignalDataRead() { DataChanged = false; } //todo race condition possible here
        public bool DataChanged { get; private set; } = false;
        public bool IsPreview { get; private set; } = false;

        //keep track of which a,b coords are occupied - may need to be unique to each plot
        public Dictionary<Tuple<float, float>, bool> usedCoords = new Dictionary<Tuple<float, float>, bool>();
    }
}
