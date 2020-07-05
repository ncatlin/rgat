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


        public List<VertexPositionColor> acquire_vert_read()
        {
            //collock_.lock_shared();
            return VertList;
        }
        public List<VertexPositionColor> acquire_vert_write(int holder = 0)
        {
            //poslock_.lock () ;
            return VertList;
        }


        List<VertexPositionColor> readonly_col() { if (VertList.Count > 0) return VertList; return null; }

        public void release_pos_write()
        {
            //poslock_.unlock();
        }
        public void release_pos_read()
        {
            //poslock_.unlock_shared();
        }

        public void release_col_write()
        {
            //collock_.unlock();
        }
        public void release_col_read()
        {
            //collock_.unlock_shared();
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

        //uint get_renderedEdges() { return edgesRendered; }
        public void inc_edgesRendered() { ++CountRenderedEdges; }


        public void drawShortLinePoints(Vector3 startC, Vector3 endC, Color colour, out int arraypos)
        {
            arraypos = 0;
            Console.WriteLine("todo drawShortLinePoints");
        }

        public int drawLongCurvePoints(Vector3 bezierC, Vector3 startC, Vector3 endC, Color colour, eEdgeNodeType edgeType, out int colarraypos)
        {
            Console.WriteLine("todo drawLongCurvePoints");
            colarraypos = 0;
            return 0;
        }

        //bool get_coord(NODEINDEX index, FCOORD* result);




        //mutable std::shared_mutex poslock_;
        //mutable std::shared_mutex collock_;

        public int CountVerts() => VertList.Count;

        public List<VertexPositionColor> VertList = new List<VertexPositionColor>();

        public ulong vcolarraySize { get; private set; } = 0;

        //not used for nodes
        public uint CountRenderedEdges { get; private set; } = 0;
        public bool IsPreview { get; private set; } = false;
    }
}
