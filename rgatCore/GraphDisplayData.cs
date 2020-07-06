﻿using System;
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
            R = col.R;
            G = col.G;
            B = col.B;
            A = col.A;
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


        public void drawShortLinePoints(Vector3 startC, Vector3 endC, WritableRgbaFloat colour, out int arraypos)
        {

            List<VertexPositionColor> vertposlist = acquire_vert_write();

            arraypos = vertposlist.Count;

            VertexPositionColor vert = new VertexPositionColor()
            {
                Position = startC,
                Color = colour
            };
            vertposlist.Add(vert);
            vert.Position = endC;
            vertposlist.Add(vert);
        }

        public int drawLongCurvePoints(Vector3 bezierC, Vector3 startC, Vector3 endC, WritableRgbaFloat colour, eEdgeNodeType edgeType, out int arraypos)
        {
            float[] fadeArray = { 0.4f, 0.4f, 0.5f, 0.5f, 0.7f, 0.7f, 0.6f, 0.8f, 0.8f, 0.7f, 0.9f, 0.9f, 0.9f, 0.7f, 1, 1, 1 };

            int curvePoints = GL_Constants.LONGCURVEPTS + 2;
            List<VertexPositionColor> vertposlist = acquire_vert_write();

            if (vertposlist == null)
            {
                Console.WriteLine("drawLongCurvePoints Error, failed to acquire vert lock");
                arraypos = 0;
                return 0;
            }
            arraypos = vertposlist.Count;

            VertexPositionColor startVert = new VertexPositionColor() {
                Position = startC,
                Color = colour
            };


            vertposlist.Add(startVert);

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

                vertposlist.Add(nextVert);

                //start new line at same point  
                //todo: use indexing to avoid this

                vertposlist.Add(nextVert);
            }

            colour.A = (float)255;
            VertexPositionColor lastVert = new VertexPositionColor()
            {
                Position = endC,
                Color = colour
            };
            vertposlist.Add(lastVert);
            release_col_write();
            release_pos_write();

            return curvePoints + 2;
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