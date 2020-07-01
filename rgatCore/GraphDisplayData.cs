using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Numerics;
using System.Text;
/*
This class holds (and provides dubiously mutex guarded access to) OpenGl vertex and colour data
*/
namespace rgatCore
{
    class GraphDisplayData
    {

        public GraphDisplayData(bool preview = false) => IsPreview = preview;

        ~GraphDisplayData()
        {
            //acquire_pos_write();vector
            //acquire_col_write();
        }


        public List<float> acquire_pos_read(int holder = 0)
        {
            //poslock_.lock_shared();
            return vposarray;
        }

        public List<float> acquire_col_read()
        {
            //collock_.lock_shared();
            return vcolarray;
        }
        public List<float> acquire_pos_write(int holder = 0)
        {
            //poslock_.lock () ;
            return vposarray;
        }
        public List<float> acquire_col_write()
        {
            //collock_.lock();
            return vcolarray;
        }

        List<float> readonly_col() { if (vcolarray.Count > 0) return vcolarray; return null; }
        List<float> readonly_pos() { if (vposarray.Count > 0) return vposarray; return null; }

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

        int col_sizec() { return vcolarray.Count; }

        public void set_numVerts(int num)
        {
            Debug.Assert(num >= CountVerts);
            CountVerts = num;
            vcolarraySize = (ulong)vcolarray.Count;
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

        public int CountVerts { private set; get; } = 0;
        public int CountLoadedVerts = 0;

        List<float> vposarray = new List<float>();
        List<float> vcolarray = new List<float>();
        public ulong vcolarraySize { get; private set; } = 0;

        //not used for nodes
        public uint CountRenderedEdges { get; private set; } = 0;
        public bool IsPreview { get; private set; } = false;
    }
}
