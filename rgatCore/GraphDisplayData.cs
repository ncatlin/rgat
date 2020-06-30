using System;
using System.Collections.Generic;
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

		/*
			List<float>* acquire_pos_read(int holder = 0);
			List<float>* acquire_col_read();
			List<float>* acquire_pos_write(int holder = 0);
			List<float>* acquire_col_write();

			float* readonly_col() { if (!vcolarray.empty()) return &vcolarray.at(0); return 0; }
			float* readonly_pos() { if (!vposarray.empty()) return &vposarray.at(0); return 0; }

			void release_pos_write();
			void release_pos_read();
			void release_col_write();
			void release_col_read();

			void clear();
			void reset();
			size_t col_sizec() { return vcolarray.size(); }
			//this is actually quite slow? or at least is a significant % of reported cpu time
			uint col_buf_capacity_floats() { return vcolarraySize; }
			GLsizei get_numVerts() { return numVerts; }
			GLsizei get_numLoadedVerts() { return loadedVerts; }
			void set_numLoadedVerts(GLsizei qty) { loadedVerts = qty; }
			void set_numVerts(GLsizei num);
				*/
		//uint get_renderedEdges() { return edgesRendered; }
			public void inc_edgesRendered() { ++CountRenderedEdges; }

		/*
			void drawShortLinePoints(FCOORD &startC, FCOORD &endC, QColor &colour, long* arraypos);
			int drawLongCurvePoints(FCOORD &bezierC, FCOORD &startC, FCOORD &endC, QColor &colour, int edgeType, long* colarraypos);

			bool get_coord(NODEINDEX index, FCOORD* result);
				
		*/


		//mutable std::shared_mutex poslock_;
		//mutable std::shared_mutex collock_;

		public int CountVerts { private set; get; } = 0;
        ulong loadedVerts = 0;

        //List<float> vposarray;
        //List<float> vcolarray;
        ulong vcolarraySize = 0;

        //not used for nodes
        public uint CountRenderedEdges { get; private set; } = 0;
        public bool IsPreview { get; private set; } = false;
    }
}
