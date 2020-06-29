using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{
    class CylinderGraph : PlottedGraph
    {
		const int DEFAULT_PIX_PER_A_COORD = 80;
		const int DEFAULT_PIX_PER_B_COORD = 120;
		const int PREVIEW_PIX_PER_A_COORD = 3;
		const int PREVIEW_PIX_PER_B_COORD = 4;

		public CylinderGraph(ProtoGraph baseProtoGraph) : base(baseProtoGraph)//, vector<QColor>* coloursPtr)
		{
			layout = graphLayouts.eCylinderLayout;
		}

		/*
		void maintain_draw_wireframe(graphGLWidget &gltarget);
		void plot_wireframe(graphGLWidget &gltarget);

		void performMainGraphDrawing(graphGLWidget &gltarget);
		void render_static_graph();
		bool render_edge(NODEPAIR ePair, GraphDisplayData* edgedata, QColor* colourOverride, bool preview, bool noUpdate);

		void drawHighlight(NODEINDEX nodeIndex, GRAPH_SCALE* scale, QColor &colour, int lengthModifier, graphGLWidget &gltarget);
		void drawHighlight(GENERIC_COORD& graphCoord, GRAPH_SCALE* scale, QColor &colour, int lengthModifier, graphGLWidget &gltarget);

		bool get_visible_node_pos(NODEINDEX nidx, DCOORD* screenPos, SCREEN_QUERY_PTRS* screenInfo, graphGLWidget &gltarget);

		pair<void*, float> get_diffgraph_nodes() { return make_pair(&node_coords, maxB); }
		void set_diffgraph_nodes(pair<void*, float> diffData) { node_coords = (vector<CYLINDERCOORD>*)diffData.first; maxB = diffData.second; }
		uint get_graph_size() { return main_scalefactors.plotSize; };

		void orient_to_user_view();
		*/
		public void InitialiseDefaultDimensions()
        {
			wireframeSupported = true;
			wireframeActive = true;

			preview_scalefactors.plotSize = 600;
			preview_scalefactors.basePlotSize = 600;
			preview_scalefactors.pix_per_A = PREVIEW_PIX_PER_A_COORD;
			preview_scalefactors.pix_per_B = PREVIEW_PIX_PER_B_COORD;

			main_scalefactors.plotSize = 20000;
			main_scalefactors.basePlotSize = 20000;
			main_scalefactors.userSizeModifier = 1;
			main_scalefactors.pix_per_A = DEFAULT_PIX_PER_A_COORD;
			main_scalefactors.original_pix_per_A = DEFAULT_PIX_PER_A_COORD;
			main_scalefactors.pix_per_B = DEFAULT_PIX_PER_B_COORD;
			main_scalefactors.original_pix_per_B = DEFAULT_PIX_PER_B_COORD;

			view_shift_x = 96;
			view_shift_y = 65;
			cameraZoomlevel = 60000;
		}
		/*
		void initialiseCustomDimensions(GRAPH_SCALE scale);

		void setWireframeActive(int mode);

		float previewZoom() { return -2550; }
		int prevScrollYPosition() { return -250; }

		int getNearestNode(QPoint screenPos, graphGLWidget &gltarget, node_data** node);

		protected:
	void render_node(node_data* n, PLOT_TRACK* lastNode, GraphDisplayData* vertdata, GraphDisplayData* animvertdata,
		GRAPH_SCALE* dimensions);
		FCOORD nodeIndexToXYZ(NODEINDEX index, GRAPH_SCALE* dimensions, float diamModifier);

		private:
	void initialise();
		int needed_wireframe_loops();
		void draw_wireframe(graphGLWidget &gltarget);
		void regenerate_wireframe_if_needed();
		void regen_wireframe_buffers(graphGLWidget &gltarget);

		void display_graph(PROJECTDATA* pd, graphGLWidget &gltarget);
		int drawCurve(GraphDisplayData* linedata, FCOORD &startC, FCOORD &endC,
			QColor &colour, int edgeType, GRAPH_SCALE* dimensions, long* arraypos);
		void write_rising_externs(PROJECTDATA* pd, graphGLWidget &gltarget);

		void positionVert(void* positionStruct, node_data* n, PLOT_TRACK* lastNode);
		CYLINDERCOORD* get_node_coord(NODEINDEX idx);
		bool get_screen_pos(NODEINDEX nodeIndex, GraphDisplayData* vdata, PROJECTDATA* pd, DCOORD* screenPos);
		bool a_coord_on_screen(int a, float hedgesep);
		void cylinderCoord(CYLINDERCOORD* sc, FCOORD* c, GRAPH_SCALE* dimensions, float diamModifier = 0);
		void cylinderCoord(float a, float b, FCOORD* c, GRAPH_SCALE* dimensions, float diamModifier);
		void getCylinderCoordAB(FCOORD &c, GRAPH_SCALE* dimensions, float* a, float* b);
		void getCylinderCoordAB(DCOORD &c, GRAPH_SCALE* dimensions, float* a, float* b);

		void add_to_callstack(bool isPreview, MEM_ADDRESS address, NODEINDEX idx);

		private:
	int wireframe_loop_count = 0;
		GraphDisplayData* wireframe_data = NULL;
		GLuint wireframeVBOs[2];
		bool staleWireframe = false;
		bool wireframeBuffersCreated = false;
		vector<GLint> wireframeStarts, wireframeSizes;

		vector<CYLINDERCOORD> node_coords_storage;
		vector<CYLINDERCOORD>* node_coords = &node_coords_storage;

		//these are the edges/nodes that are brightend in the animation
		map<NODEPAIR, edge_data*> activeEdgeMap;
		//<index, final (still active) node>
		map<NODEINDEX, bool> activeNodeMap;
		*/
	}
}
