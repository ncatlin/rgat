#include "stdafx.h"
#include "basicblock_handler.h"
#include "trace_handler.h"
#include "render_preview_thread.h"
#include "traceStructs.h"
#include "traceMisc.h"
#include "module_handler.h"
#include "render_heatmap_thread.h"
#include "render_conditional_thread.h"
#include "GUIManagement.h"
#include "rendering.h"
#include "b64.h"
#include "preview_pane.h"
#include "serialise.h"
#include "diff_plotter.h"
#include "timeline.h"
#include "OSspecific.h"
#include "clientConfig.h"

//possible name: rgat
//ridiculous/runtime graph analysis tool
//run rgat -f malware.exe

#pragma comment(lib, "glu32.lib")
#pragma comment(lib, "OpenGL32.lib")

int handle_event(ALLEGRO_EVENT *ev, VISSTATE *clientstate);


void launch_saved_PID_threads(int PID, PROCESS_DATA *piddata, VISSTATE *clientState)
{
	DWORD threadID;
	preview_renderer *previews_thread = new preview_renderer;
	previews_thread->clientState = clientState;
	previews_thread->PID = PID;
	previews_thread->piddata = piddata;

	HANDLE hOutThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)previews_thread->ThreadEntry,
		(LPVOID)previews_thread, 0, &threadID);

	heatmap_renderer *heatmap_thread = new heatmap_renderer;
	heatmap_thread->clientState = clientState;
	heatmap_thread->piddata = piddata;

	HANDLE hHeatThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)heatmap_thread->ThreadEntry,
		(LPVOID)heatmap_thread, 0, &threadID);

	conditional_renderer *conditional_thread = new conditional_renderer;
	conditional_thread->clientState = clientState;
	conditional_thread->piddata = piddata;

	Sleep(200);
	HANDLE hConditionThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)conditional_thread->ThreadEntry,
		(LPVOID)conditional_thread, 0, &threadID);

}
//todo: make this a thread/mainloop check that listens for new processes
void launch_new_process_threads(int PID, std::map<int, PROCESS_DATA *> *glob_piddata_map, HANDLE pidmutex, VISSTATE *clientState) {
	PROCESS_DATA *piddata = new PROCESS_DATA;
	piddata->PID = PID;

	if (!obtainMutex(pidmutex, "Launch PID threads", 1000)) return;
	glob_piddata_map->insert_or_assign(PID, piddata);
	dropMutex(pidmutex, "Launch PID threads");

	DWORD threadID;

	//handles new threads for process
	module_handler *tPIDThread = new module_handler;
	tPIDThread->clientState = clientState;
	tPIDThread->PID = PID;
	tPIDThread->piddata = piddata;

	HANDLE hPIDmodThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)tPIDThread->ThreadEntry,
		(LPVOID)tPIDThread, 0, &threadID);

	//handles new disassembly data
	basicblock_handler *tBBThread = new basicblock_handler;
	tBBThread->clientState = clientState;
	tBBThread->PID = PID;
	tBBThread->piddata = piddata;

	HANDLE hPIDBBThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)tBBThread->ThreadEntry,
		(LPVOID)tBBThread, 0, &threadID);

	//renders threads for preview pane
	preview_renderer *render_preview_thread = new preview_renderer;
	render_preview_thread->clientState = clientState;
	render_preview_thread->PID = PID;
	render_preview_thread->piddata = piddata;

	HANDLE hPreviewThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)render_preview_thread->ThreadEntry,
		(LPVOID)render_preview_thread, 0, &threadID);
	
	//renders heatmaps
	heatmap_renderer *heatmap_thread = new heatmap_renderer;
	heatmap_thread->clientState = clientState;
	heatmap_thread->piddata = piddata;
	heatmap_thread->setUpdateDelay(clientState->config->heatmap.delay);

	HANDLE hHeatThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)heatmap_thread->ThreadEntry,
		(LPVOID)heatmap_thread, 0, &threadID);
	
	//renders conditionals
	conditional_renderer *conditional_thread = new conditional_renderer;
	conditional_thread->clientState = clientState;
	conditional_thread->piddata = piddata;
	conditional_thread->setUpdateDelay(clientState->config->conditional.delay);

	Sleep(200);
	HANDLE hConditionThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)conditional_thread->ThreadEntry,
		(LPVOID)conditional_thread, 0, &threadID);

}



int GUI_init(ALLEGRO_EVENT_QUEUE ** evq, ALLEGRO_DISPLAY **newDisplay) {
	
	*newDisplay = displaySetup();
	if (!*newDisplay) {
		printf("Display creation failed: returned %x\n", (int)newDisplay);
		return 0;
	}

	if (!controlSetup()) {
		printf("Control setup failed\n");
		return 0;
	}

	*evq = al_create_event_queue();
	al_register_event_source(*evq, (ALLEGRO_EVENT_SOURCE*)al_get_mouse_event_source());
	al_register_event_source(*evq, (ALLEGRO_EVENT_SOURCE*)al_get_keyboard_event_source());
	al_register_event_source(*evq, create_menu(*newDisplay));
	al_register_event_source(*evq, al_get_display_event_source(*newDisplay));
	return 1;
}



int process_coordinator_thread(VISSTATE *clientState) {
	
	//todo: posibly worry about pre-existing if pidthreads dont work
	HANDLE hPipe = CreateNamedPipe(L"\\\\.\\pipe\\BootstrapPipe",
		PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_WAIT,
		255, 65536, 65536, 300, NULL);

	if (hPipe == INVALID_HANDLE_VALUE)
	{
		_tprintf(TEXT("CreateNamedPipe failed, GLE=%d.\n"), GetLastError());
		return -1;
	}

	
	printf("In process coordinator thread, listening on pipe...\n");
	DWORD bread = 0;
	char buf[40];
	while (true)
	{
		int conresult = ConnectNamedPipe(hPipe, NULL);
		printf("boostrap conresult : %d\n", conresult);
		ReadFile(hPipe, buf, 30, &bread, NULL);
		DisconnectNamedPipe(hPipe);
		if (!bread) {
			printf("Read 0 when waiting for PID. Try again\n");
			continue;
		}
		buf[bread] = 0;
		printf("process_coordinator thread read: [%s]\n", buf);

		int PID = 0;
		if (!extract_integer(buf, string("PID"), &PID))
		{
			//todo: fail here soemtimes
			printf("ERROR: Something bad happen in extract_integer, string is: %s\n", buf);
			return -1;
		}

		clientState->timelineBuilder->notify_new_pid(PID);
		launch_new_process_threads(PID, &clientState->glob_piddata_map, clientState->pidMapMutex, clientState);
	}
}

void updateMainRender(VISSTATE *clientState)
{
	render_main_graph(clientState);

	//todo: change to on size change?
	if (clientState->wireframe_sphere)
		delete clientState->wireframe_sphere;

	clientState->wireframe_sphere = new GRAPH_DISPLAY_DATA(WFCOLBUFSIZE * 2);
	plot_wireframe(clientState);

	plot_colourpick_sphere(clientState);
	updateTitle_NumPrimitives(clientState->maindisplay, clientState, clientState->activeGraph->get_mainnodes()->get_numVerts(),
		clientState->activeGraph->get_mainlines()->get_renderedEdges());
	clientState->rescale = false;

}


void change_mode(VISSTATE *clientState, int mode)
{
	switch (mode)
	{
	case EV_BTN_WIREFRAME:
		clientState->modes.wireframe = !clientState->modes.wireframe;
		//todo: change icon
		return;

	case EV_BTN_CONDITION:
		
		clientState->modes.conditional = !clientState->modes.conditional;
		if (clientState->modes.conditional)
		{
			clientState->modes.nodes = true;
			clientState->modes.heatmap = false;
		}
		//todo: change icon
		return;

	case EV_BTN_HEATMAP:

		clientState->modes.heatmap = !clientState->modes.heatmap;
		clientState->modes.nodes = !clientState->modes.heatmap;
		if (clientState->modes.heatmap) clientState->modes.conditional = false;
		//todo: change icon
		return;

	case EV_BTN_PREVIEW:
		{
			al_destroy_bitmap(clientState->mainGraphBMP);
			clientState->modes.preview = !clientState->modes.preview;

			TraceVisGUI *widgets = (TraceVisGUI *)clientState->widgets;
			if (clientState->modes.preview)
			{
				widgets->setScrollbarVisible(true);
				clientState->mainGraphBMP = al_create_bitmap(clientState->size.width - PREVIEW_PANE_WIDTH, clientState->size.height);
			}
			else
			{
				widgets->setScrollbarVisible(false);
				clientState->mainGraphBMP = al_create_bitmap(clientState->size.width, clientState->size.height);
			}

			return;
		}
	case EV_BTN_DIFF:
		clientState->modes.heatmap = false;
		clientState->modes.conditional = false;
		return;

	case EV_BTN_NODES:
		clientState->modes.nodes = !clientState->modes.nodes;
		return;

	case EV_BTN_EDGES:
		clientState->modes.edges = !clientState->modes.edges;
		return;

	}

}

void processDiff(VISSTATE *clientState, ALLEGRO_FONT *font, diff_plotter **diffRenderer)
{
	if (clientState->modes.diff == DIFF_STARTED) 
		display_graph_diff(clientState, *diffRenderer);
	else if (clientState->modes.diff == DIFF_SELECTED)//diff button clicked
	{
		change_mode(clientState, EV_BTN_DIFF);
		clientState->modes.diff = DIFF_STARTED;
		TraceVisGUI *widgets = (TraceVisGUI *)clientState->widgets;
		widgets->showHideDiffFrame();

		thread_graph_data *graph1 = widgets->diffWindow->get_graph(1);
		thread_graph_data *graph2 = widgets->diffWindow->get_graph(2);
		*diffRenderer = new diff_plotter(graph1, graph2, clientState);
		((diff_plotter*)*diffRenderer)->render();
	}

	((diff_plotter*)*diffRenderer)->display_diff_summary(20, 10, font, clientState);
}

struct EXTTEXT{
	NODEPAIR edge;
	int nodeIdx;
	float timeRemaining;
	float yOffset;
	string displayString;
} ;

string generate_funcArg_string(thread_graph_data *graph, int nodeIdx, ARGLIST args, PROCESS_DATA* piddata)
{
	stringstream funcArgStr;
	funcArgStr << graph->get_node_sym(nodeIdx, piddata) << "(";

	int numargs = args.size();
	for (int i = 0; i < numargs; ++i)
	{
		funcArgStr << args[i].first << ": " << args[i].second;
		if (i < numargs - 1)
			funcArgStr << ", ";
	}
	funcArgStr << ")";
	return funcArgStr.str();
}

void transferNewLiveCalls(thread_graph_data *graph, map <int, vector<EXTTEXT>> *externFloatingText, PROCESS_DATA* piddata)
{
	while (!graph->funcQueue.empty())
	{
		obtainMutex(graph->funcQueueMutex, "FuncQueue Pop", INFINITE);
		EXTERNCALLDATA resu = graph->funcQueue.front();
		graph->funcQueue.pop();

		EXTTEXT extt;
		extt.edge = resu.edgeIdx;
		extt.nodeIdx = resu.nodeIdx;
		extt.timeRemaining = 5;
		extt.yOffset = 0;
		extt.displayString = generate_funcArg_string(graph, extt.nodeIdx, resu.fdata, piddata);

		if (resu.edgeIdx.first == resu.edgeIdx.second) { printf("WARNING: bad argument edge!\n"); continue; }

		if (graph->active )
		{
			if (!resu.callerAddr)
			{
				node_data* parentn = graph->get_node(resu.edgeIdx.first);
				node_data* externn = graph->get_node(resu.edgeIdx.second);
				resu.callerAddr = parentn->ins->address;
				resu.externPath = piddata->modpaths[externn->nodeMod];
				if (extt.displayString == "()")
				{
					stringstream hexaddr;
					hexaddr << "NOSYM:<0x" << std::hex << externn->address << ">";
					extt.displayString = hexaddr.str();
				}
			}
			stringstream callLog;
			callLog << "0x" << std::hex << resu.callerAddr << ": ";
			callLog << resu.externPath << " -> ";
			callLog << extt.displayString << "\n";
			graph->loggedCalls.push_back(callLog.str());	
		}

		graph->set_edge_alpha(resu.edgeIdx, graph->get_activelines(), 1.0);
		graph->set_node_alpha(resu.nodeIdx, graph->get_activenodes(), 1.0);
		dropMutex(graph->funcQueueMutex, "FuncQueue Pop");
		externFloatingText->at(graph->tid).push_back(extt);
	}
}

void drawExternTexts(thread_graph_data *graph, map <int, vector<EXTTEXT>> *externFloatingText, VISSTATE *clientState, PROJECTDATA *pd)
{
	if (externFloatingText->at(graph->tid).empty()) return;

	vector <EXTTEXT>::iterator exttIt = externFloatingText->at(graph->tid).begin();
	map <EXTTEXT*, int> drawMap;
	map <int, EXTTEXT*> drawnNodes;
	for (; exttIt != externFloatingText->at(graph->tid).end(); )
	{
		if (exttIt->timeRemaining <= 0) 
		{
			graph->set_edge_alpha(exttIt->edge, graph->get_activelines(), 0.3);
			graph->set_node_alpha(exttIt->nodeIdx, graph->get_activenodes(), 0.3);
			exttIt = externFloatingText->at(graph->tid).erase(exttIt);
		}
		else
		{
			if (!drawnNodes.count(exttIt->nodeIdx))
			{
				EXTTEXT *exaddr = &*exttIt;
				drawMap[exaddr] = 1;
				drawnNodes[exttIt->nodeIdx] = exaddr;
			}
			exttIt->timeRemaining -= 1;
			exttIt->yOffset += 0.5;
			exttIt++;
		}
	}

	DCOORD pos;
	map <EXTTEXT*, int>::iterator drawIt = drawMap.begin();
	for (; drawIt != drawMap.end(); ++drawIt)
	{
		EXTTEXT* ex = drawIt->first;
		node_data *n = graph->get_node(ex->nodeIdx);
		if(!n->get_screen_pos(graph->get_mainnodes(), pd, &pos)) continue;
		string displayString = ex->displayString;
		al_draw_text(clientState->standardFont, al_col_green,
			pos.x, clientState->size.height - pos.y - ex->yOffset, 0, displayString.c_str());
	}
}

unsigned int fill_extern_log(ALLEGRO_TEXTLOG *textlog, thread_graph_data *graph, unsigned int logSize)
{
	vector <string>::iterator logIt = graph->loggedCalls.begin();
	advance(logIt, logSize);
	while (logIt != graph->loggedCalls.end())
	{
		al_append_native_text_log(textlog, logIt->c_str());
		logSize++;
		logIt++;
	}
	return logSize;
}

void closeTextLog(VISSTATE *clientState)
{
	al_close_native_text_log(clientState->textlog);
	clientState->textlog = 0;
	clientState->logSize = 0;
}

void performIrregularActions(VISSTATE *clientState)
{
	SCREEN_EDGE_PIX TBRG;
	//update where camera is pointing on sphere
	edge_picking_colours(clientState, &TBRG, true);
	clientState->leftcolumn = (int)floor(ADIVISIONS * TBRG.leftgreen) - 1;
	clientState->rightcolumn = (int)floor(ADIVISIONS * TBRG.rightgreen) - 1;

	//update highlight nodes
	if (clientState->highlightData.highlightState && clientState->activeGraph->active)
	{
		TraceVisGUI *widgets = (TraceVisGUI *)clientState->widgets;
		widgets->highlightWindow->updateHighlightNodes(&clientState->highlightData,
			clientState->activeGraph, clientState->activePid);
	}
}

void performMainGraphRendering(VISSTATE *clientState, map <int, vector<EXTTEXT>> *externFloatingText)
{
	TraceVisGUI* widgets = (TraceVisGUI*)clientState->widgets;
	thread_graph_data *graph = clientState->activeGraph;

	if (
		(graph->get_mainnodes()->get_numVerts() < graph->get_num_nodes()) ||
		(graph->get_mainlines()->get_renderedEdges() < graph->get_num_edges()) ||
		clientState->rescale)
	{
		updateMainRender(clientState);
	}
	
	if (!graph->active && clientState->animationUpdate)
	{
		int result = graph->updateAnimation(clientState->animationUpdate,
			clientState->modes.animation, clientState->skipLoop);
		if (clientState->skipLoop) clientState->skipLoop = false;

		if (clientState->modes.animation)
		{
			if (result == ANIMATION_ENDED)
			{
				graph->reset_animation();
				clientState->animationUpdate = 0;
				clientState->modes.animation = false;
				widgets->controlWindow->notifyAnimFinished();
			}
			else
				graph->update_animation_render(clientState->config->animationFadeRate);
		}
		else
			clientState->animationUpdate = 0;
	}
	
	drawHighlight(graph->get_active_node(), graph->m_scalefactors,&clientState->config->activityLineColour, 0);
	if (clientState->highlightData.highlightState)
		graph->highlightNodes(&clientState->highlightData.highlightNodes, 
			&clientState->config->highlightColour, clientState->config->highlightProtrusion);
	

	if (clientState->modes.heatmap) display_big_heatmap(clientState);
	else if (clientState->modes.conditional) display_big_conditional(clientState);
	else
	{
		if (graph->active)
		{
			if (clientState->modes.animation)
				graph->animate_latest(clientState->config->animationFadeRate);
		}
		else
			if (graph->terminated)
			{
				graph->reset_animation();
				clientState->modes.animation = false;
				graph->terminated = false;
				if (clientState->highlightData.highlightState)
					widgets->highlightWindow->updateHighlightNodes(&clientState->highlightData,
						clientState->activeGraph,
						clientState->activePid);
			}
			
		if (clientState->textlog && clientState->logSize < graph->loggedCalls.size())
			clientState->logSize = fill_extern_log(clientState->textlog,
				clientState->activeGraph, clientState->logSize);
		
		PROJECTDATA pd;
		gather_projection_data(&pd);
		display_graph(clientState, graph, &pd);

		transferNewLiveCalls(graph, externFloatingText, clientState->activePid);
		drawExternTexts(graph, externFloatingText, clientState, &pd);
	}
}

int main(int argc, char **argv)
{
	if (!al_init()) {
		fprintf(stderr, "Failed to initialise allegro!\n");
		return NULL;
	}

	ALLEGRO_DISPLAY *newDisplay = 0;
	ALLEGRO_EVENT_QUEUE *newQueue = 0;
	if (!GUI_init(&newQueue, &newDisplay)) {
		printf("GUI init failed - todo - nongraphical mode\n");
		return 0;
	}

	//first deal with any command line arguments
	VISSTATE clientstate;
	clientstate.event_queue = newQueue;
	clientstate.maindisplay = newDisplay;
	string moduleDir = getModulePath();
	string configPath = moduleDir + "\\rgat.cfg";

	clientstate.config = new clientConfig(configPath);
	clientConfig *config = clientstate.config;

	printf("Starting visualiser\n");



	clientstate.size.height = al_get_display_height(clientstate.maindisplay);
	clientstate.size.width = al_get_display_width(clientstate.maindisplay);
	clientstate.mainGraphBMP = al_create_bitmap(clientstate.size.width - PREVIEW_PANE_WIDTH, clientstate.size.height);

	clientstate.modes.wireframe = true;
	clientstate.activeGraph = 0;

	al_set_target_backbuffer(clientstate.maindisplay);

	TITLE windowtitle;
	clientstate.title = &windowtitle;

	updateTitle_Mouse(clientstate.maindisplay, &windowtitle, 0, 0);
	updateTitle_Zoom(clientstate.maindisplay, &windowtitle, clientstate.zoomlevel);

	bool buildComplete = false;

	//this is a pain in the neck to have, see wireframe code
	GLint *wireframeStarts = (GLint *)malloc(WIREFRAMELOOPS * sizeof(GLint));
	GLint *wireframeSizes = (GLint *)malloc(WIREFRAMELOOPS * sizeof(GLint));
	for (int i = 0; i < WIREFRAMELOOPS; ++i)
	{
		wireframeStarts[i] = i*WF_POINTSPERLINE;
		wireframeSizes[i] = WF_POINTSPERLINE;
	}

	int bufsize = 0;

	//setup frame limiter/fps clock
	double fps, fps_unlocked, frame_start_time;

	ALLEGRO_EVENT tev;
	ALLEGRO_TIMER *frametimer = al_create_timer(1.0 / 60.0);
	ALLEGRO_EVENT_QUEUE *frame_timer_queue = al_create_event_queue();
	al_register_event_source(frame_timer_queue, al_get_timer_event_source(frametimer));
	al_start_timer(frametimer);

	//edge_picking_colours() is a hefty call, but doesn't need calling often
	ALLEGRO_TIMER *updatetimer = al_create_timer(40.0 / 60.0);
	ALLEGRO_EVENT_QUEUE *low_frequency_timer_queue = al_create_event_queue();
	al_register_event_source(low_frequency_timer_queue, al_get_timer_event_source(updatetimer));
	al_start_timer(updatetimer);

	if (!frametimer || !updatetimer) printf("Failed timer creation\n");

	al_init_font_addon();
	al_init_ttf_addon();
	

	//todo: handle failure here
	stringstream fontPath_ss;
	fontPath_ss << moduleDir << "\\" << "VeraSe.ttf";
	string fontPath = fontPath_ss.str();
	clientstate.standardFont = al_load_ttf_font(fontPath.c_str(), 12, 0);
	ALLEGRO_FONT *PIDFont = al_load_ttf_font(fontPath.c_str(), 14, 0);
	if (!clientstate.standardFont) {
		fprintf(stderr, "Could not load font file %s\n", fontPath.c_str());
		return -1;
	}

	TraceVisGUI* widgets = new TraceVisGUI(&clientstate);
	clientstate.widgets = (void *)widgets;
	widgets->widgetSetup(fontPath);

	//preload glyphs in cache
	al_get_text_width(clientstate.standardFont, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890");
	al_get_text_width(PIDFont, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890");

	glEnableClientState(GL_VERTEX_ARRAY);
	glEnableClientState(GL_COLOR_ARRAY);

	clientstate.zoomlevel = 100000;
	clientstate.previewPaneBMP = al_create_bitmap(PREVIEW_PANE_WIDTH, clientstate.size.height);
	initial_gl_setup(&clientstate);

	//for rendering graph diff
	diff_plotter *diffRenderer;

	GRAPH_DISPLAY_DATA *vertsdata = NULL;
	GRAPH_DISPLAY_DATA *linedata = NULL;
	map<int, node_data>::iterator vertit;

	ALLEGRO_EVENT ev;
	int previewRenderFrame = 0;
	map <int, NODEPAIR> graphPositions;
	map <int, vector<EXTTEXT>> externFloatingText;

	HANDLE hProcessCoordinator = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)process_coordinator_thread,
		(LPVOID)&clientstate, 0, 0);

	clientstate.timelineBuilder = new timeline;
	
	ALLEGRO_COLOR mainBackground = clientstate.config->mainBackground;
	ALLEGRO_COLOR conditionalBackground = clientstate.config->conditional.background;

	bool running = true;
	while (running)
	{
		frame_start_time = al_get_time();

		//no active graph but a process exists
		//this is in the main loop so the GUI gets rendered at the start
		//todo set to own function when we OOP this
		if (!clientstate.activeGraph && clientstate.glob_piddata_map.size() > 0)
		{
			if (!obtainMutex(clientstate.pidMapMutex, "Main Loop",2000)) return 0;

			PROCESS_DATA *activePid = clientstate.glob_piddata_map.begin()->second;
			
			widgets->setActivePID(activePid->PID);
			clientstate.activePid = activePid;
			map<int, void *>::iterator graphIt;
			graphIt = activePid->graphs.begin();

			for (; graphIt != activePid->graphs.end(); ++graphIt)
			{
				thread_graph_data * graph = (thread_graph_data *)graphIt->second;
				if (!graph->get_num_edges()) continue;

				if (!graph->VBOsGenned)
					gen_graph_VBOs(graph);
				clientstate.activeGraph = graph;
				clientstate.modes.animation = true;
				clientstate.animationUpdate = 1;
				if (graph->active)
					widgets->controlWindow->setAnimState(ANIM_LIVE);
				else 
					widgets->controlWindow->setAnimState(ANIM_INACTIVE);
				
				if (!externFloatingText.count(graph->tid))
				{
					vector<EXTTEXT> newVec;
					externFloatingText[graph->tid] = newVec;
				}
				break;
			}
			dropMutex(clientstate.pidMapMutex, "Main Loop");
		}

		//active graph changed
		if (clientstate.newActiveGraph)
		{
			clientstate.activeGraph = (thread_graph_data *)clientstate.newActiveGraph;
			
			if (clientstate.activeGraph->active)
			{
				widgets->controlWindow->setAnimState(ANIM_LIVE);
				clientstate.animationUpdate = 1;
				clientstate.modes.animation = true;
			}
			else
			{
				widgets->controlWindow->setAnimState(ANIM_INACTIVE);
				clientstate.activeGraph->reset_animation();
				clientstate.modes.animation = false;
			}

			clientstate.activeGraph->emptyArgQueue();

			clientstate.newActiveGraph = 0;
			if (!externFloatingText.count(clientstate.activeGraph->tid))
			{
				vector<EXTTEXT> newVec;
				externFloatingText[clientstate.activeGraph->tid] = newVec;
			}
			
			if (clientstate.textlog) closeTextLog(&clientstate);
			
		}

		if (clientstate.activeGraph)
		{

			al_set_target_bitmap(clientstate.mainGraphBMP);
			frame_gl_setup(&clientstate);

			if (clientstate.modes.conditional)
				al_clear_to_color(conditionalBackground);
			else
				al_clear_to_color(mainBackground);

			if (!al_is_event_queue_empty(low_frequency_timer_queue))
			{
				al_flush_event_queue(low_frequency_timer_queue);
				performIrregularActions(&clientstate);
			}

			if (clientstate.modes.wireframe)
				draw_wireframe(&clientstate, wireframeStarts, wireframeSizes);

			if (clientstate.modes.diff)
				processDiff(&clientstate, PIDFont, &diffRenderer);
			else
				performMainGraphRendering(&clientstate, &externFloatingText);
				
			frame_gl_teardown();

			al_set_target_backbuffer(clientstate.maindisplay);
			if (clientstate.modes.preview)
			{
				if (previewRenderFrame++ % (60 / clientstate.config->preview.FPS))
				{
					drawPreviewGraphs(&clientstate, &graphPositions);
					previewRenderFrame = 0;
				}
				al_draw_bitmap(clientstate.previewPaneBMP, clientstate.size.width - PREVIEW_PANE_WIDTH, 0, 0);
			}
			al_draw_bitmap(clientstate.mainGraphBMP, 0, 0, 0);
			al_draw_filled_rectangle(0, clientstate.size.height - CONTROLS_Y, 	
				clientstate.size.width - PREVIEW_PANE_WIDTH,clientstate.size.height, al_map_rgba(0, 0, 0, 150));

			if (clientstate.activeGraph)
				display_activeGraph_summary(20, 10, PIDFont, &clientstate);
		}
		else
			al_clear_to_color(mainBackground);

		widgets->updateRenderWidgets(clientstate.activeGraph);
		al_flip_display();

		//ui events
		while (al_get_next_event(clientstate.event_queue, &ev))
		{
			int eventResult = handle_event(&ev, &clientstate);
			if (!eventResult) continue;
			switch (eventResult)
			{
			case EV_KEYBOARD:
				widgets->processEvent(&ev);
				break;

			case EV_MOUSE:
				widgets->processEvent(&ev);
				if (clientstate.newPID > -1)
				{
					clientstate.activePid = clientstate.glob_piddata_map[clientstate.newPID];
					clientstate.graphPositions.clear();
					map<int, void *> *pidGraphList = &clientstate.activePid->graphs;
					map<int, void *>::iterator pidIt;
					//get first graph with some verts
					clientstate.newActiveGraph = 0;
					for (pidIt = pidGraphList->begin();  pidIt != pidGraphList->end(); ++pidIt)
					{
						pair<int, void *> graphPair = *pidIt;
						thread_graph_data *graph = (thread_graph_data *)graphPair.second;
						if (graph->get_num_nodes())
						{
							clientstate.newActiveGraph = graph;
							break;
						}
					}			
					if (!clientstate.newActiveGraph) printf("ERROR: No graph found!\n");
					clientstate.newPID = -1;
				}
				break;

			case EV_BTN_RUN:
				{
					widgets->exeSelector->show();
					//todo: start timeline
					break;
				}
			case EV_BTN_QUIT:
				running = false;
				break;

			default:
				printf("WARNING! Unhandled event %d\n", eventResult);
			}
		}

		fps_unlocked = 1 / (al_get_time() - frame_start_time);
		al_wait_for_event(frame_timer_queue, &tev);
		fps = 1 / (al_get_time() - frame_start_time);
		updateTitle_FPS(clientstate.maindisplay, clientstate.title, fps, fps_unlocked);
	}

	free(wireframeStarts);
	free(wireframeSizes);

	cleanup_for_exit(clientstate.maindisplay);
	return 0;
}



bool loadTrace(VISSTATE *clientState, string filename) {

	ifstream loadfile;
	loadfile.open(filename, std::ifstream::binary);
	//load process data
	string s1;

	loadfile >> s1;
	if (s1 != "PID") {
		printf("Corrupt save, start = %s\n", s1.c_str());
		return false;
	}

	int PID;
	loadfile >> PID;
	if (PID < 0 || PID > 100000) { printf("Corrupt save (pid=%d)\n", PID); return false; }
	else printf("Loading saved PID: %d\n", PID);
	loadfile.seekg(1, ios::cur);

	PROCESS_DATA *newpiddata = new PROCESS_DATA;
	newpiddata->PID = PID;
	if (!loadProcessData(clientState, &loadfile, newpiddata))
	{
		printf("Process data load failed\n");
		return false;
	}
	printf("Loaded process data. Loading graphs...\n");

	if (!loadProcessGraphs(clientState, &loadfile, newpiddata))
	{
		printf("Process Graph load failed\n");
		return false;
	}

	printf("Loading completed successfully\n");
	loadfile.close();

	TraceVisGUI *widgets = (TraceVisGUI *)clientState->widgets;

	if (!obtainMutex(clientState->pidMapMutex, "load graph")) return 0;
	clientState->glob_piddata_map[PID] = newpiddata;
	widgets->addPID(PID);
	dropMutex(clientState->pidMapMutex, "load graph");

	launch_saved_PID_threads(PID, newpiddata, clientState);
	return true;
}

void set_active_graph(VISSTATE *clientState, int PID, int TID)
{
	PROCESS_DATA* target_pid = clientState->glob_piddata_map[PID];
	clientState->newActiveGraph = target_pid->graphs[TID];

	thread_graph_data * graph = (thread_graph_data *)target_pid->graphs[TID];
	if (graph->modPath.empty())	graph->assign_modpath(target_pid);

	TraceVisGUI *widgets = (TraceVisGUI *)clientState->widgets;
	widgets->diffWindow->setDiffGraph(graph);

	if (clientState->modes.diff)
		clientState->modes.diff = 0;
}

bool mouse_in_previewpane(VISSTATE* clientState, int mousex)
{
	return (clientState->modes.preview &&
		mousex > (clientState->size.width - PREVIEW_PANE_WIDTH));
}

int handle_event(ALLEGRO_EVENT *ev, VISSTATE *clientstate) {
	ALLEGRO_DISPLAY *display = clientstate->maindisplay;
	if (ev->type == ALLEGRO_EVENT_DISPLAY_RESIZE)
	{
		//TODO! REMAKE BITMAP
		clientstate->size.height = ev->display.height;
		clientstate->size.width = ev->display.width;
		handle_resize(clientstate);
		al_acknowledge_resize(display);
		printf("display resize handled\n");
		return EV_RESIZE;
	}

	if (ev->type == ALLEGRO_EVENT_MOUSE_AXES)
	{
		if (!clientstate->activeGraph) return 0;

		TraceVisGUI *widgets = (TraceVisGUI *)clientstate->widgets;
		MULTIPLIERS *mainscale = clientstate->activeGraph->m_scalefactors;
		float diam = mainscale->radius;
		long maxZoomIn = diam + 5; //prevent zoom into globe
		long slowRotateThresholdLow = diam + 8000;  // move very slow beyond this much zoom in 
		long slowRotateThresholdHigh = diam + 54650;// move very slow beyond this much zoom out

		float zoomdiff = abs(mainscale->radius - clientstate->zoomlevel);

		if (ev->mouse.dz) 
		{
			if (mouse_in_previewpane(clientstate, ev->mouse.x))
			{
				widgets->doScroll(ev->mouse.dz);
			}
			else
			{
				//adjust speed of zoom depending on how close we are
				int zoomfactor;
				if (clientstate->zoomlevel > 40000)
					zoomfactor = -5000;
				else
					zoomfactor = -1000;

				float newZoom = clientstate->zoomlevel + zoomfactor * ev->mouse.dz;
				if (newZoom >= maxZoomIn)
					clientstate->zoomlevel = newZoom;
				if (clientstate->zoomlevel == 0)
					clientstate->zoomlevel = 1; //delme testing only

				if (clientstate->activeGraph)
					updateTitle_Zoom(display, clientstate->title, (clientstate->zoomlevel - clientstate->activeGraph->zoomLevel));
			}
		}


		if (ev->mouse.dx || ev->mouse.dy) {
			ALLEGRO_MOUSE_STATE state;
			al_get_mouse_state(&state);
			if (clientstate->mouse_dragging)
			{
				//printf("Mouse DRAGGED dx:%d, dy:%d x:%d,y:%d\n", ev->mouse.dx, ev->mouse.dy, ev->mouse.x, ev->mouse.y);
				float dx = ev->mouse.dx;
				float dy = ev->mouse.dy;
				dx = min(1, max(dx, -1));
				dy = min(1, max(dy, -1));

				float slowdownfactor = 0.035; //reduce movement this much for every 1000 pixels zoomed in
				float slowdown = zoomdiff / 1000;
				//printf("zoomdiff: %f slowdown: %f\n", zoomdiff, slowdown);

				// here we control drag speed at various zoom levels
				// todo when we have insturctions to look at
				//todo: fix speed at furhter out zoom levels

				//if (zoomdiff > slowRotateThresholdLow && zoomdiff < slowRotateThresholdHigh) {
				//	printf("non slowed drag! low:%ld -> zd: %f -> high:%ld\n", slowRotateThresholdLow, zoomdiff, slowRotateThresholdHigh);
				//	dx *= 0.1;
				//	dy *= 0.1;
				//}
				//else
				//{
				if (slowdown > 0)
				{
					//printf("slowed drag! low:%ld -> zd: %f -> high:%ld slowdown:%f\n",slowRotateThresholdLow,zoomdiff,slowRotateThresholdHigh,slowdown);
					if (dx != 0) dx *= (slowdown * slowdownfactor);
					if (dy != 0) dy *= (slowdown * slowdownfactor);
				}
				//}
				clientstate->xturn -= dx;
				clientstate->yturn -= dy;
				char tistring[200];
				snprintf(tistring, 200, "xt:%f, yt:%f", fmod(clientstate->xturn, 360), fmod(clientstate->yturn, 360));
				updateTitle_dbg(display, clientstate->title, tistring);
			}
			else 
			{
				if (mouse_in_previewpane(clientstate, ev->mouse.x) && !widgets->dropdownDropped())
				{
					int PID, TID;
					if (find_mouseover_thread(clientstate, ev->mouse.x, ev->mouse.y, &PID, &TID))
					{
						thread_graph_data *graph = (thread_graph_data *)clientstate->glob_piddata_map[PID]->graphs[TID];
						widgets->showGraphToolTip(graph, clientstate->glob_piddata_map[PID], ev->mouse.x, ev->mouse.y);
					}
				}
			}
			updateTitle_Mouse(display, clientstate->title, ev->mouse.x, ev->mouse.y);
		}

		return EV_MOUSE;
	}

	switch (ev->type)
	{
	case ALLEGRO_EVENT_MOUSE_BUTTON_DOWN:
	{
		if (!mouse_in_previewpane(clientstate, ev->mouse.x))
			clientstate->mouse_dragging = true;
		else
		{
			TraceVisGUI *widgets = (TraceVisGUI *)clientstate->widgets;
			if (widgets->dropdownDropped()) return EV_MOUSE;
			printf("Setting graph from mouseover\n");
			int PID, TID;
			if (find_mouseover_thread(clientstate, ev->mouse.x, ev->mouse.y, &PID, &TID))
				set_active_graph(clientstate, PID, TID);		
		}
		return EV_MOUSE;
	}

	case ALLEGRO_EVENT_MOUSE_BUTTON_UP:
	{
		clientstate->mouse_dragging = false;
		return EV_MOUSE;
	}

	case ALLEGRO_EVENT_KEY_CHAR:
	{
		if (!clientstate->activeGraph) return 0;
		MULTIPLIERS *mainscale = clientstate->activeGraph->m_scalefactors;
		switch (ev->keyboard.keycode)
		{
		case ALLEGRO_KEY_ESCAPE: 
		{
			TraceVisGUI *widgets = (TraceVisGUI *)clientstate->widgets;
			if (widgets->diffWindow->diffFrame->isVisible())
			{
				widgets->diffWindow->diffFrame->setVisibility(false);
				break; 
			}

			if (widgets->highlightWindow->highlightFrame->isVisible())
			{
				widgets->highlightWindow->highlightFrame->setVisibility(false);
				break;
			}

			if (clientstate->highlightData.highlightState)
			{
				clientstate->highlightData.highlightState = 0;
				break;
			}

			if (clientstate->modes.diff)
			{
				printf("cancel diff");
				break;
			}
			return EV_BTN_QUIT;
		}
		case ALLEGRO_KEY_Y:
			change_mode(clientstate, EV_BTN_WIREFRAME);
			break;

		case ALLEGRO_KEY_K:
			change_mode(clientstate, EV_BTN_HEATMAP);
			break;

		case ALLEGRO_KEY_J:
			change_mode(clientstate, EV_BTN_CONDITION);
			break;

		case ALLEGRO_KEY_LEFT:

			mainscale->userHEDGESEP -= 0.05;
			clientstate->rescale = true;
			break;
		case ALLEGRO_KEY_RIGHT:
			mainscale->userHEDGESEP += 0.05;
			clientstate->rescale = true;
			break;
		case ALLEGRO_KEY_DOWN:
			mainscale->userVEDGESEP += 0.01;
			clientstate->rescale = true;
			break;
		case ALLEGRO_KEY_UP:
			mainscale->userVEDGESEP -= 0.01;
			clientstate->rescale = true;
			break;
		case ALLEGRO_KEY_PAD_PLUS:
			mainscale->userDiamModifier += 0.05;
			clientstate->rescale = true;
			break;
		case ALLEGRO_KEY_PAD_MINUS:
			mainscale->userDiamModifier -= 0.05;
			clientstate->rescale = true;
			break;
		case ALLEGRO_KEY_T:
			clientstate->show_ins_text++;
			if (clientstate->show_ins_text > INSTEXT_LAST)
				clientstate->show_ins_text = INSTEXT_FIRST;
			switch (clientstate->show_ins_text) {
			case INSTEXT_NONE:
				printf("Instruction text off");
				break;
			case INSTEXT_AUTO:
				printf("Instruction text auto");
				break;
			case INSTEXT_ALL_ALWAYS:
				printf("Instruction text always on");
				break;
			}
			break;
		case ALLEGRO_KEY_PAD_7:
			clientstate->zoomlevel += 100;
			break;
		case ALLEGRO_KEY_PAD_1:
			clientstate->zoomlevel -= 100;
			break;
		case ALLEGRO_KEY_PAD_8:
			clientstate->zoomlevel += 10;
			break;
		case ALLEGRO_KEY_PAD_2:
			clientstate->zoomlevel -= 10;
			break;
		case ALLEGRO_KEY_PAD_9:
			clientstate->zoomlevel += 1;
			break;
		case ALLEGRO_KEY_PAD_3:
			clientstate->zoomlevel -= 1;
			break;
		default:
			return EV_KEYBOARD;
		}
		return EV_KEYBOARD;
	}

	case ALLEGRO_EVENT_MENU_CLICK:
	{
		switch (ev->user.data1)
		{
		case EV_BTN_RUN:  return EV_BTN_RUN;
		case EV_BTN_QUIT: return EV_BTN_QUIT;

		case EV_BTN_WIREFRAME:
		case EV_BTN_PREVIEW:
		case EV_BTN_CONDITION:
		case EV_BTN_HEATMAP:
		case EV_BTN_NODES:
		case EV_BTN_EDGES:
			change_mode(clientstate, ev->user.data1);
			break;

		case EV_BTN_HIGHLIGHT:
			((TraceVisGUI *)clientstate->widgets)->showHideHighlightFrame();
			break;

		case EV_BTN_DIFF:
			((TraceVisGUI *)clientstate->widgets)->showHideDiffFrame();
			break;
		case EV_BTN_EXTERNLOG:
			if (clientstate->textlog)
				closeTextLog(clientstate);
			else
			{
				if (!clientstate->activeGraph) break;
				stringstream windowName;
				windowName << "Extern calls [TID: " << clientstate->activeGraph->tid << "]";
				clientstate->textlog = al_open_native_text_log(windowName.str().c_str(), 0);
				ALLEGRO_EVENT_SOURCE* logevents = (ALLEGRO_EVENT_SOURCE*)al_get_native_text_log_event_source(clientstate->textlog);
				al_register_event_source(clientstate->event_queue, logevents);
				clientstate->logSize = fill_extern_log(clientstate->textlog, clientstate->activeGraph, clientstate->logSize);
			}	
			break;

		case EV_BTN_SAVE:
			if (clientstate->activeGraph)
			{
				printf("Saving process %d to file\n", clientstate->activeGraph->pid);
				saveTrace(clientstate);
			}
			break;
		case EV_BTN_LOAD:
			printf("Opening file dialogue\n");
			loadTrace(clientstate, string("C:\\tracing\\testsave.txt"));
			clientstate->modes.animation = false;
			break;
		default:
			printf("UNHANDLED MENU EVENT? %d\n", ev->user.data1);
			break;
		}
		return EV_NONE;
	}

	case ALLEGRO_EVENT_DISPLAY_CLOSE:
		return EV_BTN_QUIT;

	case ALLEGRO_EVENT_NATIVE_DIALOG_CLOSE:
		closeTextLog(clientstate);
		return EV_NONE;
	}




	switch (ev->type) {
	case ALLEGRO_EVENT_DISPLAY_SWITCH_IN:
	case ALLEGRO_EVENT_DISPLAY_SWITCH_OUT:
	case ALLEGRO_EVENT_KEY_DOWN: //agui doesn't like this
	case ALLEGRO_EVENT_MOUSE_LEAVE_DISPLAY:
	case ALLEGRO_EVENT_KEY_UP:
	case ALLEGRO_EVENT_MOUSE_ENTER_DISPLAY:
	case ALLEGRO_EVENT_KEY_CHAR:
		return EV_NONE;
	}
	printf("unhandled event: %d\n", ev->type);

	return EV_NONE; //usually lose_focus
}