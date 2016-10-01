/*
Copyright 2016 Nia Catlin

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
This is where main lives

Performs initial setup 
handles all of the drawing and UI processing in a loop

OpenGL activity must be done in this thread
Doing agui widget manipulation in other threads will cause deque errors
*/

#include "stdafx.h"
#include "basicblock_handler.h"
#include "trace_handler.h"
#include "render_preview_thread.h"
#include "traceStructs.h"
#include "traceMisc.h"
#include "module_handler.h"
#include "render_heatmap_thread.h"
#include "render_conditional_thread.h"
#include "maingraph_render_thread.h"
#include "GUIManagement.h"
#include "rendering.h"
#include "b64.h"
#include "preview_pane.h"
#include "serialise.h"
#include "diff_plotter.h"
#include "timeline.h"
#include "OSspecific.h"
#include "clientConfig.h"

#pragma comment(lib, "glu32.lib")
#pragma comment(lib, "OpenGL32.lib")

struct THREAD_POINTERS {
	vector <base_thread *> threads;
	module_handler *modThread;
	basicblock_handler *BBthread;
	preview_renderer *previewThread;
	heatmap_renderer *heatmapThread;
	conditional_renderer *conditionalThread;
};

bool kbdInterrupt = false;

//for each saved process we have a thread rendering graph data for previews, heatmaps and conditonals
void launch_saved_process_threads(int PID, PROCESS_DATA *piddata, VISSTATE *clientState)
{
	DWORD threadID;
	preview_renderer *previews_thread = new preview_renderer(PID,0);
	previews_thread->clientState = clientState;
	previews_thread->piddata = piddata;

	HANDLE hOutThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)previews_thread->ThreadEntry,
		(LPVOID)previews_thread, 0, &threadID);

	heatmap_renderer *heatmap_thread = new heatmap_renderer(PID, 0);
	heatmap_thread->clientState = clientState;
	heatmap_thread->piddata = piddata;

	HANDLE hHeatThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)heatmap_thread->ThreadEntry,
		(LPVOID)heatmap_thread, 0, &threadID);

	conditional_renderer *conditional_thread = new conditional_renderer(PID, 0);
	conditional_thread->clientState = clientState;
	conditional_thread->piddata = piddata;

	Sleep(200);
	HANDLE hConditionThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)conditional_thread->ThreadEntry,
		(LPVOID)conditional_thread, 0, &threadID);

	clientState->spawnedProcess = clientState->glob_piddata_map[PID];
}
 
//for each live process we have a thread rendering graph data for previews, heatmaps and conditonals
//+ module data and disassembly
THREAD_POINTERS *launch_new_process_threads(int PID, std::map<int, PROCESS_DATA *> *glob_piddata_map, HANDLE pidmutex, VISSTATE *clientState)
{
	THREAD_POINTERS *processThreads = new THREAD_POINTERS;
	PROCESS_DATA *piddata = new PROCESS_DATA;
	piddata->PID = PID;
	if (clientState->switchProcess)
		clientState->spawnedProcess = piddata;

	if (!obtainMutex(pidmutex, 1038)) return 0;
	glob_piddata_map->insert_or_assign(PID, piddata);
	dropMutex(pidmutex);

	DWORD threadID;

	//spawns trace threads + handles module data for process
	module_handler *tPIDThread = new module_handler(PID, 0);
	tPIDThread->clientState = clientState;
	tPIDThread->piddata = piddata;

	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)tPIDThread->ThreadEntry,
		(LPVOID)tPIDThread, 0, &threadID);
	processThreads->modThread = tPIDThread;
	processThreads->threads.push_back(tPIDThread);

	//handles new disassembly data
	basicblock_handler *tBBHandler = new basicblock_handler(PID, 0);
	tBBHandler->clientState = clientState;
	tBBHandler->piddata = piddata;

	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)tBBHandler->ThreadEntry,
		(LPVOID)tBBHandler, 0, &threadID);
	processThreads->BBthread = tBBHandler;
	processThreads->threads.push_back(tBBHandler);

	if (!clientState->commandlineLaunchPath.empty()) return processThreads;

	//graphics rendering threads for each process here	
	preview_renderer *tPrevThread = new preview_renderer(PID,0);
	tPrevThread->clientState = clientState;
	tPrevThread->piddata = piddata;

	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)tPrevThread->ThreadEntry,
		(LPVOID)tPrevThread, 0, &threadID);

	heatmap_renderer *tHeatThread = new heatmap_renderer(PID, 0);
	tHeatThread->clientState = clientState;
	tHeatThread->piddata = piddata;
	tHeatThread->setUpdateDelay(clientState->config->heatmap.delay);

	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)tHeatThread->ThreadEntry,
		(LPVOID)tHeatThread, 0, &threadID);
	processThreads->heatmapThread = tHeatThread;
	processThreads->threads.push_back(tHeatThread);

	conditional_renderer *tCondThread = new conditional_renderer(PID, 0);
	tCondThread->clientState = clientState;
	tCondThread->piddata = piddata;
	tCondThread->setUpdateDelay(clientState->config->conditional.delay);

	Sleep(200);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)tCondThread->ThreadEntry,
		(LPVOID)tCondThread, 0, &threadID);

	processThreads->conditionalThread = tCondThread;
	processThreads->threads.push_back(tCondThread);

	return processThreads;
}

//listens for new and dying processes, spawns and kills threads to handle them
void process_coordinator_thread(VISSTATE *clientState) 
{
	//todo: posibly worry about pre-existing if pidthreads dont work

	HANDLE hPipe = CreateNamedPipe(L"\\\\.\\pipe\\BootstrapPipe",
		PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE,
		255, 65536, 65536, 0, NULL);

	OVERLAPPED ov = { 0 };
	ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

	if (hPipe == INVALID_HANDLE_VALUE)
	{
		cout << "[rgat]CreateNamedPipe failed with error " << GetLastError();
		return;
	}

	vector<THREAD_POINTERS*> threadsList;
	DWORD res = 0, bread = 0;
	char buf[40];
	while (!clientState->die)
	{
		bool conFail = ConnectNamedPipe(hPipe, &ov);
		if (conFail)
		{
			cerr << "[rgat]Warning! Bootstrap connection error" << endl;
			Sleep(1000);
			continue;
		}

		int err = GetLastError();
		if (err == ERROR_IO_PENDING || err == ERROR_PIPE_LISTENING) {
			res = WaitForSingleObject(ov.hEvent, 3000);
			if (res == WAIT_TIMEOUT) {
				Sleep(100);
				continue;
			}
		}

		ReadFile(hPipe, buf, 30, &bread, NULL);
		DisconnectNamedPipe(hPipe);

		if (!bread) {
			cout << "[rgat]ERROR: Read 0 when waiting for PID. Try again" << endl;
			Sleep(1000);
			continue;
		}
		buf[bread] = 0;

		int PID = 0;
		if (extract_integer(buf, string("PID"), &PID))
		{
			clientState->timelineBuilder->notify_new_pid(PID);
			THREAD_POINTERS *threads = launch_new_process_threads(PID, &clientState->glob_piddata_map, clientState->pidMapMutex, clientState);
			threadsList.push_back(threads);
			continue;
		}
		
	}

	//we get here when rgat is exiting
	//this tells all the child threads to die
	vector<THREAD_POINTERS *>::iterator processIt;
	for (processIt = threadsList.begin(); processIt != threadsList.end(); ++processIt)
	{
		THREAD_POINTERS *p = ((THREAD_POINTERS *)*processIt);
		vector<base_thread *>::iterator threadIt = p->threads.begin();
		for (; threadIt != p->threads.end(); ++threadIt)
			((base_thread *)*threadIt)->kill();
	}

	//wait for all children to terminate
	for (processIt = threadsList.begin(); processIt != threadsList.end(); ++processIt)
	{
		THREAD_POINTERS *p = ((THREAD_POINTERS *)*processIt);
		vector<base_thread *>::iterator threadIt = p->threads.begin();
		
		for (; threadIt != p->threads.end(); ++threadIt)
		{
			int waitLimit = 100;
			while (true)
			{
				if (!waitLimit--) ExitProcess(-1);
				if (((base_thread *)*threadIt)->is_alive()) {
					Sleep(2);  
					continue;
				}
				break;
			}
		}
		
	}

	clientState->glob_piddata_map.clear();
}

void change_mode(VISSTATE *clientState, int mode)
{
	switch (mode)
	{
	case EV_BTN_WIREFRAME:
		clientState->modes.wireframe = !clientState->modes.wireframe;
		return;

	case EV_BTN_CONDITION:
		
		clientState->modes.conditional = !clientState->modes.conditional;
		if (clientState->modes.conditional)
		{
			clientState->modes.nodes = true;
			clientState->modes.heatmap = false;
		}
		return;

	case EV_BTN_HEATMAP:

		clientState->modes.heatmap = !clientState->modes.heatmap;
		clientState->modes.nodes = !clientState->modes.heatmap;
		if (clientState->modes.heatmap) clientState->modes.conditional = false;
		return;

	case EV_BTN_PREVIEW:
		{
			al_destroy_bitmap(clientState->mainGraphBMP);
			clientState->modes.preview = !clientState->modes.preview;

			TraceVisGUI *widgets = (TraceVisGUI *)clientState->widgets;
			if (clientState->modes.preview)
			{
				widgets->setScrollbarVisible(true);
				clientState->mainGraphBMP = al_create_bitmap(clientState->mainFrameSize.width, clientState->mainFrameSize.height);
			}
			else
			{
				widgets->setScrollbarVisible(false);
				clientState->mainGraphBMP = al_create_bitmap(clientState->displaySize.width, clientState->mainFrameSize.height);
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

void draw_display_diff(VISSTATE *clientState, ALLEGRO_FONT *font, diff_plotter **diffRenderer)
{
	if (clientState->modes.diff == DIFF_STARTED) //diff graph built, display it
	{
		
		thread_graph_data *graph2 = (*diffRenderer)->get_graph(1);
		node_data *n = (*diffRenderer)->get_diff_node();
		if (n) //highlight has to be drawn before the graph or the text rendering will destroy it
			drawHighlight(&n->vcoord, graph2->m_scalefactors, &al_col_orange, 10);

		thread_graph_data *diffGraph = (*diffRenderer)->get_diff_graph();
		display_graph_diff(clientState, *diffRenderer);
	}

	else if (clientState->modes.diff == DIFF_SELECTED)//diff button clicked, build the graph first
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

	((diff_plotter*)*diffRenderer)->display_diff_summary(20, 40, font, clientState);
}

void closeTextLog(VISSTATE *clientState)
{
	al_close_native_text_log(clientState->textlog);
	clientState->textlog = 0;
	clientState->logSize = 0;
}

/*performs actions that need to be done quite often, but not every frame
this includes checking the locations of the screen edge on the sphere and
drawing new highlights for things that match the active filter*/
void performIrregularActions(VISSTATE *clientState)
{
	SCREEN_EDGE_PIX TBRG;
	//update where camera is pointing on sphere, used to choose which node text to draw
	edge_picking_colours(clientState, &TBRG, true);
	clientState->leftcolumn = (int)floor(ADIVISIONS * TBRG.leftgreen) - 1;
	clientState->rightcolumn = (int)floor(ADIVISIONS * TBRG.rightgreen) - 1;

	if (clientState->highlightData.highlightState && clientState->activeGraph->active)
	{
		TraceVisGUI *widgets = (TraceVisGUI *)clientState->widgets;
		widgets->highlightWindow->updateHighlightNodes(&clientState->highlightData,
			clientState->activeGraph, clientState->activePid);
	}
}

bool process_rgat_args(int argc, char **argv, VISSTATE *clientState)
{
	for (int idx = 1; idx < argc; idx++)
	{
		string arg(argv[idx]);
		if (arg == "-b")
		{
			clientState->launchopts.basic = true;
			continue;
		}

		if (arg == "-s")
		{
			clientState->launchopts.caffine = true;
			continue;
		}

		if (arg == "-p")
		{
			clientState->launchopts.pause = true;
			continue;
		}

		if (arg == "-l" && idx + 1 < argc)
		{
			clientState->commandlineLaunchPath = string(argv[++idx]);
			clientState->commandlineLaunchArgs = "";
			continue;
		}

		if (arg == "-e" && idx+2 < argc)
		{
			clientState->commandlineLaunchPath = string(argv[++idx]);
			clientState->commandlineLaunchArgs = string(argv[++idx]);
			continue;
		}

		if (arg == "-h" )
		{
			//TODO
			cout << "rgat - Instruction trace visualiser" << endl;
			cout << "-e target \"arguments\" Execute target with specified argument string"  << endl;
			cout << "-l target Execute target without arguments" << endl;
			cout << "-p Pause execution on program start. Allows attaching a debugger" << endl;
			cout << "-s Reduce sleep() calls and shorten tick counts for target" << endl;
			cout << "-b Launch in basic mode which does not save animation data" << endl;
			return false;
		}
	}

	if (!fileExists(clientState->commandlineLaunchPath))
	{
		cerr << "[rgat]ERROR: File " << clientState->commandlineLaunchPath << " does not exist, exiting..." << endl;
		return false;
	}
	return true;
}

BOOL WINAPI consoleHandler(DWORD signal) {

	if (signal == CTRL_C_EVENT)
		kbdInterrupt = true;

	return TRUE;
}

void handleKBDExit()
{
	if (!SetConsoleCtrlHandler(consoleHandler, TRUE)) {
		cerr << "[rgat]ERROR: Could not set control handler" << endl;
		return;
	}
}

static void set_active_graph(VISSTATE *clientState, int PID, int TID)
{
	PROCESS_DATA* target_pid = clientState->glob_piddata_map[PID];
	clientState->newActiveGraph = target_pid->graphs[TID];

	if (target_pid != clientState->activePid)
	{
		clientState->spawnedProcess = target_pid;
		clientState->switchProcess = true;
	}

	thread_graph_data * graph = (thread_graph_data *)target_pid->graphs[TID];
	if (graph->modPath.empty())	graph->assign_modpath(target_pid);

	TraceVisGUI *widgets = (TraceVisGUI *)clientState->widgets;
	widgets->diffWindow->setDiffGraph(graph);

	if (clientState->modes.diff)
		clientState->modes.diff = 0;
}

static bool mouse_in_previewpane(VISSTATE* clientState, int mousex)
{
	return (clientState->modes.preview &&
		mousex > clientState->mainFrameSize.width);
}

bool loadTrace(VISSTATE *clientState, string filename)
{
	ifstream loadfile;
	loadfile.open(filename, std::ifstream::binary);
	//load process data
	string s1;

	display_only_status_message("Loading save file...", clientState);

	loadfile >> s1;
	if (s1 != "PID") {
		cout << "[rgat]ERROR: Corrupt save, start = " << s1 << endl;
		return false;
	}

	string PID_s;
	int PID;
	loadfile >> PID_s;
	if (!caught_stoi(PID_s, &PID, 10)) return false;
	if (PID < 0 || PID > 100000) { cout << "[rgat]Corrupt save (pid= " << PID << ")" << endl; return false; }
	else
		cout << "[rgat]Loading saved PID: " << PID << endl;
	loadfile.seekg(1, ios::cur);

	PROCESS_DATA *newpiddata = new PROCESS_DATA;
	newpiddata->PID = PID;
	if (!loadProcessData(clientState, &loadfile, newpiddata))
	{
		cout << "[rgat]ERROR: Process data load failed" << endl;
		return false;
	}

	
	cout << "[rgat]Loaded process data. Loading graphs..." << endl;

	if (!loadProcessGraphs(clientState, &loadfile, newpiddata))
	{
		cout << "[rgat]Process Graph load failed" << endl;
		return false;
	}

	cout << "[rgat]Loading completed successfully" << endl;
	loadfile.close();

	if (!obtainMutex(clientState->pidMapMutex, 1039))
	{
		cerr << "[rgat]ERROR: Failed to obtain pidMapMutex in load" << endl;
		return false;
	}
	clientState->glob_piddata_map[PID] = newpiddata;
	TraceVisGUI *widgets = (TraceVisGUI *)clientState->widgets;
	widgets->addPID(PID);
	dropMutex(clientState->pidMapMutex);

	launch_saved_process_threads(PID, newpiddata, clientState);
	return true;
}

static int handle_event(ALLEGRO_EVENT *ev, VISSTATE *clientState)
{
	ALLEGRO_DISPLAY *display = clientState->maindisplay;
	TraceVisGUI *widgets = (TraceVisGUI *)clientState->widgets;

	if (ev->type == ALLEGRO_EVENT_DISPLAY_RESIZE)
	{
		clientState->displaySize.height = ev->display.height;
		clientState->mainFrameSize.height = ev->display.height - BASE_CONTROLS_HEIGHT;
		clientState->mainFrameSize.width = ev->display.width - (PREVIEW_PANE_WIDTH + PREV_SCROLLBAR_WIDTH);
		clientState->displaySize.width = ev->display.width;
		al_acknowledge_resize(display);
		handle_resize(clientState);

		return EV_NONE;
	}

	if (ev->type == ALLEGRO_EVENT_MOUSE_AXES)
	{
		if (!clientState->activeGraph || widgets->isHighlightVisible()) return EV_MOUSE;

		MULTIPLIERS *mainscale = clientState->activeGraph->m_scalefactors;
		float diam = mainscale->radius;
		long maxZoomIn = diam + 5; //prevent zoom into globe
		long slowRotateThresholdLow = diam + 8000;  // move very slow beyond this much zoom in 
		long slowRotateThresholdHigh = diam + 54650;// move very slow beyond this much zoom out

		float zoomdiff = abs(mainscale->radius - clientState->cameraZoomlevel);

		if (ev->mouse.dz)
		{
			if (mouse_in_previewpane(clientState, ev->mouse.x))
				widgets->doScroll(ev->mouse.dz);
			else
			{
				//adjust speed of zoom depending on how close we are
				int zoomfactor;
				if (clientState->cameraZoomlevel > 40000)
					zoomfactor = -5000;
				else
					zoomfactor = -1000;

				float newZoom = clientState->cameraZoomlevel + zoomfactor * ev->mouse.dz;
				if (newZoom >= maxZoomIn)
					clientState->cameraZoomlevel = newZoom;

				if (clientState->activeGraph)
					updateTitle_Zoom(display, clientState->title, (clientState->cameraZoomlevel - clientState->activeGraph->zoomLevel));
			}
		}

		if (ev->mouse.dx || ev->mouse.dy) 
		{
			ALLEGRO_MOUSE_STATE state;
			al_get_mouse_state(&state);
			if (clientState->mouse_dragging)
			{
				float dx = ev->mouse.dx;
				float dy = ev->mouse.dy;
				dx = min(1, max(dx, -1));
				dy = min(1, max(dy, -1));

				float slowdownfactor = 0.035; //reduce movement this much for every 1000 pixels zoomed in
				float slowdown = zoomdiff / 1000;

				// here we control drag speed at various zoom levels
				// todo when we have insturctions to look at
				//todo: fix speed at further out zoom levels

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
				clientState->xturn -= dx;
				clientState->yturn -= dy;
				char tistring[200];
				snprintf(tistring, 200, "xt:%f, yt:%f", fmod(clientState->xturn, 360), fmod(clientState->yturn, 360));
				updateTitle_dbg(display, clientState->title, tistring);
			}
			else
			{
				if (!mouse_in_previewpane(clientState, ev->mouse.x))
					widgets->toggleSmoothDrawing(false);
				else
				{
					widgets->toggleSmoothDrawing(true); //redraw every frame so preview tooltip moves smoothly
					int PID, TID;
					if (find_mouseover_thread(clientState, ev->mouse.x, ev->mouse.y, &PID, &TID))
					{
						map<int, PROCESS_DATA*>::iterator PIDIt = clientState->glob_piddata_map.find(PID);
						if (PIDIt != clientState->glob_piddata_map.end())
						{
							PROCESS_DATA* PID = PIDIt->second;
							map<int, void *>::iterator graphit = PID->graphs.find(TID);
							if (graphit != PID->graphs.end())
								widgets->showGraphToolTip((thread_graph_data *)graphit->second, PID, ev->mouse.x, ev->mouse.y);
						}
					}
				}
			}
			updateTitle_Mouse(display, clientState->title, ev->mouse.x, ev->mouse.y);
		}

		return EV_MOUSE;
	}

	switch (ev->type)
	{
		case ALLEGRO_EVENT_MOUSE_BUTTON_DOWN:
		{
			if (!mouse_in_previewpane(clientState, ev->mouse.x))
				clientState->mouse_dragging = true;
			else
			{
				if (widgets->dropdownDropped()) return EV_MOUSE;
				int PID, TID;
				if (find_mouseover_thread(clientState, ev->mouse.x, ev->mouse.y, &PID, &TID))
					set_active_graph(clientState, PID, TID);
			}
			return EV_MOUSE;
		}

		case ALLEGRO_EVENT_MOUSE_BUTTON_UP:
		{
			clientState->mouse_dragging = false;
			return EV_MOUSE;
		}

		case ALLEGRO_EVENT_KEY_CHAR:
		{
			bool closed = false;
			if (ev->keyboard.keycode == ALLEGRO_KEY_ESCAPE)
			{
				widgets->exeSelector->hide();
				widgets->highlightWindow->highlightFrame->setVisibility(false);
				widgets->diffWindow->diffFrame->setVisibility(false);
			}

			if (!clientState->activeGraph)
			{
				widgets->processEvent(ev);
				return EV_NONE;
			}

			MULTIPLIERS *mainscale = clientState->activeGraph->m_scalefactors;
			switch (ev->keyboard.keycode)
			{
				case ALLEGRO_KEY_ESCAPE:
				{
				
					if (clientState->highlightData.highlightState)
					{
						clientState->highlightData.highlightState = 0;
						break;
					}

					if (clientState->modes.diff)
					{
						clientState->modes.diff = 0;
						break;
					}
				}

				case ALLEGRO_KEY_Y:
					change_mode(clientState, EV_BTN_WIREFRAME);
					break;

				case ALLEGRO_KEY_K:
					change_mode(clientState, EV_BTN_HEATMAP);
					break;

				case ALLEGRO_KEY_M:
					clientState->config->showExternText = !clientState->config->showExternText;
					break;

				case ALLEGRO_KEY_J:
					change_mode(clientState, EV_BTN_CONDITION);
					break;

				case ALLEGRO_KEY_E:
					change_mode(clientState, EV_BTN_EDGES);
					break;

				case ALLEGRO_KEY_LEFT:
					mainscale->userHEDGESEP -= 0.05;
					clientState->rescale = true;
					break;

				case ALLEGRO_KEY_RIGHT:
					mainscale->userHEDGESEP += 0.05;
					clientState->rescale = true;
					break;

				case ALLEGRO_KEY_PAD_4:
					mainscale->userHEDGESEP -= 0.005;
					clientState->rescale = true;
					break;
				case ALLEGRO_KEY_PAD_6:
					mainscale->userHEDGESEP += 0.005;
					clientState->rescale = true;
					break;

				case ALLEGRO_KEY_DOWN:
					mainscale->userVEDGESEP += 0.01;
					clientState->rescale = true;
					break;
				case ALLEGRO_KEY_UP:
					mainscale->userVEDGESEP -= 0.01;
					clientState->rescale = true;
					break;
				case ALLEGRO_KEY_PAD_PLUS:
					mainscale->userDiamModifier += 0.05;
					clientState->rescale = true;
					break;
				case ALLEGRO_KEY_PAD_MINUS:
					mainscale->userDiamModifier -= 0.05;
					clientState->rescale = true;
					break;
				case ALLEGRO_KEY_T:
					clientState->show_ins_text++;
					if (clientState->show_ins_text > INSTEXT_LAST)
						clientState->show_ins_text = INSTEXT_FIRST;
					switch (clientState->show_ins_text) {
					case INSTEXT_NONE:
						cout << "[rgat]Instruction text off" << endl;
						break;
					case INSTEXT_AUTO:
						cout << "[rgat]Instruction text auto" << endl;
						break;
					case INSTEXT_ALL_ALWAYS:
						cout << "[rgat]Instruction text always on" << endl;
						break;
					}
					break;
				case ALLEGRO_KEY_PAD_7:
					clientState->cameraZoomlevel += 100;
					break;
				case ALLEGRO_KEY_PAD_1:
					clientState->cameraZoomlevel -= 100;
					break;
				}

				widgets->processEvent(ev);
				return EV_NONE;
		}

		case ALLEGRO_EVENT_MENU_CLICK:
		{
			switch (ev->user.data1)
			{
			case EV_BTN_RUN:
				widgets->exeSelector->show();
				break;

			case EV_BTN_QUIT: return EV_BTN_QUIT;

			case EV_BTN_WIREFRAME:
			case EV_BTN_PREVIEW:
			case EV_BTN_CONDITION:
			case EV_BTN_HEATMAP:
			case EV_BTN_NODES:
			case EV_BTN_EDGES:
				change_mode(clientState, ev->user.data1);
				break;

			case EV_BTN_HIGHLIGHT:
				widgets->showHideHighlightFrame();
				break;

			case EV_BTN_DIFF:
				widgets->showHideDiffFrame();
				break;
			case EV_BTN_EXTERNLOG:
				if (clientState->textlog)
					closeTextLog(clientState);
				else
				{
					if (!clientState->activeGraph) break;
					stringstream windowName;
					windowName << "Extern calls [TID: " << clientState->activeGraph->tid << "]";
					clientState->textlog = al_open_native_text_log(windowName.str().c_str(), 0);
					ALLEGRO_EVENT_SOURCE* logevents = (ALLEGRO_EVENT_SOURCE*)al_get_native_text_log_event_source(clientState->textlog);
					al_register_event_source(clientState->event_queue, logevents);
					clientState->logSize = clientState->activeGraph->fill_extern_log(clientState->textlog, clientState->logSize);
				}
				break;

			case EV_BTN_EXT_MOD_TEXT:
				clientState->config->showExternText = !clientState->config->showExternText;
				break;

			case EV_BTN_SAVE:
				if (clientState->activeGraph)
				{
					stringstream displayMessage;
					displayMessage << "[rgat]Saving process " << clientState->activeGraph->pid << " to filesystem" << endl;
					display_only_status_message("Saving process "+to_string(clientState->activeGraph->pid), clientState);
					cout << displayMessage.str();
					saveTrace(clientState);
				}
				break;

			case EV_BTN_LOAD:
			{
				widgets->exeSelector->hide();
				ALLEGRO_FILECHOOSER *fileDialog;
				//bug: sometimes uses current directory
				fileDialog = al_create_native_file_dialog(clientState->config->saveDir.c_str(),
					"Choose saved trace to open", "*.rgat;*.*;",
					ALLEGRO_FILECHOOSER_FILE_MUST_EXIST);
				al_show_native_file_dialog(clientState->maindisplay, fileDialog);

				const char* result = al_get_native_file_dialog_path(fileDialog, 0);
				al_destroy_native_file_dialog(fileDialog);

				if (!result) return EV_NONE;
				string path(result);
				if (!fileExists(path)) return EV_NONE;

				loadTrace(clientState, path);
				clientState->modes.animation = false;
				break;
			}
			default:
				cout << "[rgat]Warning: Unhandled menu event " << ev->user.data1;
				break;
			}
			return EV_NONE;
		}

		case ALLEGRO_EVENT_DISPLAY_CLOSE:
			return EV_BTN_QUIT;

		case ALLEGRO_EVENT_NATIVE_DIALOG_CLOSE:
			closeTextLog(clientState);
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
	cout << "[rgat]Warning: Unhandled Allegro event " << ev->type << endl;

	return EV_NONE; //usually lose_focus
}

//performs cleanup of old active graph, sets up environment to display new one
void switchToActiveGraph(VISSTATE *clientState, TraceVisGUI* widgets, map <int, vector<EXTTEXT>> *externFloatingText)
{
	clientState->activeGraph = (thread_graph_data *)clientState->newActiveGraph;
	clientState->activeGraph->needVBOReload_active = true;
	if (!clientState->activeGraph->VBOsGenned)
		gen_graph_VBOs(clientState->activeGraph);

	if (clientState->activeGraph->active)
	{
		widgets->controlWindow->setAnimState(ANIM_LIVE);
		clientState->animationUpdate = 1;
		clientState->modes.animation = true;

	}
	else
	{
		widgets->controlWindow->setAnimState(ANIM_INACTIVE);
		clientState->activeGraph->reset_animation();
		clientState->modes.animation = false;
		clientState->animationUpdate = 1;
		clientState->activeGraph->set_active_node(0);
	}

	clientState->activeGraph->emptyArgQueue();

	clientState->newActiveGraph = 0;
	if (!externFloatingText->count(clientState->activeGraph->tid))
	{
		vector<EXTTEXT> newVec;
		(*externFloatingText)[clientState->activeGraph->tid] = newVec;
	}

	if (clientState->textlog) closeTextLog(clientState);
}

int main(int argc, char **argv)
{

	if (fileExists("\\\\.\\pipe\\BootstrapPipe"))
	{
		printf("[rgat]Already running [Existing BootstrapPipe found]. Exiting...\n");
		return -1;
	}

	VISSTATE clientState;

	if (!al_init())
	{
		cerr << "[rgat]ERROR:Failed to initialise Allegro! Try using nongraphical mode -e from command line" << endl;
		return NULL;
	}

	//for linux this will want to be user home directory
	//windows probably wants it in AppData
	string configPath = getModulePath() + "\\rgat.cfg";
	clientState.config = new clientConfig(configPath);
	clientConfig *config = clientState.config;

	clientState.timelineBuilder = new timeline;

	//first deal with any command line arguments
	//if they exist, we go into non-graphical mode
	if (argc > 1)
	{
		if(!process_rgat_args(argc, argv, &clientState)) return 0;

		HANDLE hProcessCoordinator = CreateThread(
			NULL, 0, (LPTHREAD_START_ROUTINE)process_coordinator_thread,
			(LPVOID)&clientState, 0, 0);

		execute_tracer(clientState.commandlineLaunchPath, clientState.commandlineLaunchArgs, &clientState);
		handleKBDExit();
		
		int newTIDs,activeTIDs = 0;
		int newPIDs,activePIDs = 0;

		while (true)
		{
			newTIDs = clientState.timelineBuilder->numLiveThreads();
			newPIDs = clientState.timelineBuilder->numLiveProcesses();
			if (activeTIDs != newTIDs || activePIDs != newPIDs)
			{
				activeTIDs = newTIDs;
				activePIDs = newPIDs;
				cout << "[rgat]Tracking " << activeTIDs << " threads in " << activePIDs << " processes" << endl;
				if (!activeTIDs && !activePIDs)
				{
					cout << "[rgat]All processes terminated. Saving...\n" << endl;
					saveAll(&clientState);
					cout << "[rgat]Saving complete. Exiting." << endl;
					return 1;
				}
			}

			if (kbdInterrupt)
			{
				cout << "[rgat]Keyboard interrupt detected, saving..."<<endl;
				saveAll(&clientState);
				cout << "[rgat]Saving complete. Exiting." << endl;
				clientState.die = true;
				Sleep(500);
				return 1;
			}

		}
	}

	ALLEGRO_DISPLAY *newDisplay = 0;
	ALLEGRO_EVENT_QUEUE *newQueue = 0;
	if (!GUI_init(&newQueue, &newDisplay)) {
		cout << "[rgat]GUI init failed - Use nongraphical mode -e from command line" << endl;
		return 0;
	}
	
	clientState.gen_wireframe_buffers();
	clientState.event_queue = newQueue;
	clientState.maindisplay = newDisplay;
	clientState.displaySize.height = al_get_display_height(clientState.maindisplay);
	clientState.displaySize.width = al_get_display_width(clientState.maindisplay);
	clientState.mainFrameSize.height = clientState.displaySize.height - BASE_CONTROLS_HEIGHT;
	clientState.mainFrameSize.width = clientState.displaySize.width - (PREVIEW_PANE_WIDTH + PREV_SCROLLBAR_WIDTH);
	clientState.mainGraphBMP = al_create_bitmap(clientState.mainFrameSize.width, clientState.mainFrameSize.height);
	clientState.GUIBMP = al_create_bitmap(clientState.displaySize.width, clientState.displaySize.height);

	al_set_target_backbuffer(clientState.maindisplay);

	TITLE windowtitle;
	clientState.title = &windowtitle;

	updateTitle_Mouse(clientState.maindisplay, &windowtitle, 0, 0);
	updateTitle_Zoom(clientState.maindisplay, &windowtitle, clientState.cameraZoomlevel);

	bool buildComplete = false;

	//wireframe drawn using glMultiDrawArrays which takes a list of vert starts/sizes
	GLint *wireframeStarts = (GLint *)malloc(WIREFRAMELOOPS * sizeof(GLint));
	GLint *wireframeSizes = (GLint *)malloc(WIREFRAMELOOPS * sizeof(GLint));
	for (int i = 0; i < WIREFRAMELOOPS; ++i)
	{
		wireframeStarts[i] = i*WF_POINTSPERLINE;
		wireframeSizes[i] = WF_POINTSPERLINE;
	}

	//setup frame limiter/fps clock
	double fps, fps_max, frame_start_time;

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

	if (!frametimer || !updatetimer)
	{
		cerr << "[rgat]ERROR: Failed timer creation" << endl;
		return -1;
	}

	if (!al_init_font_addon() || !al_init_ttf_addon())
	{
		cerr << "[rgat]ERROR: Failed to init allegro font addon. Exiting..." << endl;
		return -1;
	}
	
	stringstream fontPath_ss;
	fontPath_ss << getModulePath() << "\\" << "VeraSe.ttf";
	string fontPath = fontPath_ss.str();
	clientState.standardFont = al_load_ttf_font(fontPath.c_str(), 12, 0);
	clientState.messageFont = al_load_ttf_font(fontPath.c_str(), 15, 0);
	ALLEGRO_FONT *PIDFont = al_load_ttf_font(fontPath.c_str(), 14, 0);
	if (!clientState.standardFont) {
		cerr << "[rgat]ERROR: Could not load font file "<< fontPath << endl;
		return -1;
	}

	TraceVisGUI* widgets = new TraceVisGUI(&clientState);
	clientState.widgets = (void *)widgets;
	widgets->widgetSetup(fontPath);
	widgets->toggleSmoothDrawing(true);

	//preload glyphs in cache
	al_get_text_width(clientState.standardFont, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890()=-+_,.><?/");
	al_get_text_width(PIDFont, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890()=-+_,.><?/");

	clientState.cameraZoomlevel = INITIALZOOM;
	clientState.previewPaneBMP = al_create_bitmap(PREVIEW_PANE_WIDTH, clientState.displaySize.height - 50);
	initial_gl_setup(&clientState);

	//for rendering graph diff
	diff_plotter *diffRenderer;

	ALLEGRO_EVENT ev;
	int previewRenderFrame = 0;
	map <int, NODEPAIR> graphPositions;
	map <int, vector<EXTTEXT>> externFloatingText;

	HANDLE hProcessCoordinator = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)process_coordinator_thread,
		(LPVOID)&clientState, 0, 0);

	maingraph_render_thread *mainRenderThread = new maingraph_render_thread(0,0);
	mainRenderThread->clientState = &clientState;

	HANDLE hPIDmodThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)mainRenderThread->ThreadEntry,
		(LPVOID)mainRenderThread, 0, 0);
	
	ALLEGRO_COLOR mainBackground = clientState.config->mainBackground;
	ALLEGRO_COLOR conditionalBackground = clientState.config->conditional.background;

	bool running = true;
	while (running)
	{
		frame_start_time = al_get_time();

		al_set_target_backbuffer(al_get_current_display());
		al_clear_to_color(al_col_black);

		//we want to switch to a new process, a new process exists and has graphs to show
		if (clientState.switchProcess && clientState.spawnedProcess && !clientState.spawnedProcess->graphs.empty())
		{
			PROCESS_DATA* activePid = clientState.spawnedProcess;
			clientState.activeGraph = 0;

			if (!obtainMutex(clientState.pidMapMutex, 1040)) return 0;
			
			widgets->setActivePID(activePid->PID);
			clientState.activePid = activePid;
			map<int, void *>::iterator graphIt;
			graphIt = activePid->graphs.begin();

			for (; graphIt != activePid->graphs.end(); ++graphIt)
			{
				thread_graph_data * graph = (thread_graph_data *)graphIt->second;
				if (!graph->get_num_edges()) continue;

				if (!graph->VBOsGenned)
					gen_graph_VBOs(graph);
				clientState.activeGraph = graph;
				clientState.modes.animation = true;
				clientState.animationUpdate = 1;
				if (graph->active)
					widgets->controlWindow->setAnimState(ANIM_LIVE);
				else 
					widgets->controlWindow->setAnimState(ANIM_INACTIVE);
				
				if (!externFloatingText.count(graph->tid))
				{
					vector<EXTTEXT> newVec;
					externFloatingText[graph->tid] = newVec;
				}

				clientState.wireframe_sphere = new GRAPH_DISPLAY_DATA(WFCOLBUFSIZE * 2);
				plot_wireframe(&clientState);
				plot_colourpick_sphere(&clientState);

				widgets->toggleSmoothDrawing(false);
				
				break;
			}

			//successfully found an active graph in a new process
			if (graphIt != activePid->graphs.end())
			{
				clientState.spawnedProcess = NULL;
				clientState.switchProcess = false;
			}

			dropMutex(clientState.pidMapMutex);
		}

		//active graph changed
		if (clientState.newActiveGraph)
			switchToActiveGraph(&clientState, widgets, &externFloatingText);

		widgets->updateWidgets(clientState.activeGraph);
		
		if (clientState.activeGraph)
		{
			al_set_target_bitmap(clientState.mainGraphBMP);
			frame_gl_setup(&clientState);

			if (clientState.modes.conditional)
				al_clear_to_color(conditionalBackground);
			else
				al_clear_to_color(mainBackground);

			if (!al_is_event_queue_empty(low_frequency_timer_queue))
			{
				al_flush_event_queue(low_frequency_timer_queue);
				performIrregularActions(&clientState);
			}

			if (clientState.modes.wireframe)
				maintain_draw_wireframe(&clientState, wireframeStarts, wireframeSizes);

			if (clientState.modes.diff)
				draw_display_diff(&clientState, PIDFont, &diffRenderer);

			if (!clientState.modes.diff) //not an else for clarity
				performMainGraphDrawing(&clientState, &externFloatingText);

			frame_gl_teardown();

			if (clientState.animFinished)
			{
				clientState.animFinished = false;
				TraceVisGUI* widgets = (TraceVisGUI*)clientState.widgets;
				widgets->controlWindow->notifyAnimFinished();
			}
			
			//draw preview graphs onto the previewpane bitmap
			al_set_target_backbuffer(clientState.maindisplay);
			if (clientState.modes.preview)
			{
				if (previewRenderFrame++ % (60 / clientState.config->preview.FPS))
				{
					redrawPreviewGraphs(&clientState, &graphPositions);
					previewRenderFrame = 0;
				}
				//draw them on the screen
				al_draw_bitmap(clientState.previewPaneBMP, clientState.mainFrameSize.width, MAIN_FRAME_Y, 0);
			}
			//draw the main big graph bitmap on the screen
			al_draw_bitmap(clientState.mainGraphBMP, 0, 0, 0);

			if (clientState.activeGraph)
				display_activeGraph_summary(20, 10, PIDFont, &clientState);
		}

		//draw the GUI controls, labels, etc onto the screen
		widgets->paintWidgets();
		al_set_target_backbuffer(clientState.maindisplay);
		al_draw_bitmap(clientState.GUIBMP, 0, 0, 0);

		if (clientState.modes.heatmap)
			draw_heatmap_key(&clientState);
		else if (clientState.modes.conditional)
			draw_conditional_key(&clientState);

		al_flip_display();

		//ui events
		while (al_get_next_event(clientState.event_queue, &ev))
		{
			int eventResult = handle_event(&ev, &clientState);
			if (!eventResult) continue;
			switch (eventResult)
			{
			case EV_MOUSE:
				widgets->processEvent(&ev);
				
				if (clientState.selectedPID > -1)
				{
					clientState.activePid = clientState.glob_piddata_map[clientState.selectedPID];
					clientState.graphPositions.clear();
					map<int, void *> *pidGraphList = &clientState.activePid->graphs;
					map<int, void *>::iterator pidIt;
					//get first graph with some verts
					clientState.newActiveGraph = 0;
					for (pidIt = pidGraphList->begin();  pidIt != pidGraphList->end(); ++pidIt)
					{
						pair<int, void *> graphPair = *pidIt;
						thread_graph_data *graph = (thread_graph_data *)graphPair.second;
						if (graph->get_num_nodes())
						{
							clientState.newActiveGraph = graph;
							break;
						}
					}			
					clientState.selectedPID = -1;
				}
	
				break;

			case EV_BTN_QUIT:
			{
				clientState.die = true;
				running = false;
				while (!clientState.glob_piddata_map.empty()) { Sleep(1); }
				break;
			}
			default:
				cout << "[rgat]WARNING: Unhandled event "<< eventResult << endl;
			}
		}

		fps_max = 1 / (al_get_time() - frame_start_time);
		al_wait_for_event(frame_timer_queue, &tev);
		fps = 1 / (al_get_time() - frame_start_time);
		updateTitle_FPS(clientState.maindisplay, clientState.title, fps, fps_max);
	}

	free(wireframeStarts);
	free(wireframeSizes);

	cleanup_for_exit(clientState.maindisplay);
	return 0;
}



