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
This is where main lives - after the initial setup it 
handles all of the drawing and UI processing in a loop

OpenGL activity must be done from this thread
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
	module_handler *modThread;
	basicblock_handler *BBthread;
	preview_renderer *previewThread;
	heatmap_renderer *heatmapThread;
	conditional_renderer *conditionalThread;
};

bool kbdInterrupt = false;

//for each saved process we have a thread rendering graph data for previews, heatmaps and conditonals
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
 
//for each live process we have a thread rendering graph data for previews, heatmaps and conditonals
//+ module data and disassembly
THREAD_POINTERS *launch_new_process_threads(int PID, std::map<int, PROCESS_DATA *> *glob_piddata_map, HANDLE pidmutex, VISSTATE *clientState) {
	THREAD_POINTERS *threads = new THREAD_POINTERS;
	PROCESS_DATA *piddata = new PROCESS_DATA;
	piddata->PID = PID;
	if (clientState->switchProcess)
		clientState->spawnedProcess = piddata;


	if (!obtainMutex(pidmutex, 1000)) return 0;
	glob_piddata_map->insert_or_assign(PID, piddata);
	dropMutex(pidmutex);

	DWORD threadID;

	//handles new threads+dlls for process
	module_handler *tPIDThread = new module_handler;
	tPIDThread->clientState = clientState;
	tPIDThread->PID = PID;
	tPIDThread->piddata = piddata;

	HANDLE hPIDmodThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)tPIDThread->ThreadEntry,
		(LPVOID)tPIDThread, 0, &threadID);
	threads->modThread = tPIDThread;

	//handles new disassembly data
	basicblock_handler *tBBThread = new basicblock_handler;
	tBBThread->clientState = clientState;
	tBBThread->PID = PID;
	tBBThread->piddata = piddata;

	HANDLE hPIDBBThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)tBBThread->ThreadEntry,
		(LPVOID)tBBThread, 0, &threadID);
	threads->BBthread = tBBThread;

	if (!clientState->commandlineLaunchPath.empty()) return threads;
	//graphics rendering threads for each process here	

	preview_renderer *tPrevThread = new preview_renderer;
	tPrevThread->clientState = clientState;
	tPrevThread->PID = PID;
	tPrevThread->piddata = piddata;

	HANDLE hPreviewThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)tPrevThread->ThreadEntry,
		(LPVOID)tPrevThread, 0, &threadID);
	threads->previewThread = tPrevThread;

	heatmap_renderer *tHeatThread = new heatmap_renderer;
	tHeatThread->clientState = clientState;
	tHeatThread->piddata = piddata;
	tHeatThread->setUpdateDelay(clientState->config->heatmap.delay);

	HANDLE hHeatThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)tHeatThread->ThreadEntry,
		(LPVOID)tHeatThread, 0, &threadID);
	threads->heatmapThread = tHeatThread;

	conditional_renderer *tCondThread = new conditional_renderer;
	tCondThread->clientState = clientState;
	tCondThread->piddata = piddata;
	tCondThread->setUpdateDelay(clientState->config->conditional.delay);

	Sleep(200);
	HANDLE hConditionThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)tCondThread->ThreadEntry,
		(LPVOID)tCondThread, 0, &threadID);
	threads->conditionalThread = tCondThread;

	return threads;
}

//listens for new and dying processes, spawns and kills threads to handle them
int process_coordinator_thread(VISSTATE *clientState) 
{
	//todo: posibly worry about pre-existing if pidthreads dont work
	HANDLE hPipe = CreateNamedPipe(L"\\\\.\\pipe\\BootstrapPipe",
		PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_WAIT,
		255, 65536, 65536, 300, NULL);

	if (hPipe == INVALID_HANDLE_VALUE)
	{
		cout << "[rgat]CreateNamedPipe failed with error " << GetLastError();
		return -1;
	}

	vector<THREAD_POINTERS*> threadsList;
	DWORD bread = 0;
	char buf[40];
	while (true)
	{
		int conresult = ConnectNamedPipe(hPipe, NULL);
		if (!conresult) {
			cout << "[rgat]ERROR: Failed to connect bootstrap pipe"<<endl;
			Sleep(1000);
			continue;
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

		if (string(buf).substr(0,3) == "DIE")
		{
			vector<THREAD_POINTERS *>::iterator threadIt;
			for (threadIt = threadsList.begin(); threadIt != threadsList.end(); ++threadIt)
			{
				THREAD_POINTERS *t = ((THREAD_POINTERS *)*threadIt);
				t->BBthread->die = true;
				ofstream BBPipe;
				BBPipe.open(t->BBthread->pipename);
				BBPipe << "DIE" << endl;
				BBPipe.close();

				((THREAD_POINTERS *)*threadIt)->modThread->die = true;
				ofstream modPipe;
				modPipe.open(t->modThread->pipename);
				modPipe << "DIE" << endl;
				modPipe.close();

				if (clientState->commandlineLaunchPath.empty())
				{
					t->heatmapThread->die = true;
					t->conditionalThread->die = true;
					t->previewThread->die = true;
				}
			}
		}
		else
		{
			cout << "[rgat]ERROR: Something bad happened in extract_integer, string is: " << buf << endl;
		}
		return -1;
	}
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

	((diff_plotter*)*diffRenderer)->display_diff_summary(20, 20, font, clientState);
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

bool process_rgat_args(int argc, char **argv, VISSTATE *clientstate)
{
	for (int idx = 1; idx < argc; idx++)
	{
		string arg(argv[idx]);
		if (arg == "-b")
		{
			clientstate->launchopts.basic = true;
			continue;
		}

		if (arg == "-s")
		{
			clientstate->launchopts.caffine = true;
			continue;
		}

		if (arg == "-p")
		{
			clientstate->launchopts.pause = true;
			continue;
		}

		if (arg == "-e" && idx+1 < argc)
		{
			clientstate->commandlineLaunchPath = string(argv[++idx]);
			continue;
		}

		if (arg == "-h" )
		{
			//TODO
			printf("Help...\n");
			return false;
		}
	}

	if (!fileExists(clientstate->commandlineLaunchPath))
	{
		cerr << "[rgat]ERROR: File " << clientstate->commandlineLaunchPath << " does not exist, exiting..." << endl;
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

	loadfile >> s1;
	if (s1 != "PID") {
		cout << "[rgat]Corrupt save, start = " << s1 << endl;
		return false;
	}

	int PID;
	loadfile >> PID;
	if (PID < 0 || PID > 100000) { cout << "[rgat]Corrupt save (pid= " << PID << ")" << endl; return false; }
	else
		cout << "[rgat]Loading saved PID: " << PID << endl;
	loadfile.seekg(1, ios::cur);

	PROCESS_DATA *newpiddata = new PROCESS_DATA;
	newpiddata->PID = PID;
	if (!loadProcessData(clientState, &loadfile, newpiddata))
	{
		cout << "Process data load failed" << endl;
		return false;
	}

	cout << "Loaded process data. Loading graphs..." << endl;

	if (!loadProcessGraphs(clientState, &loadfile, newpiddata))
	{
		cout << "Process Graph load failed" << endl;
		return false;
	}

	cout << "Loading completed successfully" << endl;
	loadfile.close();

	if (!obtainMutex(clientState->pidMapMutex, 6000))
	{
		cerr << "Failed to obtain pidMapMutex in load" << endl;
		return false;
	}
	clientState->glob_piddata_map[PID] = newpiddata;
	TraceVisGUI *widgets = (TraceVisGUI *)clientState->widgets;
	widgets->addPID(PID);
	dropMutex(clientState->pidMapMutex);

	launch_saved_PID_threads(PID, newpiddata, clientState);
	return true;
}

static int handle_event(ALLEGRO_EVENT *ev, VISSTATE *clientstate)
{
	ALLEGRO_DISPLAY *display = clientstate->maindisplay;
	TraceVisGUI *widgets = (TraceVisGUI *)clientstate->widgets;

	if (ev->type == ALLEGRO_EVENT_DISPLAY_RESIZE)
	{
		clientstate->displaySize.height = ev->display.height;
		clientstate->mainFrameSize.height = ev->display.height - BASE_CONTROLS_HEIGHT;
		clientstate->mainFrameSize.width = ev->display.width - (PREVIEW_PANE_WIDTH + PREV_SCROLLBAR_WIDTH);
		clientstate->displaySize.width = ev->display.width;
		al_acknowledge_resize(display);
		handle_resize(clientstate);

		return EV_NONE;
	}

	if (ev->type == ALLEGRO_EVENT_MOUSE_AXES)
	{
		if (!clientstate->activeGraph || widgets->isHighlightVisible()) return EV_MOUSE;

		MULTIPLIERS *mainscale = clientstate->activeGraph->m_scalefactors;
		float diam = mainscale->radius;
		long maxZoomIn = diam + 5; //prevent zoom into globe
		long slowRotateThresholdLow = diam + 8000;  // move very slow beyond this much zoom in 
		long slowRotateThresholdHigh = diam + 54650;// move very slow beyond this much zoom out

		float zoomdiff = abs(mainscale->radius - clientstate->zoomlevel);

		if (ev->mouse.dz)
		{
			if (mouse_in_previewpane(clientstate, ev->mouse.x))
				widgets->doScroll(ev->mouse.dz);
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
				clientstate->xturn -= dx;
				clientstate->yturn -= dy;
				char tistring[200];
				snprintf(tistring, 200, "xt:%f, yt:%f", fmod(clientstate->xturn, 360), fmod(clientstate->yturn, 360));
				updateTitle_dbg(display, clientstate->title, tistring);
			}
			else
			{
				if (mouse_in_previewpane(clientstate, ev->mouse.x))
				{
					widgets->toggleSmoothDrawing(true);
					int PID, TID;
					if (find_mouseover_thread(clientstate, ev->mouse.x, ev->mouse.y, &PID, &TID))
					{
						thread_graph_data *graph = (thread_graph_data *)clientstate->glob_piddata_map[PID]->graphs[TID];
						widgets->showGraphToolTip(graph, clientstate->glob_piddata_map[PID], ev->mouse.x, ev->mouse.y);
					}
				}
				else
					widgets->toggleSmoothDrawing(false);
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
				if (widgets->dropdownDropped()) return EV_MOUSE;
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
			if (ev->keyboard.keycode == ALLEGRO_KEY_ESCAPE)
				widgets->exeSelector->hide();

			if (!clientstate->activeGraph)
			{
				widgets->processEvent(ev);
				return EV_KEYBOARD;
			}

			MULTIPLIERS *mainscale = clientstate->activeGraph->m_scalefactors;
			switch (ev->keyboard.keycode)
			{
			case ALLEGRO_KEY_ESCAPE:
			{
				if (widgets->diffWindow->diffFrame->isVisible())
				{
					widgets->diffWindow->diffFrame->setVisibility(false);
					break;
				}

				if (widgets->isHighlightVisible())
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
					clientstate->modes.diff = 0;
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

			case ALLEGRO_KEY_E:
				change_mode(clientstate, EV_BTN_EDGES);
				break;

			case ALLEGRO_KEY_LEFT:
				mainscale->userHEDGESEP -= 0.05;
				clientstate->rescale = true;
				break;
			case ALLEGRO_KEY_RIGHT:
				mainscale->userHEDGESEP += 0.05;
				clientstate->rescale = true;
				break;

			case ALLEGRO_KEY_PAD_4:
				mainscale->userHEDGESEP -= 0.005;
				clientstate->rescale = true;
				break;
			case ALLEGRO_KEY_PAD_6:
				mainscale->userHEDGESEP += 0.005;
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
				clientstate->zoomlevel += 100;
				break;
			case ALLEGRO_KEY_PAD_1:
				clientstate->zoomlevel -= 100;
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
				change_mode(clientstate, ev->user.data1);
				break;

			case EV_BTN_HIGHLIGHT:
				widgets->showHideHighlightFrame();
				break;

			case EV_BTN_DIFF:
				widgets->showHideDiffFrame();
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
					clientstate->logSize = clientstate->activeGraph->fill_extern_log(clientstate->textlog, clientstate->logSize);
				}
				break;

			case EV_BTN_EXT_MOD_TEXT:
				clientstate->config->showExternText = !clientstate->config->showExternText;
				break;

			case EV_BTN_SAVE:
				if (clientstate->activeGraph)
				{
					cout << "[rgat]Saving process " << clientstate->activeGraph->pid << " to file" << endl;
					saveTrace(clientstate);
				}
				break;

			case EV_BTN_LOAD:
			{
				widgets->exeSelector->hide();
				ALLEGRO_FILECHOOSER *fileDialog;
				fileDialog = al_create_native_file_dialog(clientstate->config->saveDir.c_str(),
					"Choose saved trace to open", "*.rgat;*.*;",
					ALLEGRO_FILECHOOSER_FILE_MUST_EXIST);
				al_show_native_file_dialog(clientstate->maindisplay, fileDialog);

				const char* result = al_get_native_file_dialog_path(fileDialog, 0);
				al_destroy_native_file_dialog(fileDialog);

				if (!result) return EV_NONE;
				string path(result);
				if (!fileExists(path)) return EV_NONE;

				loadTrace(clientstate, path);
				clientstate->modes.animation = false;
				break;
			}
			default:
				cout << "[rgat]Error: Unhandled menu event " << ev->user.data1;
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
	cout << "[rgat]Warning: Unhandled event " << ev->type << endl;

	return EV_NONE; //usually lose_focus
}

int main(int argc, char **argv)
{

	if (fileExists("\\\\.\\pipe\\BootstrapPipe"))
	{
		printf("rgat already running [BootstrapPipe found]. Exiting...\n");
		return -1;
	}

	VISSTATE clientstate;

	if (!al_init())
	{
		cerr << "Failed to initialise Allegro! Use nongraphical mode -e from command line" << endl;
		return NULL;
	}

	string configPath = getModulePath() + "\\rgat.cfg";
	clientstate.config = new clientConfig(configPath);
	clientConfig *config = clientstate.config;

	clientstate.timelineBuilder = new timeline;

	//first deal with any command line arguments
	//if they exist, we go into non-graphical mode
	if (argc > 1)
	{
		if(!process_rgat_args(argc, argv, &clientstate)) return 0;

		HANDLE hProcessCoordinator = CreateThread(
			NULL, 0, (LPTHREAD_START_ROUTINE)process_coordinator_thread,
			(LPVOID)&clientstate, 0, 0);

		execute_tracer(clientstate.commandlineLaunchPath, &clientstate);
		handleKBDExit();
		
		int newTIDs,activeTIDs = 0;
		int newPIDs,activePIDs = 0;

		while (true)
		{
			newTIDs = clientstate.timelineBuilder->numLiveThreads();
			newPIDs = clientstate.timelineBuilder->numLiveProcesses();
			if (activeTIDs != newTIDs || activePIDs != newPIDs)
			{
				activeTIDs = newTIDs;
				activePIDs = newPIDs;
				cout << "[rgat]Tracking " << activeTIDs << " threads in " << activePIDs << " processes" << endl;
				if (!activeTIDs && !activePIDs)
				{
					cout << "[rgat]All processes terminated. Saving...\n" << endl;
					saveAll(&clientstate);
					cout << "[rgat]Saving complete. Exiting." << endl;
					return 1;
				}
			}

			if (kbdInterrupt)
			{
				cout << "[rgat]Keyboard interrupt detected, saving..."<<endl;
				//TODO: terminate all
				saveAll(&clientstate);
				cout << "[rgat]Saving complete. Exiting." << endl;
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
	
	clientstate.gen_wireframe_buffers();
	clientstate.event_queue = newQueue;
	clientstate.maindisplay = newDisplay;
	clientstate.displaySize.height = al_get_display_height(clientstate.maindisplay);
	clientstate.displaySize.width = al_get_display_width(clientstate.maindisplay);
	clientstate.mainFrameSize.height = clientstate.displaySize.height - BASE_CONTROLS_HEIGHT;
	clientstate.mainFrameSize.width = clientstate.displaySize.width - (PREVIEW_PANE_WIDTH + PREV_SCROLLBAR_WIDTH);
	clientstate.mainGraphBMP = al_create_bitmap(clientstate.mainFrameSize.width, clientstate.mainFrameSize.height);
	clientstate.GUIBMP = al_create_bitmap(clientstate.displaySize.width, clientstate.displaySize.height);

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

	if (!al_init_font_addon() || !al_init_ttf_addon())
	{
		cerr << "[rgat] Failed to init allegro font addon. Exiting..." << endl;
	}
	
	stringstream fontPath_ss;
	fontPath_ss << getModulePath() << "\\" << "VeraSe.ttf";
	string fontPath = fontPath_ss.str();
	clientstate.standardFont = al_load_ttf_font(fontPath.c_str(), 12, 0);
	ALLEGRO_FONT *PIDFont = al_load_ttf_font(fontPath.c_str(), 14, 0);
	if (!clientstate.standardFont) {
		cerr << "[rgat]Could not load font file "<< fontPath << endl;
		return -1;
	}

	TraceVisGUI* widgets = new TraceVisGUI(&clientstate);
	clientstate.widgets = (void *)widgets;
	widgets->widgetSetup(fontPath);
	widgets->toggleSmoothDrawing(true);

	//preload glyphs in cache
	al_get_text_width(clientstate.standardFont, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890()=-+_,.><?/");
	al_get_text_width(PIDFont, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890()=-+_,.><?/");

	clientstate.zoomlevel = INITIALZOOM;
	clientstate.previewPaneBMP = al_create_bitmap(PREVIEW_PANE_WIDTH, clientstate.displaySize.height - 50);
	initial_gl_setup(&clientstate);

	//for rendering graph diff
	diff_plotter *diffRenderer;

	ALLEGRO_EVENT ev;
	int previewRenderFrame = 0;
	map <int, NODEPAIR> graphPositions;
	map <int, vector<EXTTEXT>> externFloatingText;

	HANDLE hProcessCoordinator = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)process_coordinator_thread,
		(LPVOID)&clientstate, 0, 0);

	maingraph_render_thread *mainRenderThread = new maingraph_render_thread;
	mainRenderThread->clientState = &clientstate;

	HANDLE hPIDmodThread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)mainRenderThread->ThreadEntry,
		(LPVOID)mainRenderThread, 0, 0);
	
	ALLEGRO_COLOR mainBackground = clientstate.config->mainBackground;
	ALLEGRO_COLOR conditionalBackground = clientstate.config->conditional.background;

	bool running = true;
	while (running)
	{
		frame_start_time = al_get_time();

		al_set_target_backbuffer(al_get_current_display());
		al_clear_to_color(al_col_black);

		//no active graph but a process exists
		//this is in the main loop so the GUI gets rendered at the start
		//todo set to own function when we OOP this
		if (clientstate.switchProcess && clientstate.spawnedProcess && !clientstate.spawnedProcess->graphs.empty())
		{
			PROCESS_DATA* activePid = clientstate.spawnedProcess;

			if (!obtainMutex(clientstate.pidMapMutex, 2000)) return 0;
			
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

				clientstate.wireframe_sphere = new GRAPH_DISPLAY_DATA(WFCOLBUFSIZE * 2);
				plot_wireframe(&clientstate);
				plot_colourpick_sphere(&clientstate);

				widgets->toggleSmoothDrawing(false);
				
				break;
			}

			//successfully found an active graph in a new process
			if (graphIt != activePid->graphs.end())
			{
				clientstate.spawnedProcess = NULL;
				clientstate.switchProcess = false;
			}

			dropMutex(clientstate.pidMapMutex);
		}

		//active graph changed
		if (clientstate.newActiveGraph)
		{
			clientstate.activeGraph = (thread_graph_data *)clientstate.newActiveGraph;
			clientstate.activeGraph->needVBOReload_active = true;
			if (!clientstate.activeGraph->VBOsGenned)
				gen_graph_VBOs(clientstate.activeGraph);

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
		widgets->updateWidgets(clientstate.activeGraph);
		
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
				maintain_draw_wireframe(&clientstate, wireframeStarts, wireframeSizes);

			if (clientstate.modes.diff)
				processDiff(&clientstate, PIDFont, &diffRenderer);

			if (!clientstate.modes.diff) //not an else for clarity
				performMainGraphDrawing(&clientstate, &externFloatingText);

			frame_gl_teardown();

			if (clientstate.animFinished)
			{
				clientstate.animFinished = false;
				TraceVisGUI* widgets = (TraceVisGUI*)clientstate.widgets;
				widgets->controlWindow->notifyAnimFinished();
			}
			
			al_set_target_backbuffer(clientstate.maindisplay);
			if (clientstate.modes.preview)
			{
				if (previewRenderFrame++ % (60 / clientstate.config->preview.FPS))
				{
					drawPreviewGraphs(&clientstate, &graphPositions);
					previewRenderFrame = 0;
				}
				al_draw_bitmap(clientstate.previewPaneBMP, clientstate.mainFrameSize.width, MAIN_FRAME_Y, 0);
			}
			al_draw_bitmap(clientstate.mainGraphBMP, 0, 0, 0);

			if (clientstate.activeGraph)
				display_activeGraph_summary(20, 10, PIDFont, &clientstate);
		}

		//draw the GUI controls, labels, etc onto the screen
		widgets->paintWidgets();
		al_set_target_backbuffer(clientstate.maindisplay);
		al_draw_bitmap(clientstate.GUIBMP, 0, 0, 0);

		if (clientstate.modes.heatmap)
			draw_heatmap_key(&clientstate);
		else if (clientstate.modes.conditional)
			draw_conditional_key(&clientstate);

		al_flip_display();

		//ui events
		while (al_get_next_event(clientstate.event_queue, &ev))
		{
			int eventResult = handle_event(&ev, &clientstate);
			if (!eventResult) continue;
			switch (eventResult)
			{
			case EV_MOUSE:
				widgets->processEvent(&ev);
				
				if (clientstate.selectedPID > -1)
				{
					clientstate.activePid = clientstate.glob_piddata_map[clientstate.selectedPID];
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
					clientstate.selectedPID = -1;
				}
	
				break;

			case EV_BTN_QUIT:
			{
				mainRenderThread->die = true;
				if (clientstate.activePid)
					clientstate.terminationPid = clientstate.activePid->PID; //only stops current process threads
				Sleep(500);
				running = false;
				break;
			}
			default:
				cout << "[rgat]WARNING! Unhandled event "<< eventResult << endl;
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



