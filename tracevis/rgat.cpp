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
#include "b64.h"
#include "clientConfig.h"
#include "processLaunching.h"
#include "maingraph_render_thread.h"
#include "GUIManagement.h"
#include "rendering.h"
#include "preview_pane.h"
#include "serialise.h"
#include "diff_plotter.h"
#include "timeline.h"
#include "sphere_graph.h"
#include "tree_graph.h"

#pragma comment(lib, "glu32.lib")
#pragma comment(lib, "OpenGL32.lib")

bool kbdInterrupt = false;

void switchToActiveGraph(VISSTATE *clientState, TraceVisGUI* widgets);

bool process_rgat_args(int argc, char **argv, VISSTATE *clientState)
{
	for (int idx = 1; idx < argc; idx++)
	{
		string arg(argv[idx]);

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

		if (arg == "-y")
		{
			clientState->launchopts.debugLogging = true;
			continue;
		}

		if (arg == "-l")
		{
			if (idx + 1 < argc)
			{
				clientState->commandlineLaunchPath = string(argv[++idx]);
				clientState->commandlineLaunchArgs = "";
				continue;
			}
			cerr << "[rgat]ERROR: The -l option requires a path to an exeutable" << endl;
			return false;
		}

		if (arg == "-e")
		{
			if (idx + 2 < argc)
			{
				clientState->commandlineLaunchPath = string(argv[++idx]);
				clientState->commandlineLaunchArgs = string(argv[++idx]);
				continue;
			}
			cerr << "[rgat]ERROR: The -e option requires an executable and an argument string" << endl;
			return false;
		}

		if (arg == "-h" || arg == "-?")
		{
			cout << "rgat - Instruction trace visualiser" << endl;
			cout << "-e target \"arguments\" Execute target with specified argument string"  << endl;
			cout << "-l target Execute target without arguments" << endl;
			cout << "-p Pause execution on program start. Allows attaching a debugger" << endl;
			cout << "-s Reduce sleep() calls and shorten tick counts for target" << endl;
			cout << "-y Generate an instrumentation log for debugging drgat and reporting crashes" << endl;
			return false;
		}
		else
		{
			cout << "[rgat]Unknown arg: " << arg << endl;
			return false;
		}
	}

	if (!fileExists(clientState->commandlineLaunchPath))
	{
		cerr << "[rgat]ERROR: File [" << clientState->commandlineLaunchPath << "] does not exist, exiting..." << endl;
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
	//todo: os specific
	if (!SetConsoleCtrlHandler(consoleHandler, TRUE)) 
	{
		cerr << "[rgat]ERROR: Could not set console control handler" << endl;
		return;
	}
}

//prepares for switch to new graph
static void set_active_graph(VISSTATE *clientState, PID_TID PID, PID_TID TID)
{
	PROCESS_DATA* target_pid = clientState->glob_piddata_map[PID];
	plotted_graph * graph = (plotted_graph *)target_pid->plottedGraphs[TID];

	bool currentGraph = (clientState->activeGraph == graph) ? true : false;

	if (!currentGraph)
	{
		clientState->newActiveGraph = target_pid->plottedGraphs[TID];

		if (target_pid != clientState->activePid)
		{
			clientState->spawnedProcess = target_pid;
			clientState->switchProcess = true;
		}

		if (graph->get_protoGraph()->modulePath.empty())	graph->get_protoGraph()->assign_modpath(target_pid);
		graph->reset_animation();
	}

	TraceVisGUI *widgets = (TraceVisGUI *)clientState->widgets;
	widgets->diffWindow->setDiffGraph(graph);

	if (clientState->modes.diff)
		clientState->modes.diff = 0;

	updateTitle_NumPrimitives(clientState->maindisplay, clientState, graph->get_mainnodes()->get_numVerts(),
		graph->get_mainlines()->get_renderedEdges());
}

static bool mouse_in_previewpane(VISSTATE* clientState, int mousex)
{
	return (clientState->modes.preview &&
		mousex > clientState->mainFrameSize.width);
}

static bool mouse_in_maingraphpane(HEIGHTWIDTH *frameSize, int mousex, int mousey)
{
	return (mousex > 0 &&
			mousex < frameSize->width &&
			mousey > 0 &&
			mousey < frameSize->height);
}


bool loadTrace(VISSTATE *clientState, string filename)
{

	FILE* pFile;
	fopen_s(&pFile, filename.c_str(), "rb");
	char buffer[65536];
	rapidjson::FileReadStream is(pFile, buffer, sizeof(buffer));
	rapidjson::Document saveJSON;
	saveJSON.ParseStream<0, rapidjson::UTF8<>, rapidjson::FileReadStream>(is);

	//load process data
	string s1;

	display_only_status_message("Loading save file...", clientState);

	
	rapidjson::Value::ConstMemberIterator PIDIt = saveJSON.FindMember("PID");
	if (PIDIt == saveJSON.MemberEnd())
	{
		cout << "[rgat]ERROR: Process data load failed" << endl;
		return false;
	}
	PID_TID PID = PIDIt->value.GetUint64();

	if (clientState->glob_piddata_map.count(PID)) { cout << "[rgat]PID " << PID << " already loaded! Close rgat and reload" << endl; return false; }
	else
		cout << "[rgat]Loading saved PID: " << PID << endl;

	PROCESS_DATA *newpiddata;
	if (!loadProcessData(clientState, saveJSON, &newpiddata, PID))
	{
		cout << "[rgat]ERROR: Process data load failed" << endl;
		return false;
	}

	
	cout << "[rgat]Loaded process data. Loading graphs..." << endl;

	if (!loadProcessGraphs(clientState, saveJSON, newpiddata))
	{
		cout << "[rgat]Process Graph load failed" << endl;
		return false;
	}

	cout << "[rgat]Loading completed successfully" << endl;
	fclose(pFile);

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


void handle_mouse_zoom(ALLEGRO_EVENT *ev, VISSTATE *clientState, TraceVisGUI *widgets, long maxZoomIn)
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
	}
}

void handle_mouse_drag(ALLEGRO_EVENT *ev, VISSTATE *clientState, float zoomdiff)
{
	float dx = ev->mouse.dx;
	float dy = ev->mouse.dy;
	dx = min(1, max(dx, -1));
	dy = min(1, max(dy, -1));

	float slowdownfactor = 0.035; //reduce movement this much for every 1000 pixels zoomed in
	float slowdown = zoomdiff / 1000;

	// here we control drag speed at various zoom levels
	// todo when we have insturctions to look at
	if (slowdown > 0)
	{
		if (dx != 0) dx *= (slowdown * slowdownfactor);
		if (dy != 0) dy *= (slowdown * slowdownfactor);
	}

	clientState->view_shift_x -= dx;
	clientState->view_shift_y -= dy;
}

void handle_mouse_move(ALLEGRO_EVENT *ev, VISSTATE *clientState, TraceVisGUI *widgets)
{
	if (!mouse_in_previewpane(clientState, ev->mouse.x))
	{
		widgets->toggleSmoothDrawing(false);
		return;
	}

	widgets->toggleSmoothDrawing(true); //redraw every frame so preview tooltip moves smoothly
	PID_TID PID, TID;
	if (find_mouseover_thread(clientState, ev->mouse.x, ev->mouse.y, &PID, &TID))
	{
		map<PID_TID, PROCESS_DATA*>::iterator PIDIt = clientState->glob_piddata_map.find(PID);
		if (PIDIt != clientState->glob_piddata_map.end())
		{
			PROCESS_DATA* PID = PIDIt->second;
			map<PID_TID, void *>::iterator graphit = PID->plottedGraphs.find(TID);
			if (graphit != PID->plottedGraphs.end())
			{
				proto_graph *protoGraph = ((plotted_graph *)graphit->second)->get_protoGraph();
				widgets->showGraphToolTip(protoGraph, PID, ev->mouse.x, ev->mouse.y);
			}
		}
	}
}

void change_active_layout(VISSTATE *clientState, TraceVisGUI *widgets, graphLayouts clickedLayout, plotted_graph *oldActiveGraph)
{
	clientState->currentLayout = clickedLayout;
	widgets->setLayoutIcon();

	proto_graph *active_proto_graph = oldActiveGraph->get_protoGraph();
	PROCESS_DATA *piddata = active_proto_graph->get_piddata();
	PID_TID graphThread = oldActiveGraph->get_tid();

	plotted_graph *newPlottedGraph = 0;
	switch (clientState->currentLayout)
	{
	case eSphereLayout:
	{
		newPlottedGraph = new sphere_graph(piddata, graphThread, active_proto_graph, &clientState->config->graphColours);
		break;
	}
	case eTreeLayout:
	{
		newPlottedGraph = new tree_graph(piddata, graphThread, active_proto_graph, &clientState->config->graphColours);
		break;
	}
	default:
	{
		cout << "Bad graph layout: " << clientState->currentLayout << endl;
		assert(0);
	}
	}
	newPlottedGraph->initialiseDefaultDimensions();
	piddata->plottedGraphs.at(graphThread) = newPlottedGraph;
	clientState->newActiveGraph = newPlottedGraph;
	switchToActiveGraph(clientState, widgets);

	delete oldActiveGraph;
}

void handleKeypress(ALLEGRO_EVENT *ev, VISSTATE *clientState, TraceVisGUI *widgets)
{
	switch (ev->keyboard.keycode)
	{
	case ALLEGRO_KEY_ESCAPE:
	{
		if (!clientState->activeGraph) break;
		HIGHLIGHT_DATA *highlightData = &((plotted_graph *)clientState->activeGraph)->highlightData;
		if (highlightData->highlightState)
		{
			highlightData->highlightState = 0;
			break;
		}

		if (clientState->modes.diff)
		{
			clientState->modes.diff = 0;
			break;
		}

		break;
	}

	case ALLEGRO_KEY_Y:
		clientState->change_mode(EV_BTN_WIREFRAME);
		break;

	case ALLEGRO_KEY_K:
		clientState->change_mode(EV_BTN_HEATMAP);
		break;

	case ALLEGRO_KEY_N:
		clientState->modes.nearSide = !clientState->modes.nearSide;
		break;

	case ALLEGRO_KEY_J:
		clientState->change_mode(EV_BTN_CONDITION);
		break;

	case ALLEGRO_KEY_T:
		widgets->textConfigBox->toggle();
		break;

	case ALLEGRO_KEY_E:
		clientState->change_mode(EV_BTN_EDGES);
		break;

		//stretch and shrink the graph
	case ALLEGRO_KEY_LEFT:
		((plotted_graph *)clientState->activeGraph)->adjust_A_edgeSep(-0.05);
		clientState->rescale = true;
		break;
	case ALLEGRO_KEY_RIGHT:
		((plotted_graph *)clientState->activeGraph)->adjust_A_edgeSep(0.05);
		clientState->rescale = true;
		break;
	case ALLEGRO_KEY_DOWN:
		((plotted_graph *)clientState->activeGraph)->adjust_B_edgeSep(0.02);
		clientState->rescale = true;
		break;
	case ALLEGRO_KEY_UP:
		((plotted_graph *)clientState->activeGraph)->adjust_B_edgeSep(-0.02);
		clientState->rescale = true;
		break;

	case ALLEGRO_KEY_PAD_4:
		((plotted_graph *)clientState->activeGraph)->adjust_A_edgeSep(-0.005);
		clientState->rescale = true;
		break;
	case ALLEGRO_KEY_PAD_6:
		((plotted_graph *)clientState->activeGraph)->adjust_A_edgeSep(0.005);
		clientState->rescale = true;
		break;

		//fine zoon control
	case ALLEGRO_KEY_PAD_7:
		clientState->cameraZoomlevel += 100;
		break;
	case ALLEGRO_KEY_PAD_1:
		clientState->cameraZoomlevel -= 100;
		break;
	case ALLEGRO_KEY_PAD_8:
		clientState->cameraZoomlevel += 10;
		break;
	case ALLEGRO_KEY_PAD_2:
		clientState->cameraZoomlevel -= 10;
		break;

	case ALLEGRO_KEY_PAD_PLUS:
		((plotted_graph *)clientState->activeGraph)->adjust_size(0.05);
		clientState->rescale = true;
		break;
	case ALLEGRO_KEY_PAD_MINUS:
		((plotted_graph *)clientState->activeGraph)->adjust_size(-0.05);
		clientState->rescale = true;
		break;
	}

	widgets->processEvent(ev);
}

int handle_menu_click(ALLEGRO_EVENT *ev, VISSTATE *clientState, TraceVisGUI *widgets)
{
	switch (ev->user.data1)
	{
	case EV_BTN_RUN:
		widgets->exeSelector->show();
		break;

	case EV_BTN_QUIT:
		return EV_BTN_QUIT;

	case EV_BTN_WIREFRAME:
	case EV_BTN_PREVIEW:
	case EV_BTN_CONDITION:
	case EV_BTN_HEATMAP:
	case EV_BTN_NODES:
	case EV_BTN_EDGES:
		clientState->change_mode((eUIEventCode)ev->user.data1);
		break;

	case EV_BTN_HIGHLIGHT:
		widgets->showHideHighlightFrame();
		break;

	case EV_BTN_DIFF:
		widgets->showHideDiffFrame();
		break;

	case EV_BTN_EXTERNLOG:
		toggleExternLog(clientState);
		break;

	case EV_BTN_EXT_TEXT_MENU:
		widgets->textConfigBox->toggle();
		break;

	case EV_BTN_RESETSCALE:
		((plotted_graph *)clientState->activeGraph)->reset_edgeSep();
		clientState->rescale = true;
		break;

	case EV_BTN_AUTOSCALE:
		clientState->autoscale = !clientState->autoscale;
		cout << "[rgat]Autoscale ";
		if (clientState->autoscale) cout << "On." << endl;
		else cout << "Off. Re-enable to fix excess graph wrapping" << endl;
		break;

	case EV_BTN_NEARSIDE:
		clientState->modes.nearSide = !clientState->modes.nearSide;
		break;

	case EV_BTN_SAVE:
		if (clientState->activeGraph)
		{
			stringstream displayMessage;
			PID_TID pid = ((plotted_graph *)clientState->activeGraph)->get_pid();
			displayMessage << "[rgat]Starting save of process " << pid << " to filesystem" << endl;
			display_only_status_message("Saving process " + to_string(pid), clientState);
			cout << displayMessage.str();
			saveTrace(clientState);
		}
		break;

	case EV_BTN_LOAD:
	{

		if (!fileExists(clientState->config->saveDir))
		{
			string newSavePath = getModulePath() + "\\saves\\";
			clientState->config->updateSavePath(newSavePath);
		}

		widgets->exeSelector->hide();
		ALLEGRO_FILECHOOSER *fileDialog;
		//bug: sometimes uses current directory
		fileDialog = al_create_native_file_dialog(clientState->config->saveDir.c_str(),
			"Choose saved trace to open", "*.rgat;*.*;",
			ALLEGRO_FILECHOOSER_FILE_MUST_EXIST);
		clientState->dialogOpen = true;
		al_show_native_file_dialog(clientState->maindisplay, fileDialog);
		clientState->dialogOpen = false;

		const char* result = al_get_native_file_dialog_path(fileDialog, 0);
		al_destroy_native_file_dialog(fileDialog);
		if (!result) return EV_NONE;

		string path(result);
		if (!fileExists(path)) return EV_NONE;

		loadTrace(clientState, path);
		clientState->modes.animation = false;
		break;
	}

	case EV_BTN_ABOUT:
	{
		widgets->aboutBox->setLocation(200, 200);
		widgets->aboutBox->setVisibility(!widgets->aboutBox->isVisible());
		break;
	}

	default:
		cout << "[rgat]Warning: Unhandled menu event " << ev->user.data1;
		break;
	}

	return EV_NONE;
}

static int handle_event(ALLEGRO_EVENT *ev, VISSTATE *clientState)
{
	ALLEGRO_DISPLAY *display = clientState->maindisplay;
	TraceVisGUI *widgets = (TraceVisGUI *)clientState->widgets;

	if (ev->type == ALLEGRO_EVENT_DISPLAY_RESIZE)
	{
		resize_display(clientState, ev->display.width, ev->display.height);
		return EV_NONE;
	}

	if (ev->type == ALLEGRO_EVENT_MOUSE_AXES)
	{
		if (!clientState->activeGraph)  return EV_MOUSE;
		//if (widgets->isDialogVisible()) return EV_MOUSE;
		long graphSize = clientState->get_activegraph_size();

		long maxZoomIn = graphSize + 5; //prevent zoom into globe
		long slowRotateThresholdLow = graphSize + 8000;  // move very slow beyond this much zoom in 
		long slowRotateThresholdHigh = graphSize + 54650;// move very slow beyond this much zoom out

		float zoomdiff = abs(graphSize - clientState->cameraZoomlevel);

		if (ev->mouse.dz)
			handle_mouse_zoom(ev, clientState, widgets, maxZoomIn);


		if (ev->mouse.dx || ev->mouse.dy) 
		{
			ALLEGRO_MOUSE_STATE state;
			al_get_mouse_state(&state);
			
			if (clientState->mouse_dragging)
				handle_mouse_drag(ev, clientState, zoomdiff);
			else
				handle_mouse_move(ev, clientState, widgets);

			updateTitle_Mouse(display, clientState->title, ev->mouse.x, ev->mouse.y);
		}

		return EV_MOUSE;
	}

	switch (ev->type)
	{
		case ALLEGRO_EVENT_MOUSE_BUTTON_DOWN:
		{
			graphLayouts clickedLayout = layout_selection_click(ev->mouse.x, ev->mouse.y);
			if (clickedLayout != eLayoutInvalid)
			{
				plotted_graph *oldActiveGraph = (plotted_graph *)clientState->activeGraph;
				if (!oldActiveGraph) 
					return EV_MOUSE;

				if (clickedLayout != oldActiveGraph->getLayout())
				{
					change_active_layout(clientState, widgets, clickedLayout, oldActiveGraph);
				}

				return EV_MOUSE;
			}

			if (!clientState->dialogOpen && mouse_in_maingraphpane(&clientState->mainFrameSize, ev->mouse.x, ev->mouse.y))
				clientState->mouse_dragging = true;
			else
				if (mouse_in_previewpane(clientState, ev->mouse.x))
				{
					if (widgets->dropdownDropped()) return EV_MOUSE;
					PID_TID PID, TID;
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
			//close any open cruft on screen
			if (ev->keyboard.keycode == ALLEGRO_KEY_ESCAPE)
			{
				widgets->exeSelector->hide();
				widgets->highlightWindow->highlightFrame->setVisibility(false);
				widgets->diffWindow->diffFrame->setVisibility(false);
				clientState->dialogOpen = false;
			}

			if (clientState->dialogOpen) 
			{
				widgets->processEvent(ev);
				return EV_NONE;
			}

			//clipboard/select
			switch (ev->keyboard.keycode)
			{
				case ALLEGRO_KEY_LCTRL:
					//printf("l cont\n");
					break;
				case ALLEGRO_KEY_C:
					//printf("c pressed\n");
					break;
				case ALLEGRO_KEY_V:
				case ALLEGRO_KEY_X:
					break;
			}

			if (!clientState->activeGraph)
			{
				handleKeypress(ev, clientState, widgets);
				widgets->processEvent(ev);
				return EV_NONE;
			}

			handleKeypress(ev, clientState, widgets);

			
			return EV_NONE;
		}

		case ALLEGRO_EVENT_MENU_CLICK:
		{
			int returncode = handle_menu_click(ev, clientState, widgets);
			return returncode;
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
void switchToActiveGraph(VISSTATE *clientState, TraceVisGUI* widgets)
{
	maingraph_render_thread *renderThread = (maingraph_render_thread *)clientState->maingraphRenderThreadPtr;

	renderThread->getMutex();

	clientState->set_activeGraph((plotted_graph *)clientState->newActiveGraph);

	plotted_graph * newGraph = (plotted_graph *)clientState->activeGraph;
	newGraph->needVBOReload_active = true;

	clientState->cameraZoomlevel = newGraph->get_zoom();
	pair <long, long> startShift = newGraph->getStartShift();
	clientState->view_shift_x = startShift.first;
	clientState->view_shift_y = startShift.second;

	proto_graph *protoGraph = newGraph->get_protoGraph();
	clientState->currentLayout = newGraph->getLayout();
	widgets->setLayoutIcon();

	if (!newGraph->VBOsGenned)
		newGraph->gen_graph_VBOs();

	if (protoGraph->active)
	{
		widgets->controlWindow->setAnimState(ANIM_LIVE);
		clientState->animationUpdate = 1;
		clientState->modes.animation = true;
	}
	else
	{
		widgets->controlWindow->setAnimState(ANIM_INACTIVE);
		newGraph->reset_animation();
		clientState->modes.animation = false;
		clientState->animationUpdate = 1;
		protoGraph->set_active_node(0);
	}
	renderThread->dropMutex();

	//protoGraph->emptyArgQueue();
	protoGraph->assign_modpath(clientState->activePid);

	clientState->set_activegraph_size(newGraph->get_graph_size());

	clientState->newActiveGraph = 0;
	if (!clientState->externFloatingText.count(protoGraph->get_TID()))
	{
		vector<EXTTEXT> newVec;
		(clientState->externFloatingText)[protoGraph->get_TID()] = newVec;
	}

	if (clientState->textlog) closeTextLog(clientState);
}

int start_nongraphical_mode(VISSTATE *clientState)
{
	handleKBDExit();

	rgat_create_thread(process_coordinator_thread, clientState);

	eExeCheckResult exeType = check_excecutable_type(clientState->commandlineLaunchPath);
	if (exeType == eBinary32Bit)
		execute_tracer(clientState->commandlineLaunchPath, clientState->commandlineLaunchArgs, &clientState, false);
	else if (exeType == eBinary64Bit)
		execute_tracer(clientState->commandlineLaunchPath, clientState->commandlineLaunchArgs, &clientState, true);

	int newTIDs, activeTIDs = 0;
	int newPIDs, activePIDs = 0;

	while (true)
	{
		newTIDs = clientState->timelineBuilder->numLiveThreads();
		newPIDs = clientState->timelineBuilder->numLiveProcesses();
		if (activeTIDs != newTIDs || activePIDs != newPIDs)
		{
			activeTIDs = newTIDs;
			activePIDs = newPIDs;
			cout << "[rgat]Tracking " << activeTIDs << " threads in " << activePIDs << " processes" << endl;
			if (!activeTIDs && !activePIDs)
			{
				cout << "[rgat]All processes terminated. Saving...\n" << endl;
				saveAll(clientState);
				cout << "[rgat]Saving complete. Exiting." << endl;
				return 1;
			}
		}

		if (kbdInterrupt)
		{
			cout << "[rgat]Keyboard interrupt detected, saving..." << endl;
			saveAll(clientState);
			cout << "[rgat]Saving complete. Exiting." << endl;
			clientState->die = true;
			Sleep(500);
			return 1;
		}

	}
}

int main(int argc, char **argv)
{

	if (fileExists("\\\\.\\pipe\\BootstrapPipe"))
	{
		cerr << "[rgat]Already running [Existing BootstrapPipe found]. Exiting..." << endl;
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

	//if command line arguments exist, we go into non-graphical mode
	if (argc > 1)
	{
		if (!process_rgat_args(argc, argv, &clientState)) return 0;
		int retcode = start_nongraphical_mode(&clientState);
		return retcode;
	}

	ALLEGRO_DISPLAY *newDisplay = 0;
	ALLEGRO_EVENT_QUEUE *newQueue = 0;
	if (!GUI_init(&newQueue, &newDisplay)) {
		cout << "[rgat]GUI init failed - Use nongraphical mode from command line" << endl;
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


	//setup frame limiter/fps clock
	double fps, fps_max, frame_start_time;

	ALLEGRO_EVENT tev;
	ALLEGRO_TIMER *frametimer = al_create_timer(1.0 / TARGET_FPS);
	ALLEGRO_EVENT_QUEUE *frame_timer_queue = al_create_event_queue();
	al_register_event_source(frame_timer_queue, al_get_timer_event_source(frametimer));
	al_start_timer(frametimer);

	//edge_picking_colours() is a hefty call, but doesn't need calling often
	ALLEGRO_TIMER *updatetimer = al_create_timer(40.0 / TARGET_FPS);
	clientState.low_frequency_timer_queue = al_create_event_queue();
	al_register_event_source(clientState.low_frequency_timer_queue, al_get_timer_event_source(updatetimer));
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

	string resourcePath = getModulePath();
	string fontfile = "VeraSe.ttf";
	stringstream fontPath_ss;
	fontPath_ss << resourcePath << "\\" << fontfile;
	string fontPath = fontPath_ss.str();
	clientState.standardFont = al_load_ttf_font(fontPath.c_str(), 12, 0);
	clientState.messageFont = al_load_ttf_font(fontPath.c_str(), 15, 0);
	clientState.PIDFont = al_load_ttf_font(fontPath.c_str(), 14, 0);

	if (!clientState.standardFont) {
		cerr << "[rgat]ERROR: Could not load font file "<< fontPath << endl;
		return -1;
	}

	TraceVisGUI* widgets = new TraceVisGUI(&clientState);
	clientState.widgets = (void *)widgets;
	widgets->widgetSetup(resourcePath, fontfile);
	widgets->toggleSmoothDrawing(true);

	//preload glyphs in cache
	al_get_text_width(clientState.standardFont, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890()=-+_,.><?/");
	al_get_text_width(clientState.messageFont, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890()=-+_,.><?/");
	al_get_text_width(clientState.PIDFont, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890()=-+_,.><?/");

	//clientState.cameraZoomlevel = INITIALZOOM;
	clientState.previewPaneBMP = al_create_bitmap(PREVIEW_PANE_WIDTH, clientState.displaySize.height - 50);
	initial_gl_setup(&clientState);



	ALLEGRO_EVENT ev;
	
	map <PID_TID, NODEPAIR> graphPositions;


	rgat_create_thread((void *)process_coordinator_thread, &clientState);

	maingraph_render_thread *mainRenderThread = new maingraph_render_thread(0,0);
	mainRenderThread->clientState = &clientState;
	clientState.maingraphRenderThreadPtr = mainRenderThread;

	rgat_create_thread(mainRenderThread->ThreadEntry, mainRenderThread);

	bool running = true;
	while (running)
	{
		frame_start_time = al_get_time();

		al_set_target_backbuffer(al_get_current_display());
		al_clear_to_color(al_col_black);

		//we want to switch to a new process, a new process exists and has graphs to show
		if (clientState.switchProcess && clientState.spawnedProcess && !clientState.spawnedProcess->plottedGraphs.empty())
		{
			PROCESS_DATA* activePid = clientState.spawnedProcess;

			if (!obtainMutex(clientState.pidMapMutex, 1040)) return 0;
			
			widgets->setActivePID(activePid->PID);
			clientState.activePid = activePid;
			map<PID_TID, void *>::iterator graphIt;
			graphIt = activePid->plottedGraphs.begin();

			for (; graphIt != activePid->plottedGraphs.end(); ++graphIt)
			{
				plotted_graph *graph = (plotted_graph *)graphIt->second;
				proto_graph *protoGraph = graph->get_protoGraph();

				if (!protoGraph->get_num_edges()) continue;

				if (!graph->VBOsGenned)
					graph->gen_graph_VBOs();

				clientState.set_activeGraph(graph);

				clientState.modes.animation = true;
				clientState.animationUpdate = 1;
				clientState.cameraZoomlevel = graph->get_zoom();
				pair <long, long> startShift = graph->getStartShift();
				clientState.view_shift_x = startShift.first;
				clientState.view_shift_y = startShift.second;
				clientState.set_activegraph_size(graph->get_graph_size());


				if (protoGraph->active)
					widgets->controlWindow->setAnimState(ANIM_LIVE);
				else 
					widgets->controlWindow->setAnimState(ANIM_INACTIVE);
				
				if (!clientState.externFloatingText.count(protoGraph->get_TID()))
				{
					vector<EXTTEXT> newVec;
					clientState.externFloatingText[protoGraph->get_TID()] = newVec;
				}

				clientState.wireframe_sphere = new GRAPH_DISPLAY_DATA(WFCOLBUFSIZE * 2);
				if (clientState.modes.wireframe)
					graph->plot_wireframe(&clientState);

				plot_colourpick_sphere(&clientState);

				widgets->toggleSmoothDrawing(false);
				protoGraph->assign_modpath(activePid);
				break;
			}

			//successfully found an active graph in a new process
			if (graphIt != activePid->plottedGraphs.end())
			{
				clientState.spawnedProcess = NULL;
				clientState.switchProcess = false;
			}

			dropMutex(clientState.pidMapMutex);
		}


		widgets->updateWidgets((plotted_graph *)clientState.activeGraph);
		
		clientState.displayActiveGraph();

		//clientState.discard_activeGraph_ptr();
		//cout << "graph marked out of use" << endl;

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
						clientState.activePid = clientState.glob_piddata_map.at(clientState.selectedPID);
						clientState.graphPositions.clear();
						map<PID_TID, void *> *pidGraphList = &clientState.activePid->plottedGraphs;
						map<PID_TID, void *>::iterator pidIt;

						//get first graph with some verts
						clientState.newActiveGraph = 0;
						for (pidIt = pidGraphList->begin();  pidIt != pidGraphList->end(); ++pidIt)
						{
							pair<int, void *> graphPair = *pidIt;
							plotted_graph *graph = (plotted_graph *)graphPair.second;
							if (graph->get_protoGraph()->get_num_nodes())
							{
								clientState.newActiveGraph = graph;
								switchToActiveGraph(&clientState, widgets);
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



	cleanup_for_exit(&clientState);
	return 0;
}



