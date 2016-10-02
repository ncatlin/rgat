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
Monsterous class that handles the bulk of graph management
*/

#include "stdafx.h"
#include "thread_graph_data.h"
#include "thread_trace_reader.h"
#include "rendering.h"
#include "serialise.h"

//add new extern calls to log
unsigned int thread_graph_data::fill_extern_log(ALLEGRO_TEXTLOG *textlog, unsigned int logSize)
{
	vector <string>::iterator logIt = loggedCalls.begin();
	advance(logIt, logSize);
	while (logIt != loggedCalls.end())
	{
		al_append_native_text_log(textlog, logIt->c_str());
		logSize++;
		logIt++;
	}
	return logSize;
}

//returns combined count of read+processing trace buffers
unsigned long thread_graph_data::get_backlog_total()
{
	if (!this->trace_reader) return 0;
	thread_trace_reader *reader = (thread_trace_reader *)trace_reader;
	pair <unsigned long, unsigned long> sizePair;
	reader->getBufsState(&sizePair);
	return sizePair.first + sizePair.second;
}

//take externs called from the trace/replay and make them float on graph
//also adds them to the call log
void thread_graph_data::transferNewLiveCalls(map <int, vector<EXTTEXT>> *externFloatingText, PROCESS_DATA* piddata)
{
	obtainMutex(funcQueueMutex, 1013);
	while (!floatingExternsQueue.empty())
	{
		EXTERNCALLDATA nextExtern = floatingExternsQueue.front();
		floatingExternsQueue.pop();

		EXTTEXT extt;
		extt.edge = nextExtern.edgeIdx;
		extt.nodeIdx = nextExtern.nodeIdx;
		extt.framesRemaining = EXTERN_LIFETIME_FRAMES;
		extt.yOffset = 10;
		extt.displayString = generate_funcArg_string(get_node_sym(extt.nodeIdx, piddata), nextExtern.argList);

		if (nextExtern.edgeIdx.first == nextExtern.edgeIdx.second)
		{ 
			cout << "[rgat]WARNING: bad argument edge!" << endl; 
			continue; 
		}

		node_data* externn = get_node(nextExtern.edgeIdx.second);
		if (active)
		{
			if (!nextExtern.callerAddr)
			{
				obtainMutex(piddata->disassemblyMutex, 1014);
				node_data* parentn = get_node(nextExtern.edgeIdx.first);
				nextExtern.callerAddr = parentn->ins->address;
				dropMutex(piddata->disassemblyMutex);

				nextExtern.externPath = piddata->modpaths.at(externn->nodeMod);
				if (extt.displayString == "()")
				{
					stringstream hexaddr;
					hexaddr << "NOSYM:<0x" << std::hex << externn->address << ">";
					extt.displayString = hexaddr.str();
				}
			}
		}

		if (nextExtern.drawFloating)
		{
			stringstream callLog;
			callLog << "0x" << std::hex << externn->address << ": ";
			callLog << piddata->modpaths[externn->nodeMod] << " -> ";
			callLog << generate_funcArg_string(get_node_sym(externn->index, piddata), nextExtern.argList) << "\n";
			loggedCalls.push_back(callLog.str());

			externFloatingText->at(tid).push_back(extt);
		}
	}
	dropMutex(funcQueueMutex);
}

//display live or animated graph with active areas on faded areas
void thread_graph_data::display_active(bool showNodes, bool showEdges)
{
	GRAPH_DISPLAY_DATA *nodesdata = get_activenodes();
	GRAPH_DISPLAY_DATA *linedata = get_activelines();

	//reload buffers if needed and not being written
	if (needVBOReload_active && !isGraphBusy())
	{
		setGraphBusy(true);
		load_VBO(VBO_NODE_POS, activeVBOs, mainnodesdata->pos_size(), mainnodesdata->readonly_pos());
		load_VBO(VBO_NODE_COL, activeVBOs, animnodesdata->col_size(), animnodesdata->readonly_col());

		GLfloat *buf = mainlinedata->readonly_pos();
		if (!buf) { setGraphBusy(false); return; }
		int posbufsize = mainlinedata->get_numVerts() * POSELEMS * sizeof(GLfloat);
		load_VBO(VBO_LINE_POS, activeVBOs, posbufsize, buf);

		buf = animlinedata->readonly_col();
		if (!buf) { setGraphBusy(false); return; }
		int linebufsize = animlinedata->get_numVerts() * COLELEMS * sizeof(GLfloat);
		load_VBO(VBO_LINE_COL, activeVBOs, linebufsize, buf);

		needVBOReload_active = false;
		setGraphBusy(false);
	}

	if (showNodes)
		array_render_points(VBO_NODE_POS, VBO_NODE_COL, activeVBOs, nodesdata->get_numVerts());

	if (showEdges)
		array_render_lines(VBO_LINE_POS, VBO_LINE_COL, activeVBOs, linedata->get_numVerts());
}

//display graph with everything bright and viewable
void thread_graph_data::display_static(bool showNodes, bool showEdges)
{
	if (needVBOReload_main && !isGraphBusy())
	{
		setGraphBusy(true);
		loadVBOs(graphVBOs, mainnodesdata, mainlinedata);
		needVBOReload_main = false;
		setGraphBusy(false);
	}
	
	if (showNodes)
		array_render_points(VBO_NODE_POS, VBO_NODE_COL, graphVBOs, mainnodesdata->get_numVerts());

	if (showEdges)
		array_render_lines(VBO_LINE_POS, VBO_LINE_COL, graphVBOs, mainlinedata->get_numVerts());
}

//create faded edge version of graph for use in animations
void thread_graph_data::extend_faded_edges()
{
	vector<GLfloat> *animecol = animlinedata->acquire_col();
	vector<GLfloat> *mainecol = mainlinedata->acquire_col();
	unsigned int drawnVerts = mainlinedata->get_numVerts();
	unsigned int animatedVerts = animlinedata->get_numVerts();

	assert(drawnVerts >= animatedVerts);
	int pendingVerts = drawnVerts - animatedVerts;
	if (!pendingVerts) return;

	//copy the colours over
	unsigned int fadedIndex = animlinedata->get_numVerts() *COLELEMS;
	vector<float>::iterator mainEIt= mainecol->begin();
	advance(mainEIt, fadedIndex);
	animecol->insert(animecol->end(), mainEIt, mainecol->end());
	mainlinedata->release_col();

	//fade new colours alpha
	unsigned int index2 = (animlinedata->get_numVerts() *COLELEMS);
	unsigned int end = drawnVerts*COLELEMS;
	for (; index2 < end; index2 += COLELEMS)
		animecol->at(index2 + AOFF) = 0.01; //TODO: config file entry for anim inactive

	animlinedata->set_numVerts(drawnVerts);
	animlinedata->release_col();
}

//create edges in opengl buffers
void thread_graph_data::render_new_edges(bool doResize, map<int, ALLEGRO_COLOR> *lineColoursArr)
{
	GRAPH_DISPLAY_DATA *lines = get_mainlines();
	EDGELIST::iterator edgeIt;
	obtainMutex(edMutex, 1015); //not sure if i should make a list-specific mutex
	if (doResize)
	{
		reset_mainlines();
		lines = get_mainlines();
		edgeIt = edgeList.begin();
	}
	else
	{
		edgeIt = edgeList.begin();
		std::advance(edgeIt, lines->get_renderedEdges());
	}

	if (edgeIt != edgeList.end())
		needVBOReload_main = true;

	for (; edgeIt != edgeList.end(); ++edgeIt)
	{
		render_edge(*edgeIt, lines, lineColoursArr);
		extend_faded_edges();
		lines->inc_edgesRendered();
	}
	dropMutex(edMutex);
}

//given a sequence id, get the last instruction in the block it refers to
INS_DATA* thread_graph_data::get_last_instruction(unsigned long sequenceId)
{
	obtainMutex(animationListsMutex, 1016);
	pair<MEM_ADDRESS, int> targBlock_Size = bbsequence.at(sequenceId);
	BLOCK_IDENTIFIER blockID = mutationSequence.at(sequenceId);
	dropMutex(animationListsMutex);

	MEM_ADDRESS insAddr = targBlock_Size.first;
	int instructionIndex = targBlock_Size.second-1;
	
	return getDisassemblyBlock(insAddr, blockID, piddata->disassemblyMutex, &piddata->blocklist, &terminationFlag)->at(instructionIndex);
}

//externs not included in sequence data, have to check if each block called one
void thread_graph_data::brighten_externs(unsigned long targetSequence, bool updateArgs)
{
	//check if block called an extern
	INS_DATA* ins = get_last_instruction(targetSequence);
	int nodeIdx = ins->threadvertIdx[tid];

	obtainMutex(animationListsMutex, 1017);
	map <unsigned int, EDGELIST>::iterator externit = externCallSequence.find(nodeIdx);
	if (externit == externCallSequence.end())
	{
		dropMutex(animationListsMutex);
		return; 
	}

	EDGELIST callList = externit->second;

	unsigned int callsSoFar = callCounter[nodeIdx];
	if(updateArgs) 
		callCounter[nodeIdx] = callsSoFar + 1;
	int targetExternIdx;
	
	if (callsSoFar < callList.size()) 
		targetExternIdx = callList.at(callsSoFar).second;
	else 
		targetExternIdx = callList.at(0).second;

	dropMutex(animationListsMutex);

	node_data *n = get_node(targetExternIdx);

	EXTERNCALLDATA ex;
	ex.edgeIdx = make_pair(nodeIdx, targetExternIdx);
	ex.nodeIdx = n->index;
	ex.drawFloating = updateArgs;

	set_node_alpha(ex.nodeIdx, animnodesdata, 1);
	if (!activeNodeMap.count(ex.nodeIdx))
		activeNodeMap[ex.nodeIdx] = true;

	set_edge_alpha(ex.edgeIdx,animlinedata, 1);
	if (!activeEdgeMap.count(ex.edgeIdx))
		activeEdgeMap[ex.edgeIdx] = get_edge(ex.edgeIdx);
	
	string funcArgString;
	if (updateArgs)
	{
		if (!n->funcargs.empty())
			if (callsSoFar < n->funcargs.size())
				ex.argList = n->funcargs.at(callsSoFar);
			else
				ex.argList = *n->funcargs.rbegin();
	}


	obtainMutex(funcQueueMutex, 1018);
	floatingExternsQueue.push(ex);
	dropMutex(funcQueueMutex);

}

string thread_graph_data::get_node_sym(unsigned int idx, PROCESS_DATA* piddata)
{
	node_data *n = get_node(idx);
	string sym;

	if (!piddata->get_sym(n->nodeMod, n->address, &sym))
	{
		obtainMutex(piddata->disassemblyMutex, 2043);
		string modPath = piddata->modpaths.at(n->nodeMod);
		dropMutex(piddata->disassemblyMutex);

		stringstream nosym;
		nosym << basename(modPath) << ":0x" << std::hex << n->address;
		return nosym.str();
	}

	return sym;
}

void thread_graph_data::emptyArgQueue()
{
	obtainMutex(funcQueueMutex, 1019);
	while (!floatingExternsQueue.empty()) floatingExternsQueue.pop();
	dropMutex(funcQueueMutex);
}

bool thread_graph_data::decrease_sequence()
{
	return true; //unimplemented, better things to do at the moment
}

bool thread_graph_data::advance_sequence(bool skipLoop = false)
{
	if (sequenceIndex + 1 >= bbsequence.size()) return false;

	animInstructionIndex += bbsequence.at(sequenceIndex).second;
	//if not looping
	if (!loopStateList.at(sequenceIndex).first)
	{
		brighten_externs(++sequenceIndex, true);
		return true;
	}

	//first we update loop progress

	//just started loop
	if (!animLoopStartIdx)
	{
		targetIterations = loopStateList.at(sequenceIndex).second;
		animLoopIndex = 0;
		animLoopStartIdx = sequenceIndex;
		loopIteration = 1;
		animLoopProgress.push_back(loopIteration);
	}
	//block of first iteration of loop
	else if (animLoopIndex > animLoopProgress.size() - 1)
	{
		loopIteration = 1;
		animLoopProgress.push_back(loopIteration);
	}
	else
	{
		loopIteration = animLoopProgress.at(animLoopIndex) + 1;
		animLoopProgress.at(animLoopIndex) = loopIteration;
	}

	brighten_externs(sequenceIndex, true);

	//now set where to go next
	//last iteration of loop
	if (skipLoop || (loopStateList.at(sequenceIndex).second == animLoopProgress.at(animLoopIndex)))
	{
		//last block of loop
		if ((animLoopIndex >= animLoopProgress.size() - 1) || skipLoop)
		{
			++loopsPlayed;
			animLoopProgress.clear();
			animLoopStartIdx = 0;
			animLoopIndex = 0;
		}
		else
			++animLoopIndex;
		
		if (sequenceIndex + 1 >= bbsequence.size()) return false;
		++sequenceIndex;

		if (skipLoop)
			while (loopStateList.at(sequenceIndex).first)
				++sequenceIndex;
	}

	//last block of loop but not last iteration
	else if (loopStateList.at(sequenceIndex).first != loopStateList.at(sequenceIndex + 1).first)
	{

		sequenceIndex = animLoopStartIdx;
		animLoopIndex = 0;
		
	}
	else //inside loop
	{
		if (sequenceIndex + 1 >= bbsequence.size()) return false;
		++sequenceIndex;
		++animLoopIndex;
	}
	return true;
}

void thread_graph_data::performStep(int stepSize, bool skipLoop = false)
{

	if (stepSize > 0)
	{
		for (int i = 0; i < stepSize; ++i)
			if (!advance_sequence(skipLoop)) break;

	}
	else if (stepSize < 0)
	{
		stepSize *= -1;
		for (int i = 0; i < stepSize; ++i)
			decrease_sequence();
	}

	set_active_node(derive_anim_node());
}

unsigned int thread_graph_data::updateAnimation(unsigned int updateSize, bool animationMode, bool skipLoop = false)
{
	if (nodeList.empty()) return ANIMATION_ENDED;

	performStep(updateSize, skipLoop);
	if (!animationMode) return 0;

	bool animation_end = false;

	if (sequenceIndex >= (bbsequence.size() - 1))
		return ANIMATION_ENDED;

	return 0;
}

//todo move elsewhere
//returns number in the repeating range 0.0-1.0-0.0, oscillating with the clock
float getPulseAlpha()
{
	int millisecond = ((int)(clock() / 100)) % 10;
	int countUp = ((int)(clock() / 1000) % 10) % 2;

	float pulseAlpha;
	if (countUp)
		pulseAlpha = (float)millisecond / 10.0;
	else
		pulseAlpha = 1.0 - (millisecond / 10.0);
	return pulseAlpha;
}

void thread_graph_data::darken_animation(float alphaDelta)
{
	if (!animlinedata->get_numVerts()) return;
	GLfloat *ecol = &animlinedata->acquire_col()->at(0);

	map<NODEPAIR, edge_data *>::iterator activeEdgeIt = activeEdgeMap.begin();
	bool update = false;

	if (activeEdgeIt != activeEdgeMap.end()) 
		update = true;
	while (activeEdgeIt != activeEdgeMap.end())
	{
		edge_data *e = activeEdgeIt->second;
		unsigned long edgeStart = e->arraypos;
		float edgeAlpha;
		float lowestAlpha = 0;
		assert(e->vertSize);
		for (unsigned int i = 0; i < e->vertSize; ++i)
		{
			const unsigned int colBufIndex = edgeStart + i*COLELEMS + AOFF;
			if (colBufIndex >= animlinedata->col_buf_capacity_floats())
			{
				cerr << "[rgat]ERROR in darkening. colbufIndex > capacity" << endl;
				assert(0);
			}
			edgeAlpha = ecol[colBufIndex];

			//TODO: problems here!
			//0.05 stored as 0.05000000002
			//0.06 stored as 0.59999999999997 [not the real number of 0's]
			edgeAlpha = fmax(ANIM_INACTIVE_EDGE_ALPHA, edgeAlpha - alphaDelta);
			ecol[colBufIndex] = edgeAlpha;
			lowestAlpha = fmax(lowestAlpha, edgeAlpha);
		}	

		//workaround to problem, fails with 0.05, works with 0.06
		if (lowestAlpha <= ANIM_INACTIVE_EDGE_ALPHA)
			activeEdgeIt = activeEdgeMap.erase(activeEdgeIt);
		else
			++activeEdgeIt;
	}
	animlinedata->release_col();

	GLfloat *ncol = &animnodesdata->acquire_col()->at(0);
	int colBufSize = animnodesdata->col_buf_capacity_floats();

	map<unsigned int, bool>::iterator activeNodeIt = activeNodeMap.begin();
	if (activeNodeIt != activeNodeMap.end()) 
		update = true;
	while (activeNodeIt != activeNodeMap.end())
	{
		unsigned int nodeIndex = activeNodeIt->first;
		node_data *n = get_node(nodeIndex);
		int colBufIndex = (nodeIndex * COLELEMS) + AOFF;
		if (colBufIndex >= colBufSize) break;
		float currentAlpha = ncol[colBufIndex];
		currentAlpha = fmax(ANIM_INACTIVE_NODE_ALPHA, currentAlpha - alphaDelta);
		ncol[colBufIndex] = currentAlpha;

		if (currentAlpha == ANIM_INACTIVE_NODE_ALPHA)
			activeNodeIt = activeNodeMap.erase(activeNodeIt);
		else
			++activeNodeIt;
	}

	animnodesdata->release_col();
	if (update) needVBOReload_active = true;
}

void thread_graph_data::reset_animation()
{
	last_anim_start = 0;
	last_anim_stop = 0;
	animInstructionIndex = 0;
	newanim = true;

	sequenceIndex = 0;
	blockInstruction = 0;
	if (!nodeList.empty())
	{
		set_active_node(0);
		darken_animation(1.0);
	}
	firstAnimatedBB = 0;
	lastAnimatedBB = 0;
	activeEdgeMap.clear();
	activeNodeMap.clear();
	loopsPlayed = 0;
	loopIteration = 0;
	targetIterations = 0;
	callCounter.clear();
}

int thread_graph_data::brighten_BBs()
{
	unsigned int lastNodeIdx = 0;
	unsigned int animEnd = sequenceIndex;

	unsigned int animPosition = firstAnimatedBB; 
	if (animPosition == animEnd) return animEnd;

	if((animEnd - animPosition) > MAX_LIVE_ANIMATION_NODES_PER_FRAME)
		animPosition = animEnd - MAX_LIVE_ANIMATION_NODES_PER_FRAME;

	bool dropout = false;
	map <unsigned long, bool> recentHighlights;

	for (; animPosition < animEnd; ++animPosition)
	{
		bool isLastInSequence = (animPosition == (animEnd - 1));
		brighten_externs(animPosition, active);

		//don't re-brighten same edge/node on same animation frame
		if (recentHighlights.count(animPosition)) continue;
		recentHighlights[animPosition] = true;

		GLfloat *ncol = &animnodesdata->acquire_col()->at(0);
		GLfloat *ecol = &animlinedata->acquire_col()->at(0);

		while (!ncol || !ecol) 
		{
			animnodesdata->release_col();
			animlinedata->release_col();
			cerr << "[rgat]Warning: BB brighten failed" << endl;
			Sleep(75);
			ncol = &animnodesdata->acquire_col()->at(0);
			ecol = &animlinedata->acquire_col()->at(0);
		}


		obtainMutex(animationListsMutex, 1020);
		pair<MEM_ADDRESS, int> targBlock_Size = bbsequence.at(animPosition);
		BLOCK_IDENTIFIER blockID = mutationSequence.at(animPosition);
		dropMutex(animationListsMutex);
		
		MEM_ADDRESS blockAddr = targBlock_Size.first;
		int numInstructions = targBlock_Size.second;
		
		INSLIST *block = getDisassemblyBlock(blockAddr, blockID,disassemblyMutex,&piddata->blocklist, &terminationFlag);
		INS_DATA *ins = block->at(0);

		unordered_map<int, int>::iterator vertIt = ins->threadvertIdx.find(tid);
		if (vertIt == ins->threadvertIdx.end())
		{
			cerr << "[rgat]WARNING: BrightenBBs going too far? Breaking!" << endl;
			animnodesdata->release_col();
			animlinedata->release_col();
			break;
		}
		
		obtainMutex(disassemblyMutex, 1021); //do we need this here?
		unsigned int nodeIdx = vertIt->second;
		dropMutex(disassemblyMutex);

		if (lastNodeIdx)
		{
			NODEPAIR edgePair = make_pair(lastNodeIdx, nodeIdx);
			edge_data *linkingEdge;
			if (!edge_exists(edgePair, &linkingEdge)) {
				cerr << "[rgat]WARNING: BrightenBBs: lastnode " << lastNodeIdx << "->node "
					<< nodeIdx << " not in edgedict." << endl;
				continue;
			}

			int numEdgeVerts = linkingEdge->vertSize;
			for (int i = 0; i < numEdgeVerts; ++i)
			{
				const unsigned int colArrIndex = linkingEdge->arraypos + i*COLELEMS + AOFF;
				if (colArrIndex >= animlinedata->col_buf_capacity_floats())
				{
					//used this in devel, not sure it still happens. dead code?
					cerr << "[rgat]Error: DROPOUT EDGE" << endl;
					dropout = true;
					break;
				}
				ecol[colArrIndex] = (float)1.0;
			}

			if (!activeEdgeMap.count(edgePair))
				activeEdgeMap[edgePair] = linkingEdge;
		}

		
		for (int blockIdx = 0; blockIdx < numInstructions; ++blockIdx)
		{
			const unsigned int colArrIndex = (nodeIdx * COLELEMS) + AOFF;
			if (colArrIndex >= animnodesdata->col_buf_capacity_floats())
			{
				//trying to brighten nodes we havent rendered yet
				dropout = true;
				break;
			}

			//brighten the node
			ncol[colArrIndex] = 1;
			if (!activeNodeMap.count(nodeIdx))
				activeNodeMap[nodeIdx] = true;

			if (blockIdx == numInstructions - 1) break;

			//brighten short edge between internal nodes
			INS_DATA* nextIns = block->at(blockIdx + 1);
			unsigned int nextInsIndex = nextIns->threadvertIdx.at(tid);
			NODEPAIR edgePair = make_pair(nodeIdx, nextInsIndex);

			edge_data *e = get_edge(edgePair);
			unsigned long edgeColPos = e->arraypos;
			ecol[edgeColPos + AOFF] = 1.0;
			ecol[edgeColPos + COLELEMS + AOFF] = 1.0;
			assert(edgeColPos + COLELEMS + AOFF < animlinedata->col_buf_capacity_floats());
			if (!activeEdgeMap.count(edgePair))
					activeEdgeMap[edgePair] = e;

			nodeIdx = nextInsIndex;
			ins = nextIns;
		}
		
		lastNodeIdx = nodeIdx;
		animnodesdata->release_col();
		animlinedata->release_col();
		
		if (dropout) break;
	}
	brighten_externs(animEnd, active);

	needVBOReload_active = true;
	return animPosition;
}

/*
take the latestnode-ANIMATION_WIDTH->latestnode steps from the main graph
take the rest from the faded graph
combine, season to taste

this is where optimisation is most important
darken_animation is ~25% of cpu activity
brighten_BBs is ~5%
*/
void thread_graph_data::animate_latest(float fadeRate)
{
	if (bbsequence.empty()) return;
	darken_animation(fadeRate);

	sequenceIndex = bbsequence.size() - 1;
	
	firstAnimatedBB = lastAnimatedBB;
	lastAnimatedBB = sequenceIndex;

	lastAnimatedBB = brighten_BBs();

	set_node_alpha(latest_active_node->index, animnodesdata, getPulseAlpha());
	//live process always at least has pulsing active node
	needVBOReload_active = true;
}

//replay
void thread_graph_data::update_animation_render(float fadeRate)
{
	darken_animation(fadeRate);

	firstAnimatedBB = sequenceIndex - ANIMATION_WIDTH;
	brighten_BBs();
}

//find the node corresponding to the lateset instruction in the animation sequence
unsigned int thread_graph_data::derive_anim_node()
{

	obtainMutex(animationListsMutex, 1022);
	pair<MEM_ADDRESS, int> addr_size = bbsequence.at(sequenceIndex);
	BLOCK_IDENTIFIER blockID = mutationSequence.at(sequenceIndex);
	dropMutex(animationListsMutex);

	MEM_ADDRESS blockAddr = addr_size.first;
	int remainingInstructions = blockInstruction;
	
	INS_DATA *target_ins = getDisassemblyBlock(blockAddr, blockID, piddata->disassemblyMutex, &piddata->blocklist, &terminationFlag)->at(blockInstruction);
	return target_ins->threadvertIdx.at(tid);
}

void thread_graph_data::reset_mainlines() 
{
	mainlinedata->reset();
	animlinedata->reset();
}

//find the edge represented by pair of nodes 'edge'
//false if not found
//true if found + edge data placed in edged
bool thread_graph_data::edge_exists(NODEPAIR edge, edge_data **edged)
{
	obtainMutex(edMutex, 1023);
	EDGEMAP::iterator edgeit = edgeDict.find(edge);
	dropMutex(edMutex);

	if (edgeit == edgeDict.end()) return false;

	*edged = &edgeit->second;
	return true;
}

inline edge_data *thread_graph_data::get_edge(NODEPAIR edgePair)
{
	obtainMutex(edMutex, 1024);
	edge_data *linkingEdge = &edgeDict.at(edgePair);
	dropMutex(edMutex);
	return linkingEdge;
}

//linker error if we make this inline too
edge_data * thread_graph_data::get_edge(int edgeindex)
{
	obtainMutex(edMutex, 1024);
	edge_data *linkingEdge = &edgeDict.at(edgeList.at(edgeindex));
	dropMutex(edMutex);
	return linkingEdge;
}

inline node_data *thread_graph_data::get_node(unsigned int index)
{
	obtainMutex(nodeLMutex, 1031);
	node_data *n = &nodeList.at(index);
	dropMutex(nodeLMutex);
	return n;
}

int thread_graph_data::render_edge(NODEPAIR ePair, GRAPH_DISPLAY_DATA *edgedata, map<int, ALLEGRO_COLOR> *lineColours,
	ALLEGRO_COLOR *forceColour, bool preview)
{
	node_data *sourceNode = get_node(ePair.first);
	node_data *targetNode = get_node(ePair.second);
	edge_data *e = get_edge(ePair);
	if (!e) return 0;

	MULTIPLIERS *scaling;
	if (preview)
		scaling = p_scalefactors;
	else
		scaling = m_scalefactors;

	FCOORD srcc = sourceNode->sphereCoordB(scaling, 0);
	FCOORD targc = targetNode->sphereCoordB(scaling, 0);

	int arraypos = 0;
	ALLEGRO_COLOR *edgeColour;
	if (forceColour) edgeColour = forceColour;
	else
	{
		assert((size_t)e->edgeClass < lineColours->size());
		edgeColour = &lineColours->at(e->edgeClass);
	}

	int vertsDrawn = drawCurve(edgedata, &srcc, &targc,
		edgeColour, e->edgeClass, scaling, &arraypos);

	if (!preview)
	{
		e->vertSize = vertsDrawn;
		e->arraypos = arraypos;
	}

	return 1;

}

VCOORD *thread_graph_data::get_active_node_coord()
{
	if (nodeList.empty()) return NULL;

	obtainMutex(animationListsMutex, 1025);
	VCOORD *result = &latest_active_node_coord;
	dropMutex(animationListsMutex);

	return result;
}

thread_graph_data::thread_graph_data(PROCESS_DATA *processdata, unsigned int threadID)
{
	piddata = processdata;
	pid = piddata->PID;
	tid = threadID;

	mainnodesdata = new GRAPH_DISPLAY_DATA();
	mainlinedata = new GRAPH_DISPLAY_DATA();

	animlinedata = new GRAPH_DISPLAY_DATA();
	animnodesdata = new GRAPH_DISPLAY_DATA();

	previewlines = new GRAPH_DISPLAY_DATA(true);
	previewnodes = new GRAPH_DISPLAY_DATA(true);

	conditionallines = new GRAPH_DISPLAY_DATA();
	conditionalnodes = new GRAPH_DISPLAY_DATA();
	heatmaplines = new GRAPH_DISPLAY_DATA();
	needVBOReload_conditional = true;
	needVBOReload_heatmap = true;
	needVBOReload_main = true;
	needVBOReload_preview = true;
	m_scalefactors = new MULTIPLIERS;
	p_scalefactors = new MULTIPLIERS;
	p_scalefactors->HEDGESEP = 0.15;
	p_scalefactors->VEDGESEP = 0.11;
	p_scalefactors->radius = 200;
	p_scalefactors->baseRadius = 200;
}


void thread_graph_data::start_edgeL_iteration(EDGELIST::iterator *edgeIt, EDGELIST::iterator *edgeEnd)
{
	obtainMutex(edMutex, 1026);
	*edgeIt = edgeList.begin();
	*edgeEnd = edgeList.end();
}

void thread_graph_data::stop_edgeL_iteration()
{
	dropMutex(edMutex);
}

void thread_graph_data::start_edgeD_iteration(EDGEMAP::iterator *edgeIt,
	EDGEMAP::iterator *edgeEnd)
{
	obtainMutex(edMutex, 1027);
	*edgeIt = edgeDict.begin();
	*edgeEnd = edgeDict.end();
}

void thread_graph_data::display_highlight_lines(vector<node_data *> *nodePtrList, ALLEGRO_COLOR *colour, int lengthModifier)
{
	int nodeListSize = nodePtrList->size();
	for (int nodeIdx = 0; nodeIdx != nodeListSize; ++nodeIdx)
		drawHighlight(&nodePtrList->at(nodeIdx)->vcoord, m_scalefactors, colour, lengthModifier);
}

void thread_graph_data::insert_node(int targVertID, node_data node)
{
	if (!nodeList.empty()) assert(targVertID == nodeList.back().index + 1);
	obtainMutex(nodeLMutex, 1028);
	nodeList.push_back(node);
	dropMutex(nodeLMutex);
}

void thread_graph_data::stop_edgeD_iteration()
{
	dropMutex(edMutex);
}

void thread_graph_data::add_edge(edge_data e, NODEPAIR edgePair)
{
	obtainMutex(edMutex, 1029);
	edgeDict.insert(make_pair(edgePair, e));
	edgeList.push_back(edgePair);
	dropMutex(edMutex);
}

thread_graph_data::~thread_graph_data()
{
	delete animlinedata;
	delete animnodesdata;
}


void thread_graph_data::set_edge_alpha(NODEPAIR eIdx, GRAPH_DISPLAY_DATA *edgesdata, float alpha)
{
	if (!edgesdata->get_numVerts()) return;
	edge_data *e = get_edge(eIdx);
	if (!e) return;
	const unsigned int bufsize = edgesdata->col_buf_capacity_floats();
	GLfloat *colarray = &edgesdata->acquire_col()->at(0);
	for (unsigned int i = 0; i < e->vertSize; ++i)
	{
		unsigned int bufIndex = e->arraypos + i*COLELEMS + AOFF;
		if (bufIndex > bufsize) break;
		colarray[bufIndex] = alpha;
	}
	edgesdata->release_col();
}

void thread_graph_data::set_node_alpha(unsigned int nIdx, GRAPH_DISPLAY_DATA *nodesdata, float alpha)
{
	unsigned int bufIndex = nIdx*COLELEMS + AOFF;
	if (bufIndex >= nodesdata->col_buf_capacity_floats()) return;
	GLfloat *colarray = &nodesdata->acquire_col()->at(0);
	colarray[bufIndex] = alpha;
	nodesdata->release_col();
}

void thread_graph_data::assign_modpath(PROCESS_DATA *pidinfo) 
{
	baseMod = get_node(0)->nodeMod;
	if (baseMod >= (int)pidinfo->modpaths.size()) return;
	string longmodPath = pidinfo->modpaths.at(baseMod);

	if (longmodPath.size() > MAX_DIFF_PATH_LENGTH)
		modPath = ".."+longmodPath.substr(longmodPath.size() - MAX_DIFF_PATH_LENGTH, longmodPath.size());
	else
		modPath = longmodPath;
}

bool thread_graph_data::serialise(ofstream *file)
{
	*file << "TID" << tid << "{";

	*file << "N{";
	vector<node_data>::iterator vertit = nodeList.begin();
	for (; vertit != nodeList.end(); ++vertit)
		vertit->serialise(file);
	*file << "}N,";

	*file << "D{";
	EDGELIST::iterator edgeLIt = edgeList.begin();
	for (; edgeLIt != edgeList.end(); ++edgeLIt)
	{
		edge_data *e = get_edge(*edgeLIt);
		e->serialise(file, edgeLIt->first, edgeLIt->second);
	}
	*file << "}D,";

	*file << "E{";
	vector<int>::iterator externit = externList.begin();
	for (; externit != externList.end(); ++externit)
		*file << *externit << ",";
	*file << "}E,";

	//S for stats
	*file << "S{" 
		<< maxA << ","
		<< maxB << ","
		<< maxWeight << ","
		<< loopCounter << ","
		<< baseMod << ","
		<< totalInstructions
		<< "}S,";

	*file << "A{";
	obtainMutex(animationListsMutex, 1030);
	for (unsigned long i = 0; i < bbsequence.size(); ++i)
	{
		pair<MEM_ADDRESS, int> seq_size = bbsequence.at(i);
		int mutation = mutationSequence.at(i);

		*file << seq_size.first << "," << seq_size.second << ","
			<< mutationSequence[i] << ","
			<< loopStateList[i].first << ",";
		if (loopStateList[i].first )
			*file << loopStateList[i].second << ",";
	}
	dropMutex(animationListsMutex);
	*file << "}A,";

	*file << "C{";
	map<unsigned int, EDGELIST>::iterator externCallIt;
	EDGELIST::iterator callListIt;
	for (externCallIt = externCallSequence.begin(); externCallIt != externCallSequence.end(); ++externCallIt)
	{
		//TODO: base64 encode args + decode on load
		EDGELIST *callList = &externCallIt->second;
		*file << externCallIt->first << "," << callList->size() << ",";

		for (callListIt = callList->begin(); callListIt != callList->end(); ++callListIt)
			*file << callListIt->first << "," << callListIt->second << ",";
	}
	*file << "}C,";

	*file << "}";
	return true;
}

bool thread_graph_data::loadEdgeDict(ifstream *file)
{
	string index_s, weight_s, source_s, target_s, edgeclass_s;
	int source, target;
	while (true)
	{
		edge_data *edge = new edge_data;
		getline(*file, weight_s, ',');
		if (!caught_stol(weight_s, (unsigned long *)&edge->weight, 10))
		{
			if (weight_s == string("}D"))
				return true;
			else
				return false;
		}
		getline(*file, source_s, ',');
		if (!caught_stoi(source_s, (int *)&source, 10)) return false;
		getline(*file, target_s, ',');
		if (!caught_stoi(target_s, (int *)&target, 10)) return false;
		getline(*file, edgeclass_s, '@');
		edge->edgeClass = edgeclass_s.c_str()[0];
		NODEPAIR stpair = make_pair(source, target);
		add_edge(*edge, stpair);
	}
	return false;
}

bool thread_graph_data::loadExterns(ifstream *file)
{
	string endtag;
	getline(*file, endtag, '{');
	if (endtag.c_str()[0] != 'E') return false;

	int index;
	string address_s, index_s;

	while (true) {
		getline(*file, index_s, ',');
		if (!caught_stoi(index_s, (int *)&index, 10))
		{
			if (index_s == string("}E")) return true;
			return false;
		}
		externList.push_back(index);
	}
}

bool thread_graph_data::unserialise(ifstream *file, map <MEM_ADDRESS, INSLIST> *disassembly)
{
	if (!loadNodes(file, disassembly)) { cerr << "[rgat]ERROR:Node load failed"<<endl;  return false; }
	if (!loadEdgeDict(file)) { cerr << "[rgat]ERROR:EdgeD load failed" << endl; return false; }
	if (!loadExterns(file)) { cerr << "[rgat]ERROR:Externs load failed" << endl;  return false; }
	if (!loadStats(file)) { cerr << "[rgat]ERROR:Stats load failed" << endl;  return false; }
	if (!loadAnimationData(file)) { cerr << "[rgat]ERROR:Animation load failed" << endl;  return false; }
	if (!loadCallSequence(file)) { cerr << "[rgat]ERROR:Call sequence load failed" << endl; return false; }

	dirtyHeatmap = true;
	return true;
}

bool thread_graph_data::loadCallSequence(ifstream *file)
{
	string endtag;
	getline(*file, endtag, '{');
	if (endtag.c_str()[0] != 'C') return false;

	string value_s;
	int nodeIdx, listSize;
	NODEPAIR callPair;
	while (true)
	{
		getline(*file, value_s, ',');
		if (value_s == "}C") return true;

		EDGELIST callList;
		if (!caught_stoi(value_s, &nodeIdx, 10)) break;
		getline(*file, value_s, ',');
		if (!caught_stoi(value_s, &listSize, 10)) break;
		for (int i = 0; i < listSize; ++i)
		{
			getline(*file, value_s, ',');
			if (!caught_stoi(value_s, &callPair.first, 10)) break;
			getline(*file, value_s, ',');
			if (!caught_stoi(value_s, &callPair.second, 10)) break;
			callList.push_back(callPair);
		}
		externCallSequence.emplace(nodeIdx, callList);
	}
	return false;
}

bool thread_graph_data::loadNodes(ifstream *file, map <MEM_ADDRESS, INSLIST> *disassembly)
{

	if (!verifyTag(file, tag_START, 'N')) {
		cerr << "[rgat]Bad node data" << endl;
		return false;
	}
	string endtag("}N,D");
	string value_s;
	while (true)
	{
		node_data *n = new node_data;
		
		getline(*file, value_s, '{');
		if (value_s == endtag) return true;

		if (!caught_stoi(value_s, (int *)&n->index, 10))
			return false;
		getline(*file, value_s, ',');
		if (!caught_stoi(value_s, (int *)&n->vcoord.a, 10))
			return false;
		getline(*file, value_s, ',');
		if (!caught_stoi(value_s, (int *)&n->vcoord.b, 10))
			return false;
		getline(*file, value_s, ',');
		if (!caught_stoi(value_s, (int *)&n->vcoord.bMod, 10))
			return false;
		getline(*file, value_s, ',');
		if (!caught_stoi(value_s, (int *)&n->conditional, 10))
			return false;
		getline(*file, value_s, ',');
		if (!caught_stoi(value_s, &n->nodeMod, 10))
			return false;
		getline(*file, value_s, ',');
		if (!caught_stol(value_s, &n->address, 10))
			return false;

		getline(*file, value_s, ',');
		if (value_s.at(0) == '0')
		{
			n->external = false;

			getline(*file, value_s, '}');
			if (!caught_stoi(value_s, (int *)&n->mutation, 10))
				return false;
			n->ins = disassembly->at(n->address).at(n->mutation);
			insert_node(n->index, *n);
			continue;
		}

		n->external = true;

		int numCalls;
		getline(*file, value_s, '{');
		if (!caught_stoi(value_s, &numCalls, 10))
			return false;

		vector <ARGLIST> funcCalls;
		for (int i = 0; i < numCalls; ++i)
		{
			int argidx, numArgs = 0;
			getline(*file, value_s, ',');
			if (!caught_stoi(value_s, &numArgs, 10))
				return false;
			ARGLIST callArgs;

			for (int i = 0; i < numArgs; ++i)
			{
				getline(*file, value_s, ',');
				if (!caught_stoi(value_s, &argidx, 10))
					return false;
				getline(*file, value_s, ',');
				string decodedarg = base64_decode(value_s);
				callArgs.push_back(make_pair(argidx, decodedarg));
			}
			if (!callArgs.empty())
				funcCalls.push_back(callArgs);
		}
		if (!funcCalls.empty())
			n->funcargs = funcCalls;
		file->seekg(1, ios::cur); //skip closing brace
		insert_node(n->index, *n);
	}
}
//todo: move this and the other graph loads to graph class!
bool thread_graph_data::loadStats(ifstream *file)
{
	string endtag;
	getline(*file, endtag, '{');
	if (endtag.c_str()[0] != 'S') return false;

	string value_s;
	getline(*file, value_s, ',');
	if (!caught_stoi(value_s, &maxA, 10)) return false;
	getline(*file, value_s, ',');
	if (!caught_stoi(value_s, &maxB, 10)) return false;
	getline(*file, value_s, ',');
	if (!caught_stol(value_s, (unsigned long*)&maxWeight, 10)) return false;
	getline(*file, value_s, ',');
	if (!caught_stoi(value_s, (int *)&loopCounter, 10)) return false;
	getline(*file, value_s, ',');
	if (!caught_stoi(value_s, (int *)&baseMod, 10)) return false;
	getline(*file, value_s, '}');
	if (!caught_stol(value_s, (unsigned long*)&totalInstructions, 10)) return false;

	getline(*file, endtag, ',');
	if (endtag.c_str()[0] != 'S') return false;
	return true;
}

bool thread_graph_data::loadAnimationData(ifstream *file)
{
	string endtag;
	getline(*file, endtag, '{');
	if (endtag.c_str()[0] != 'A') return false;

	string sequence_s, size_s, mutation_s, loopstateIdx_s, loopstateIts_s;
	pair<MEM_ADDRESS, int> seq_size;
	pair<unsigned int, unsigned long> loopstateIdx_Its;
	BLOCK_IDENTIFIER blockID;

	while (true)
	{
		getline(*file, sequence_s, ',');
		if (sequence_s == "}A") 
		{ 
			//no trace data, assume graph was created in basic mode
			if (bbsequence.empty())
				basic = true;
			return true; 
		}
		if (!caught_stol(sequence_s, &seq_size.first, 10)) break;
		getline(*file, size_s, ',');
		if (!caught_stoi(size_s, &seq_size.second, 10)) break;
		bbsequence.push_back(seq_size);

		getline(*file, mutation_s, ',');
		if (!caught_stol(mutation_s, &blockID, 10)) break;

		mutationSequence.push_back(blockID);

		getline(*file, loopstateIdx_s, ',');
		if (!caught_stoi(loopstateIdx_s, (int *)&loopstateIdx_Its.first, 10)) break;
		if (loopstateIdx_Its.first)
		{
			getline(*file, loopstateIts_s, ',');
			if (!caught_stol(loopstateIts_s, &loopstateIdx_Its.second, 10)) break;
		}
		else
			loopstateIdx_Its.second = 0xbad;

		loopStateList.push_back(loopstateIdx_Its);
	}
	return false;
}