#include "stdafx.h"
#include "plotted_graph.h"
#include "graphicsMaths.h"
#include "rendering.h"
#include "GUIManagement.h"


plotted_graph::plotted_graph(proto_graph *protoGraph, vector<ALLEGRO_COLOR> *graphColoursPtr)
{
		pid = protoGraph->get_piddata()->PID;
		tid = protoGraph->get_TID();

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

		main_scalefactors = new GRAPH_SCALE;
		preview_scalefactors = new GRAPH_SCALE;

		internalProtoGraph = protoGraph;
		graphColours = graphColoursPtr;

#ifdef XP_COMPATIBLE
		nodeCoordMutex = CreateMutex(NULL, FALSE, NULL);
		threadReferenceMutex = CreateMutex(NULL, FALSE, NULL);
#endif
}

#define DBG_THREADS 2

plotted_graph::~plotted_graph()
{
	dying = true;
	setGraphBusy(true);

#ifdef XP_COMPATIBLE
	while (threadRefs) Sleep(10);
	obtainMutex(threadReferenceMutex);
#else
	AcquireSRWLockExclusive(&threadReferenceLock);
#endif

	
	
	delete animlinedata;
	delete animnodesdata;
	
#ifdef XP_COMPATIBLE
	CloseHandle(nodeCoordMutex);
	CloseHandle(threadReferenceMutex);
#endif
}

bool plotted_graph::increase_thread_references()
{
	if (dying) return false;
#ifdef XP_COMPATIBLE
	//todo xp
#else
	AcquireSRWLockShared(&threadReferenceLock);
#endif
	++threadReferences;
	return true;
	
}

void plotted_graph::decrease_thread_references()
{
	if (threadReferences < 1) return;
#ifdef XP_COMPATIBLE
	//todo xp
#else
	ReleaseSRWLockShared(&threadReferenceLock);
#endif
	--threadReferences;
}



//tracking how big the graph gets
void plotted_graph::updateStats(int a, int b, int c)
{
	//the extra work of 2xabs() happens so rarely that its worth avoiding
	//the stack allocations of a variable every call
	if (abs(a) > maxA) maxA = abs(a);
	if (abs(b) > maxB) maxB = abs(b);
}

bool plotted_graph::isGraphBusy()
{
	bool busy = (WaitForSingleObject(graphwritingMutex, 0) == WAIT_TIMEOUT);
	if (!busy)
		ReleaseMutex(graphwritingMutex);
	return busy;
}

bool plotted_graph::setGraphBusy(bool set)
{
	if (dying)
		return false;

	if (set) {
		DWORD res = WaitForSingleObject(graphwritingMutex, 1000);
		if (dying)
		{
			ReleaseMutex(graphwritingMutex);
			return false;
		}

		if (res == WAIT_TIMEOUT)
			cerr << "[rgat]Timeout waiting for release of graph " << tid << endl;
		assert(res != WAIT_TIMEOUT);
	}
	else ReleaseMutex(graphwritingMutex);
	return true;
}

void plotted_graph::acquire_nodecoord_read()
{
#ifdef XP_COMPATIBLE
	obtainMutex(nodeCoordMutex, 1107);
#else
	AcquireSRWLockShared(&nodeCoordLock);
#endif
}

void plotted_graph::acquire_nodecoord_write()
{
#ifdef XP_COMPATIBLE
	obtainMutex(nodeCoordMutex, 1107);
#else
	AcquireSRWLockExclusive(&nodeCoordLock);
#endif
}

void plotted_graph::release_nodecoord_read()
{
#ifdef XP_COMPATIBLE
	dropMutex(nodeCoordMutex, 1107);
#else
	ReleaseSRWLockShared(&nodeCoordLock);
#endif
}

void plotted_graph::release_nodecoord_write()
{
#ifdef XP_COMPATIBLE
	dropMutex(nodeCoordMutex, 1107);
#else
	ReleaseSRWLockExclusive(&nodeCoordLock);
#endif
}

//display live or animated graph with active areas on faded areas
void plotted_graph::display_active(bool showNodes, bool showEdges)
{
	GRAPH_DISPLAY_DATA *nodesdata = animnodesdata;
	GRAPH_DISPLAY_DATA *linedata = animlinedata;

	//reload buffers if needed and not being written
	if (needVBOReload_active && !isGraphBusy())
	{
		if (!setGraphBusy(true))
			return;
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
void plotted_graph::display_static(bool showNodes, bool showEdges)
{
	if (needVBOReload_main && !isGraphBusy())
	{
		if (!setGraphBusy(true))
			return;
		//lock for reading?
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
void plotted_graph::extend_faded_edges()
{

	vector<GLfloat> *animecol = animlinedata->acquire_col_write();
	vector<GLfloat> *mainecol = mainlinedata->acquire_col_write();
	unsigned int drawnVerts = mainlinedata->get_numVerts();
	unsigned int animatedVerts = animlinedata->get_numVerts();

	assert(drawnVerts >= animatedVerts);
	int pendingVerts = drawnVerts - animatedVerts;
	if (!pendingVerts) return;

	//copy the colours over
	unsigned int fadedIndex = animlinedata->get_numVerts() *COLELEMS;
	vector<float>::iterator mainEIt = mainecol->begin();
	advance(mainEIt, fadedIndex);
	animecol->insert(animecol->end(), mainEIt, mainecol->end());
	mainlinedata->release_col_write();

	//fade new colours alpha
	unsigned int index2 = (animlinedata->get_numVerts() *COLELEMS);
	unsigned int end = drawnVerts*COLELEMS;
	for (; index2 < end; index2 += COLELEMS)
		animecol->at(index2 + AOFF) = 0.01; //TODO: config file entry for anim inactive

	animlinedata->set_numVerts(drawnVerts);
	animlinedata->release_col_write();
}

//create edges in opengl buffers
int plotted_graph::render_new_edges(bool doResize)
{
	GRAPH_DISPLAY_DATA *lines = get_mainlines();
	EDGELIST::iterator edgeIt;
	int edgesDrawn = 0;

	internalProtoGraph->getEdgeReadLock();
	if (doResize)
	{
		reset_mainlines();
		lines = get_mainlines();
		edgeIt = internalProtoGraph->edgeList.begin();
	}
	else
	{
		edgeIt = internalProtoGraph->edgeList.begin();
		std::advance(edgeIt, lines->get_renderedEdges());
	}

	EDGELIST::iterator end = internalProtoGraph->edgeList.end();
	if (edgeIt != end)
		needVBOReload_main = true;

	for (; edgeIt != end; ++edgeIt)
	{
		if (edgeIt->first >= mainnodesdata->get_numVerts())
		{
			node_data *n;
			n = internalProtoGraph->safe_get_node(edgeIt->first);
			add_node(n, &lastMainNode, mainnodesdata, animnodesdata, main_scalefactors);
		}

		if (edgeIt->second >= mainnodesdata->get_numVerts())
		{
			edge_data *e = &internalProtoGraph->edgeDict.at(*edgeIt);
			if (e->edgeClass == eEdgeException)
				lastPreviewNode.lastVertType = eNodeException;

			node_data *n = internalProtoGraph->safe_get_node(edgeIt->second);
			add_node(n, &lastMainNode, mainnodesdata, animnodesdata, main_scalefactors);
		}

		if (!render_edge(*edgeIt, lines, 0, false, false))
		{
			internalProtoGraph->dropEdgeReadLock();
			return edgesDrawn;
		}

		++edgesDrawn;

		extend_faded_edges();
		lines->inc_edgesRendered();
	}
	internalProtoGraph->dropEdgeReadLock();
	return edgesDrawn;
}

void plotted_graph::reset_animation()
{
	//deactivate any active nodes/edges
	clear_active();

	//darken any active drawn nodes
	if (!internalProtoGraph->nodeList.empty())
	{
		internalProtoGraph->set_active_node(0);
		darken_fading(1.0);
		darken_fading(1.0);
	}

	assert(fadingAnimEdges.empty() && fadingAnimNodes.empty());

	animInstructionIndex = 0;
	lastAnimatedNode = 0;
	animationIndex = 0;

	newAnimEdgeTimes.clear();
	newAnimNodeTimes.clear();
	activeAnimEdgeTimes.clear();
	activeAnimNodeTimes.clear();
	unchainedWaitFrames = 0;
	currentUnchainedBlocks.clear();
	animBuildingLoop = false;
}



void plotted_graph::set_node_alpha(unsigned int nIdx, GRAPH_DISPLAY_DATA *nodesdata, float alpha)
{
	unsigned int bufIndex = nIdx*COLELEMS + AOFF;
	if (bufIndex >= nodesdata->col_buf_capacity_floats()) return;

	GLfloat *colarray = &nodesdata->acquire_col_write()->at(0);
	colarray[bufIndex] = alpha;
	nodesdata->release_col_write();
}

//fill nodelist with with all nodes corresponding to basic block (blockAddr/blockID) on the graph
bool plotted_graph::fill_block_nodelist(MEM_ADDRESS blockAddr, BLOCK_IDENTIFIER blockID, vector <NODEINDEX> *nodelist)
{
	PROCESS_DATA *piddata = internalProtoGraph->get_piddata();
	INSLIST * block = getDisassemblyBlock(blockAddr, blockID, piddata, &internalProtoGraph->terminationFlag);
	if (!block)
	{
		piddata->getExternlistReadLock();
		EDGELIST callvs = piddata->externdict.at(blockAddr)->thread_callers.at(tid);

		EDGELIST::iterator callvsIt = callvs.begin();
		for (; callvsIt != callvs.end(); ++callvsIt) //run through each function with a new arg
		{
			if (callvsIt->first == lastAnimatedNode)
				nodelist->push_back(callvsIt->second);
		}
		piddata->dropExternlistReadLock();
		//todo: BUG! heap corruption can happen after here
		return true;
	}

	INSLIST::iterator blockIt = block->begin();
	for (; blockIt != block->end(); ++blockIt)
	{
		INS_DATA* activeIns = *blockIt;
		unordered_map<PID_TID, NODEINDEX>::iterator vertIt = activeIns->threadvertIdx.find(tid);
		if (vertIt == activeIns->threadvertIdx.end())
			return false;
		nodelist->push_back(vertIt->second);
	}
	return true;
}

//deactivate persistent areas of animation (where we are waiting for them to finish executing)
void plotted_graph::remove_unchained_from_animation()
{
	//get rid of any nodes/edges waiting to be activated
	map <NODEINDEX, int>::iterator newNodeIt = newAnimNodeTimes.begin();
	while (newNodeIt != newAnimNodeTimes.end() && !newAnimNodeTimes.empty())
		if (newNodeIt->second == KEEP_BRIGHT)
			newNodeIt = newAnimNodeTimes.erase(newNodeIt);
		else
			++newNodeIt;

	map <NODEPAIR, int>::iterator newEdgeIt = newAnimEdgeTimes.begin();
	while (newEdgeIt != newAnimEdgeTimes.end() && !newAnimEdgeTimes.empty())
		if (newEdgeIt->second == KEEP_BRIGHT)
			newEdgeIt = newAnimEdgeTimes.erase(newEdgeIt);
		else
			++newEdgeIt;

	//get rid of any nodes/externals/edges that have already been activated
	map <unsigned int, int>::iterator nodeIt = activeAnimNodeTimes.begin();
	for (; nodeIt != activeAnimNodeTimes.end(); ++nodeIt)
		if (nodeIt->second == KEEP_BRIGHT)
			nodeIt->second = 0;

	obtainMutex(internalProtoGraph->externGuardMutex, 2019);
	map <NODEINDEX, EXTTEXT>::iterator activeExternIt = activeExternTimes.begin();
	for (; activeExternIt != activeExternTimes.end(); ++activeExternIt)
		if (activeExternIt->second.framesRemaining == KEEP_BRIGHT)
			activeExternIt->second.framesRemaining = (int)(EXTERN_LIFETIME_FRAMES / 2);
	dropMutex(internalProtoGraph->externGuardMutex);

	map <NODEPAIR, int>::iterator edgeIt = activeAnimEdgeTimes.begin();
	for (; edgeIt != activeAnimEdgeTimes.end(); ++edgeIt)
		if (edgeIt->second == KEEP_BRIGHT)
			edgeIt->second = 0;
}

void plotted_graph::end_unchained(ANIMATIONENTRY *entry)
{
	currentUnchainedBlocks.clear();
	INSLIST* firstChainedBlock = getDisassemblyBlock(entry->blockAddr, entry->blockID,
		internalProtoGraph->get_piddata(), &internalProtoGraph->terminationFlag);
	NODEINDEX firstChainedNode = firstChainedBlock->back()->threadvertIdx.at(tid);

	lastAnimatedNode = firstChainedNode;
}

void plotted_graph::brighten_node_list(ANIMATIONENTRY *entry, int brightTime, vector <NODEINDEX> *nodeIDList)
{
	int instructionCount = 0;
	vector <NODEINDEX>::iterator nodeIt = nodeIDList->begin();

	for (; nodeIt != nodeIDList->end(); ++nodeIt)
	{
		NODEINDEX nodeIdx = *nodeIt;
		newAnimNodeTimes[nodeIdx] = brightTime;

		if (internalProtoGraph->safe_get_node(nodeIdx)->external)
		{
			if (brightTime == KEEP_BRIGHT)
				newExternTimes[make_pair(nodeIdx, entry->callCount)] = KEEP_BRIGHT;
			else
				newExternTimes[make_pair(nodeIdx, entry->callCount)] = EXTERN_LIFETIME_FRAMES;
		}

		if ((animationIndex != 0) && //cant draw edge to first node in animation
									 //edge to unchained area is not part of unchained area
			!(entry->entryType == ANIM_UNCHAINED && nodeIt == nodeIDList->begin()))
		{
			NODEPAIR edge = make_pair(lastAnimatedNode, nodeIdx);
			if (internalProtoGraph->edge_exists(edge, 0))
				newAnimEdgeTimes[edge] = brightTime;
			//else
			//	cout << "bad edge " << edge.first << "," << edge.second << endl;
			/*
			A bad edge is expected here if the user has forced an animation skip using the slider
			Shouldn't really happen otherwise but does after change to external edge creation
			Doesn't seem to affect the animation in a meaninful way but it's not good code
			*/

		}
		//cout << "lastanimnode: " << nodeIdx << endl;
		lastAnimatedNode = nodeIdx;

		++instructionCount;
		if ((entry->entryType == ANIM_EXEC_EXCEPTION) && (instructionCount == (entry->count + 1))) break;
	}
}

void plotted_graph::brighten_next_block_edge(ANIMATIONENTRY *entry, int brightTime)
{
		PROCESS_DATA *piddata = internalProtoGraph->get_piddata();
		NODEINDEX nextNode;
		NODEPAIR linkingPair;
		if (piddata->externdict.count(entry->targetAddr))
		{
			EDGELIST callers = piddata->externdict.at(entry->targetAddr)->thread_callers.at(tid);
			EDGELIST::iterator callIt = callers.begin();
			for (; callIt != callers.end(); ++callIt)
			{
				if (callIt->first == lastAnimatedNode)
				{
					nextNode = callIt->second;
					linkingPair = make_pair(lastAnimatedNode, nextNode);
					break;
				}
			}
			if (callIt == callers.end())
			{
				cerr << "[rgat]Error: Caller for " << hex << entry->targetAddr << " not found" << endl;
				assert(0);
			}
		}
		else
		{
			INSLIST* nextBlock = getDisassemblyBlock(entry->targetAddr, entry->targetID, piddata, &internalProtoGraph->terminationFlag);
			INS_DATA* nextIns = nextBlock->front();
			unordered_map<PID_TID, NODEINDEX>::iterator threadVIt = nextIns->threadvertIdx.find(tid);
			if (threadVIt == nextIns->threadvertIdx.end())
				return;
			nextNode = threadVIt->second;
			linkingPair = make_pair(lastAnimatedNode, nextNode);
		}


		if (!internalProtoGraph->edge_exists(linkingPair, 0))
			return;

		newAnimEdgeTimes[linkingPair] = brightTime;
}

void plotted_graph::process_live_update()
{
	obtainMutex(internalProtoGraph->animationListsMutex, 6210);
	ANIMATIONENTRY entry = internalProtoGraph->animUpdates.front();
	dropMutex(internalProtoGraph->animationListsMutex);

	if (entry.entryType == ANIM_LOOP_LAST)
	{
		removeEntryFromQueue();
		return;
	}

	if (entry.entryType == ANIM_UNCHAINED_RESULTS)
	{
		remove_unchained_from_animation();

		removeEntryFromQueue();
		return;
	}

	NODEINDEX backupLastAnimNode = lastAnimatedNode;
	if (entry.entryType == ANIM_UNCHAINED_DONE)
	{
		end_unchained(&entry);
		removeEntryFromQueue();
		return;
	}

	int brightTime;
	if (entry.entryType == ANIM_UNCHAINED)
	{
		currentUnchainedBlocks.push_back(entry);
		brightTime = KEEP_BRIGHT;
	}
	else
		brightTime = 0;

	//break if block not rendered yet
	vector <NODEINDEX> nodeIDList;
	if (!fill_block_nodelist(entry.blockAddr, entry.blockID, &nodeIDList))
	{
		//expect to get an incomplete block with exception or animation attempt before static rendering
		if ((entry.entryType != ANIM_EXEC_EXCEPTION) ||	(nodeIDList.size() < entry.count)) 
			return;
	}

	//add all the nodes+edges in the block to the brightening list
	brighten_node_list(&entry, brightTime, &nodeIDList);

	//also add brighten edge to next unchained block
	if (entry.entryType == ANIM_UNCHAINED)
		brighten_next_block_edge(&entry, brightTime);

	removeEntryFromQueue();
}

void plotted_graph::process_live_animation_updates()
{
	if (internalProtoGraph->animUpdates.empty()) return;

	int updateLimit = 150; //too many updates at a time damages interactivity
	while (!internalProtoGraph->animUpdates.empty() && updateLimit--)
	{
		process_live_update();
	}

	if (!updateLimit)
		cerr << "[rgat]Warning: " << internalProtoGraph->animUpdates.size() << " entry animation backlog" << endl;
}


#define ASSUME_INS_PER_BLOCK 10
//tries to make animation pause for long enough to represent heavy cpu usage but
//not too long to make it irritating (still a bit janky with very small traces though)
//if program is 1m instructions and takes 10s to execute then a 50k block should wait for ~.5s
unsigned long plotted_graph::calculate_wait_frames(unsigned int stepSize, unsigned long blockInstructions)
{
	//assume 10 instructions per step/frame
	unsigned long frames = (internalProtoGraph->totalInstructions / ASSUME_INS_PER_BLOCK) / stepSize;

	float proportion = (float)blockInstructions / internalProtoGraph->totalInstructions;
	unsigned long waitFrames = proportion*frames;
	return waitFrames;
}

void plotted_graph::process_replay_update(int stepSize)
{
	ANIMATIONENTRY entry = internalProtoGraph->savedAnimationData.at(animationIndex);

	//unchained area finished, stop highlighting it
	if (entry.entryType == ANIM_UNCHAINED_RESULTS)
	{
		PROCESS_DATA *piddata = internalProtoGraph->get_piddata();
		INSLIST *block = getDisassemblyBlock(entry.blockAddr, entry.blockID, piddata, &internalProtoGraph->terminationFlag);
		unchainedWaitFrames += calculate_wait_frames(stepSize, entry.count*block->size());

		unsigned int maxWait = (unsigned int)((float)maxWaitFrames / (float)stepSize);
		if (unchainedWaitFrames > maxWait)
			unchainedWaitFrames = maxWait;
		return;
	}

	//all consecutive unchained areas finished, wait until animation paused appropriate frames
	if (entry.entryType == ANIM_UNCHAINED_DONE)
	{
		if (unchainedWaitFrames-- > 1) return;

		remove_unchained_from_animation();
		end_unchained(&entry);
		return;
	}

	if (entry.entryType == ANIM_LOOP_LAST)
	{
		if (unchainedWaitFrames-- > 1) return;

		remove_unchained_from_animation();
		currentUnchainedBlocks.clear();
		animBuildingLoop = false;
		return;
	}

	int brightTime;
	if (entry.entryType == ANIM_UNCHAINED || animBuildingLoop)
	{
		currentUnchainedBlocks.push_back(entry);
		brightTime = KEEP_BRIGHT;
	}
	else
		brightTime = 20;

	if (entry.entryType == ANIM_LOOP)
	{
		PROCESS_DATA *piddata = internalProtoGraph->get_piddata();
		INSLIST *block = getDisassemblyBlock(entry.blockAddr, entry.blockID, piddata, &internalProtoGraph->terminationFlag);

		if (!block)
			unchainedWaitFrames += calculate_wait_frames(stepSize, entry.count); //external
		else
			unchainedWaitFrames += calculate_wait_frames(stepSize, entry.count*block->size());

		unsigned int maxWait = (unsigned int)((float)maxWaitFrames / (float)stepSize);
		if (unchainedWaitFrames > maxWait)
			unchainedWaitFrames = maxWait;

		animBuildingLoop = true;
	}

	vector <NODEINDEX> nodeIDList;

	if (!fill_block_nodelist(entry.blockAddr, entry.blockID, &nodeIDList) && entry.entryType != ANIM_EXEC_EXCEPTION)
	{
		Sleep(5);
		while (!fill_block_nodelist(entry.blockAddr, entry.blockID, &nodeIDList))
		{
			Sleep(5);
			cout << "[rgat] Waiting for vertlist block 0x" << hex << entry.blockAddr << endl;
		}
	}

	//add all the nodes+edges in the block to the brightening list
	brighten_node_list(&entry, brightTime, &nodeIDList);

	lastMainNode.lastVertID = lastAnimatedNode;

	//brighten edge to next unchained block
	if (entry.entryType == ANIM_UNCHAINED)
	{
		brighten_next_block_edge(&entry, brightTime);
	}
}

int plotted_graph::process_replay_animation_updates(int stepSize)
{
	if (internalProtoGraph->savedAnimationData.empty()) return ANIMATION_ENDED;

	unsigned long targetAnimIndex = animationIndex + stepSize;
	if (targetAnimIndex >= internalProtoGraph->savedAnimationData.size())
		targetAnimIndex = internalProtoGraph->savedAnimationData.size() - 1;

	
	for (; animationIndex < targetAnimIndex; ++animationIndex)
	{
		process_replay_update(stepSize);
	}

	internalProtoGraph->set_active_node(lastAnimatedNode);

	if (animationIndex >= internalProtoGraph->savedAnimationData.size() - 1)
		return ANIMATION_ENDED;
	else 
		return 0;
}

void plotted_graph::clear_active()
{
	if (!animnodesdata->col_size()) return;

	map<unsigned int, int>::iterator nodeAPosTimeIt = activeAnimNodeTimes.begin();
	GLfloat *ncol = &animnodesdata->acquire_col_write()->at(0);

	for (; nodeAPosTimeIt != activeAnimNodeTimes.end(); ++nodeAPosTimeIt)
		ncol[nodeAPosTimeIt->first] = ANIM_INACTIVE_NODE_ALPHA;
	animnodesdata->release_col_write();

	map<NODEPAIR, int>::iterator edgeIDIt = activeAnimEdgeTimes.begin();
	for (; edgeIDIt != activeAnimEdgeTimes.end(); ++edgeIDIt)
	{
		edge_data *pulsingEdge;
		if (internalProtoGraph->edge_exists(edgeIDIt->first, &pulsingEdge))
			set_edge_alpha(edgeIDIt->first, animlinedata, ANIM_INACTIVE_EDGE_ALPHA);
	}
}

void plotted_graph::maintain_active()
{
	if (!animnodesdata->col_size()) return;
	map<unsigned int, int>::iterator nodeAPosTimeIt = activeAnimNodeTimes.begin();

	GLfloat *ncol = &animnodesdata->acquire_col_write()->at(0);
	float currentPulseAlpha = fmax(ANIM_INACTIVE_NODE_ALPHA, getPulseAlpha());
	while (nodeAPosTimeIt != activeAnimNodeTimes.end())
	{
		int brightTime = nodeAPosTimeIt->second;
		if (brightTime == KEEP_BRIGHT)
		{
			ncol[nodeAPosTimeIt->first] = currentPulseAlpha;
			++nodeAPosTimeIt;
			continue;
		}

		if (--nodeAPosTimeIt->second <= 0)
		{
			fadingAnimNodes.insert(nodeAPosTimeIt->first);
			nodeAPosTimeIt = activeAnimNodeTimes.erase(nodeAPosTimeIt);
		}
		else
			++nodeAPosTimeIt;
	}
	animnodesdata->release_col_write();

	currentPulseAlpha = fmax(ANIM_INACTIVE_EDGE_ALPHA, getPulseAlpha());
	map<NODEPAIR, int>::iterator edgeIDIt = activeAnimEdgeTimes.begin();
	for (; edgeIDIt != activeAnimEdgeTimes.end(); ++edgeIDIt)
	{
		int brightTime = edgeIDIt->second;
		if (brightTime == KEEP_BRIGHT)
		{
			edge_data *pulsingEdge;
			assert(internalProtoGraph->edge_exists(edgeIDIt->first, &pulsingEdge));

			set_edge_alpha(edgeIDIt->first, animlinedata, currentPulseAlpha);
			continue;
		}

		if (--edgeIDIt->second <= 0)
		{
			fadingAnimEdges.insert(edgeIDIt->first);
			edgeIDIt = activeAnimEdgeTimes.erase(edgeIDIt);
			if (edgeIDIt == activeAnimEdgeTimes.end()) break;
		}
	}
}

void plotted_graph::redraw_anim_edges()
{
	map<NODEPAIR, int>::iterator edgeIDIt = activeAnimEdgeTimes.begin();
	for (; edgeIDIt != activeAnimEdgeTimes.end(); ++edgeIDIt)
	{
		NODEPAIR nodePair = edgeIDIt->first;

		GLfloat *ecol = &animlinedata->acquire_col_write()->at(0);

		EDGEMAP::iterator edgeIt = internalProtoGraph->edgeDict.find(nodePair);
		if (edgeIt != internalProtoGraph->edgeDict.end())
		{
			int numEdgeVerts = edgeIt->second.vertSize;
			unsigned int colArrIndex = edgeIt->second.arraypos + AOFF;
			for (int i = 0; i < numEdgeVerts; ++i)
				ecol[colArrIndex] = 1;
		}
		animlinedata->release_col_write();
	}
}

void plotted_graph::darken_nodes(float fadeRate)
{
	//darken fading verts
	//more nodes makes it take longer, possibly increase faderate on large fadinganimnodes.size()'s
	set<unsigned int>::iterator alphaPosIt = fadingAnimNodes.begin();
	while (alphaPosIt != fadingAnimNodes.end())
	{
		unsigned int nodeAlphaIndex = *alphaPosIt;

		GLfloat *ncol = &animnodesdata->acquire_col_write()->at(0);
		//set alpha value to 1 in animation colour data
		float currentAlpha = ncol[nodeAlphaIndex];
		currentAlpha = fmax(ANIM_INACTIVE_NODE_ALPHA, currentAlpha - fadeRate);
		ncol[nodeAlphaIndex] = currentAlpha;
		animnodesdata->release_col_write();

		if (currentAlpha == ANIM_INACTIVE_NODE_ALPHA)
		{
			alphaPosIt = fadingAnimNodes.erase(alphaPosIt);
			if (alphaPosIt == fadingAnimNodes.end() || fadingAnimNodes.empty()) break;
		}
		else
			++alphaPosIt;
	}
}

void plotted_graph::darken_edges(float fadeRate)
{
	unsigned long numLineVerts = animlinedata->get_numVerts();

	//darken fading edges
	set<NODEPAIR>::iterator edgeIDIt = fadingAnimEdges.begin();
	while (edgeIDIt != fadingAnimEdges.end())
	{
		NODEPAIR nodePair = *edgeIDIt;

		GLfloat *ecol = &animlinedata->acquire_col_write()->at(0);

		edge_data *linkingEdge = 0;
		if (!internalProtoGraph->edge_exists(nodePair, &linkingEdge))
		{
			cerr << "[rgat]ERROR: Attempted darkening of non-rendered edge " << nodePair.first << "," << nodePair.second << endl;
			Sleep(50);
			return;
		}

		EDGEMAP::iterator edgeIt = internalProtoGraph->edgeDict.find(nodePair);
		unsigned int arrayPos = edgeIt->second.arraypos;
		unsigned int colArrIndex = arrayPos + AOFF;
		
		if (colArrIndex >= animlinedata->col_buf_capacity_floats())
		{
			edgeIDIt++;
			animlinedata->release_col_write();
			if (edgeIDIt == fadingAnimEdges.end()) break;
			continue;
		}

		float currentAlpha = ecol[colArrIndex];
		currentAlpha = fmax(ANIM_INACTIVE_EDGE_ALPHA, currentAlpha - fadeRate);
		ecol[colArrIndex] = currentAlpha;

		int numEdgeVerts = edgeIt->second.vertSize;
		//set alpha value to 1 in animation colour data
		for (int i = 1; i < numEdgeVerts; ++i)
		{
			const unsigned int colArrIndex = arrayPos + i*COLELEMS + AOFF;
			if (colArrIndex >= animlinedata->col_buf_capacity_floats())
			{
				animlinedata->release_col_write();
				break;
			}
			ecol[colArrIndex] = currentAlpha;
		}
		animlinedata->release_col_write();

		if (currentAlpha == ANIM_INACTIVE_EDGE_ALPHA)
		{
			edgeIDIt = fadingAnimEdges.erase(edgeIDIt);
			if (edgeIDIt == fadingAnimEdges.end()) break;
		}
		else
			++edgeIDIt;
	}
}

//reduce alpha of fading verts and edges
//remove from darkening list if it hits minimum alpha limit
void plotted_graph::darken_fading(float fadeRate)
{
	/* when switching graph layouts of a big graph it can take
	   a long time for rerendering of all the edges in the protograph.
	   we can end up with a protograph with far more edges than the rendered edges
	   so have to check that we are operating within bounds */

	if (animnodesdata->get_numVerts())
		darken_nodes(fadeRate);

	if (animlinedata->get_numVerts())
		darken_edges(fadeRate);
}


void plotted_graph::brighten_new_active_nodes()
{
	map<NODEINDEX, int>::iterator vertIDIt = newAnimNodeTimes.begin();
	while (vertIDIt != newAnimNodeTimes.end())
	{
		NODEINDEX nodeIdx = vertIDIt->first;
		int animTime = vertIDIt->second;

		GLfloat *ncol = &animnodesdata->acquire_col_write()->at(0);

		const unsigned int arrIndexNodeAlpha = (nodeIdx * COLELEMS) + AOFF;
		if (arrIndexNodeAlpha >= animnodesdata->col_buf_capacity_floats())
		{
			//trying to brighten nodes we havent rendered yet
			animnodesdata->release_col_write();
			break;
		}

		//set alpha value to 1 in animation colour data
		ncol[arrIndexNodeAlpha] = 1;
		animnodesdata->release_col_write();

		//want to delay fading if in loop/unchained area, 
		if (animTime)
		{
			activeAnimNodeTimes[arrIndexNodeAlpha] = animTime;
			set <unsigned int>::iterator fadeIt = fadingAnimNodes.find(arrIndexNodeAlpha);
			if (fadeIt != fadingAnimNodes.end())
				fadingAnimNodes.erase(fadeIt);
		}
		else
			fadingAnimNodes.insert(arrIndexNodeAlpha);

		vertIDIt = newAnimNodeTimes.erase(vertIDIt);
	}
}

void plotted_graph::brighten_new_active_extern_nodes()
{
	PROCESS_DATA *piddata = internalProtoGraph->get_piddata();
	map <NODEINDEX, EXTTEXT> newEntries;
	map <pair<NODEINDEX, unsigned int>, int>::iterator externTimeIt = newExternTimes.begin();
	while (externTimeIt != newExternTimes.end())
	{
		NODEINDEX externNodeIdx = externTimeIt->first.first;
		unsigned int callsSoFar = externTimeIt->first.second;

		internalProtoGraph->getNodeReadLock();
		node_data *externNode = internalProtoGraph->unsafe_get_node(externNodeIdx);
		ARGLIST *args;
		obtainMutex(internalProtoGraph->externGuardMutex, 2121);
		if (externNode->funcargs.size() > callsSoFar)
			args = &externNode->funcargs.at(callsSoFar);
		else
			args = 0;

		MEM_ADDRESS insaddr = externNode->address;
		int nodeModule = externNode->nodeMod;

		internalProtoGraph->dropNodeReadLock();

		string externString = generate_funcArg_string(internalProtoGraph->get_node_sym(externNodeIdx, piddata), args);
		dropMutex(internalProtoGraph->externGuardMutex);

		string modPath;
		piddata->get_modpath(nodeModule, &modPath);

		stringstream callLogEntry;
		callLogEntry << "0x" << std::hex << insaddr << ": ";
		callLogEntry << modPath << " -> ";
		callLogEntry << externString << "\n";
		internalProtoGraph->loggedCalls.push_back(callLogEntry.str());

		EXTTEXT extEntry;
		extEntry.framesRemaining = externTimeIt->second;
		extEntry.displayString = externString;
		extEntry.yOffset = 10;

		newEntries[externNodeIdx] = extEntry;

		externTimeIt = newExternTimes.erase(externTimeIt);
	}

	obtainMutex(internalProtoGraph->externGuardMutex, 2819);
	map <NODEINDEX, EXTTEXT>::iterator entryIt = newEntries.begin();
	for (; entryIt != newEntries.end(); ++entryIt)
		activeExternTimes[entryIt->first] = entryIt->second;
	dropMutex(internalProtoGraph->externGuardMutex);
}


void plotted_graph::brighten_new_active_edges()
{
	map<NODEPAIR, int>::iterator edgeIDIt = newAnimEdgeTimes.begin();
	while (edgeIDIt != newAnimEdgeTimes.end())
	{
		NODEPAIR nodePair = edgeIDIt->first;
		unsigned int animTime = edgeIDIt->second;

		if (!internalProtoGraph->edge_exists(nodePair, 0)) {
			cerr << "[rgat]WARNING: brightening new edges non-existant edge " << nodePair.first << "," << nodePair.second << endl;
			break;
		}

		set_edge_alpha(nodePair, animlinedata, 1.0);

		//want to delay fading if in loop/unchained area, 
		if (animTime)
		{
			activeAnimEdgeTimes[nodePair] = animTime;
			set <NODEPAIR>::iterator fadeIt = fadingAnimEdges.find(nodePair);

			if (fadeIt != fadingAnimEdges.end())
				fadingAnimEdges.erase(fadeIt);
		}
		else
			fadingAnimEdges.insert(nodePair);

		edgeIDIt = newAnimEdgeTimes.erase(edgeIDIt);
	}
}

void plotted_graph::brighten_new_active()
{
	if (!animnodesdata->col_size()) return;

	brighten_new_active_nodes();
	brighten_new_active_extern_nodes();
	brighten_new_active_edges();
}


void plotted_graph::render_animation(float fadeRate)
{
	brighten_new_active();
	maintain_active();
	darken_fading(fadeRate);

	set_node_alpha(lastAnimatedNode, animnodesdata, getPulseAlpha());

	//live process always at least has pulsing active node
	needVBOReload_active = true;
}


void plotted_graph::render_live_animation(float fadeRate)
{
	process_live_animation_updates();
	render_animation(fadeRate);
}

//makes the active highlight line point to the last instruction executed
void plotted_graph::set_last_active_node()
{
	if (internalProtoGraph->lastNode < mainnodesdata->get_numVerts())
		lastAnimatedNode = internalProtoGraph->lastNode;
}


int plotted_graph::render_replay_animation(int stepSize, float fadeRate)
{
	if (userSelectedAnimPosition != -1)
	{
		reset_animation();

		int selectionDiff;
		if (userSelectedAnimPosition < 20 || internalProtoGraph->savedAnimationData.size() < 20)
		{
			animationIndex = 0;
			selectionDiff = userSelectedAnimPosition;
		}
		else
			animationIndex = userSelectedAnimPosition - 20;

		stepSize = 20;
	}

	int result = process_replay_animation_updates(stepSize);
	render_animation(fadeRate);

	if (userSelectedAnimPosition != -1)
		userSelectedAnimPosition = -1;

	return result;
}

void plotted_graph::reset_mainlines()
{
	mainlinedata->reset();
	animlinedata->reset();
}


void plotted_graph::display_highlight_lines(vector<node_data *> *nodePtrList, ALLEGRO_COLOR *colour, int lengthModifier)
{
	vector<node_data *>::iterator nodeIt = nodePtrList->begin();
	for (; nodeIt != nodePtrList->end(); ++nodeIt)
	{
		node_data *n = *nodeIt;
		drawHighlight(n->index , main_scalefactors, colour, lengthModifier);
	}
}

void plotted_graph::set_edge_alpha(NODEPAIR eIdx, GRAPH_DISPLAY_DATA *edgesdata, float alpha)
{
	if (!edgesdata->get_numVerts()) return;

	EDGEMAP::iterator edgeIt = internalProtoGraph->edgeDict.find(eIdx);
	if (edgeIt == internalProtoGraph->edgeDict.end()) return;

	edge_data *e = &edgeIt->second;
	
	const unsigned int bufsize = edgesdata->col_buf_capacity_floats();
	GLfloat *colarray = &edgesdata->acquire_col_write()->at(0);
	for (unsigned int i = 0; i < e->vertSize; ++i)
	{
		unsigned int bufIndex = e->arraypos + i*COLELEMS + AOFF;
		if (bufIndex > bufsize) break;
		colarray[bufIndex] = alpha;
	}
	edgesdata->release_col_write();
}

//rescale all drawn verts to sphere of new diameter by altering the vertex data
void plotted_graph::rescale_nodes(bool isPreview)
{

	GRAPH_SCALE *scalefactors = isPreview ? preview_scalefactors : main_scalefactors;

	GRAPH_DISPLAY_DATA *vertsdata;
	unsigned long targetIdx, nodeIdx;

	if (isPreview)
	{
		nodeIdx = 0;
		vertsdata = previewnodes;
		targetIdx = vertsdata->get_numVerts();
	}
	else
	{
		//only resize 250 nodes per call to stop it hanging
		nodeIdx = vertResizeIndex;
		vertResizeIndex += NODES_PER_RESCALE_ITERATION;
		vertsdata = get_mainnodes();
		targetIdx = min(vertResizeIndex, vertsdata->get_numVerts());
		if (targetIdx == vertsdata->get_numVerts()) 
			vertResizeIndex = 0;
	}

	if (!targetIdx) return;

	GLfloat *vpos = &vertsdata->acquire_pos_write(152)->at(0);

	for (; nodeIdx != targetIdx; ++nodeIdx)
	{
		FCOORD newCoord = nodeIndexToXYZ(nodeIdx, scalefactors, 0);

		const int arrayIndex = nodeIdx * POSELEMS;
		vpos[arrayIndex + XOFF] = newCoord.x;
		vpos[arrayIndex + YOFF] = newCoord.y;
		vpos[arrayIndex + ZOFF] = newCoord.z;
	}

	vertsdata->release_pos_write();
}


//renders edgePerRender edges of graph onto the preview data
int plotted_graph::render_new_preview_edges(VISSTATE* clientState)
{
	//draw edges
	EDGELIST::iterator edgeIt, edgeEnd;
	//todo, this should be done without the mutex using indexing instead of iteration
	internalProtoGraph->start_edgeL_iteration(&edgeIt, &edgeEnd);

	std::advance(edgeIt, previewlines->get_renderedEdges());
	if (edgeIt != edgeEnd)
		needVBOReload_preview = true;

	int remainingEdges = clientState->config->preview.edgesPerRender;
	vector<ALLEGRO_COLOR> *lineColours = &clientState->config->graphColours;

	for (; edgeIt != edgeEnd; ++edgeIt)
	{
		if (edgeIt->first >= previewnodes->get_numVerts())
		{
			node_data *n = internalProtoGraph->safe_get_node(edgeIt->first);
			add_node(n, &lastPreviewNode, previewnodes, animnodesdata, preview_scalefactors);
		}

		if (edgeIt->second >= previewnodes->get_numVerts())
		{
			edge_data *e = &internalProtoGraph->edgeDict.at(*edgeIt);
			if (e->edgeClass == eEdgeException)
				lastPreviewNode.lastVertType = eNodeException;

			node_data *n = internalProtoGraph->safe_get_node(edgeIt->second);
			add_node(n, &lastPreviewNode, previewnodes, animnodesdata, preview_scalefactors);
		}

		if (!render_edge(*edgeIt, previewlines, 0, true, false))
		{
			internalProtoGraph->stop_edgeL_iteration();
			return 0;
		}

		previewlines->inc_edgesRendered();
		if (!remainingEdges--)break;
	}
	internalProtoGraph->stop_edgeL_iteration();
	return 1;
}

void plotted_graph::removeEntryFromQueue()
{
	obtainMutex(internalProtoGraph->animationListsMutex, 6211);
	internalProtoGraph->animUpdates.pop();
	dropMutex(internalProtoGraph->animationListsMutex);
}

//displays heatmap of the active graph
void plotted_graph::display_big_heatmap(VISSTATE *clientState)
{
	plotted_graph *graph = (plotted_graph *)clientState->activeGraph;
	if (!graph->heatmaplines) return;

	if (graph->needVBOReload_heatmap)
	{
		if (!graph->heatmaplines->get_numVerts()) return;
		load_VBO(0, graph->heatmapEdgeVBO,
			graph->heatmaplines->col_size(), graph->heatmaplines->readonly_col());
		graph->needVBOReload_heatmap = false;
	}

	GRAPH_DISPLAY_DATA *vertsdata = graph->get_mainnodes();
	GRAPH_DISPLAY_DATA *linedata = graph->get_mainlines();
	if (graph->needVBOReload_main)
	{
		loadVBOs(graph->graphVBOs, vertsdata, linedata);
		graph->needVBOReload_main = false;
	}

	if (clientState->modes.nodes)
		array_render_points(VBO_NODE_POS, VBO_NODE_COL, graph->graphVBOs, vertsdata->get_numVerts());

	if (clientState->modes.edges)
	{
		glBindBuffer(GL_ARRAY_BUFFER, graph->graphVBOs[VBO_LINE_POS]);
		glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

		glBindBuffer(GL_ARRAY_BUFFER, graph->heatmapEdgeVBO[0]);
		glColorPointer(COLELEMS, GL_FLOAT, 0, 0);

		glDrawArrays(GL_LINES, 0, graph->heatmaplines->get_numVerts());
	}

	float zmul = zoomFactor(clientState->cameraZoomlevel, graph->main_scalefactors->size);

	PROJECTDATA pd;
	gather_projection_data(&pd);

	if (zmul < EXTERN_VISIBLE_ZOOM_FACTOR)
		show_symbol_labels(clientState, &pd);

	if (clientState->modes.show_ins_text && zmul < INSTEXT_VISIBLE_ZOOMFACTOR && internalProtoGraph->get_num_nodes() > 2)
		draw_edge_heat_text(clientState, zmul, &pd);


}

#define VBO_COND_NODE_COLOUR 0
#define VBO_COND_LINE_COLOUR 1
//displays the conditionals of the active graph
void plotted_graph::display_big_conditional(VISSTATE *clientState)
{
	plotted_graph *graph = (plotted_graph *)clientState->activeGraph;
	if (!graph->conditionallines || !graph->conditionalnodes) return;

	if (graph->needVBOReload_conditional)
	{
		if (!graph->conditionalnodes->get_numVerts() || !graph->conditionallines->get_numVerts()) return;

		load_VBO(VBO_COND_NODE_COLOUR, graph->conditionalVBOs,
			graph->conditionalnodes->col_size(), graph->conditionalnodes->readonly_col());
		load_VBO(VBO_COND_LINE_COLOUR, graph->conditionalVBOs,
			graph->conditionallines->col_size(), graph->conditionallines->readonly_col());

		graph->needVBOReload_conditional = false;
	}

	if (graph->needVBOReload_main)
	{
		loadVBOs(graph->graphVBOs, graph->get_mainnodes(), graph->get_mainlines());
		graph->needVBOReload_main = false;
	}

	if (clientState->modes.nodes)
	{
		glBindBuffer(GL_ARRAY_BUFFER, graph->graphVBOs[VBO_NODE_POS]);
		glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

		glBindBuffer(GL_ARRAY_BUFFER, graph->conditionalVBOs[VBO_COND_NODE_COLOUR]);
		glColorPointer(COLELEMS, GL_FLOAT, 0, 0);
		glDrawArrays(GL_POINTS, 0, graph->conditionalnodes->get_numVerts());
	}

	if (clientState->modes.edges)
	{
		glBindBuffer(GL_ARRAY_BUFFER, graph->graphVBOs[VBO_LINE_POS]);
		glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

		glBindBuffer(GL_ARRAY_BUFFER, graph->conditionalVBOs[VBO_COND_LINE_COLOUR]);
		glColorPointer(COLELEMS, GL_FLOAT, 0, 0);
		glDrawArrays(GL_LINES, 0, graph->conditionallines->get_numVerts());

	}

	PROJECTDATA pd;
	gather_projection_data(&pd);
	float zoomDiffMult = (clientState->cameraZoomlevel - graph->zoomLevel) / 1000 - 1;

	if (zoomDiffMult < 10 && internalProtoGraph->get_num_nodes() > 2)
		draw_condition_ins_text(clientState, zoomDiffMult, &pd, graph->get_mainnodes());

}



//should be same as rendering for main graph but - the animation + more pauses instead of all at once
int plotted_graph::render_preview_graph(VISSTATE *clientState)
{
	bool doResize = false;
	needVBOReload_preview = true;

	if (previewNeedsResize)
	{
		rescale_nodes(true);
		previewlines->reset();
		previewNeedsResize = false;
	}

	if (!render_new_preview_edges(clientState))
	{
		cerr << "ERROR: Failed drawing new edges in render_preview_graph! " << endl;
		//assert(0);
	}
	return 1;
}

void plotted_graph::updateMainRender(VISSTATE *clientState)
{

	render_static_graph(clientState);

	updateTitle_NumPrimitives(clientState->maindisplay, clientState, get_mainnodes()->get_numVerts(),
		get_mainlines()->get_renderedEdges());
}

void plotted_graph::gen_graph_VBOs()
{
	glGenBuffers(4, graphVBOs);
	glGenBuffers(4, previewVBOs);
	glGenBuffers(1, heatmapEdgeVBO);
	glGenBuffers(2, conditionalVBOs);
	glGenBuffers(4, activeVBOs);
	VBOsGenned = true;
}


