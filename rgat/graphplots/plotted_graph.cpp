/*
Copyright 2016-2017 Nia Catlin

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
The base graph plot class which is intended to provide everything needed to implement an actual plotted graph
must be derived (sphere, cylinder, tree, mona lisa, etc)
*/

#include "stdafx.h"
#include "plotted_graph.h"
#include "graphicsMaths.h"
#include "widgets\GraphPlotGLWidget.h"
#include "diff_plotter.h"
#include "gl/GLU.h"

rgatState *plotted_graph::clientState = NULL;

plotted_graph::plotted_graph(proto_graph *protoGraph, vector<QColor> *graphColoursPtr)
{
	pid = protoGraph->get_traceRecord()->PID;
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
	if (internalProtoGraph->active)
		animated = true;
	else
		animated = false;

	graphColours = graphColoursPtr;
}

plotted_graph::~plotted_graph()
{
	assert(graphBusyLock.islocked());
	//wait for other threads to finish using this graph
	dying = true;
	freeMe = true;
	beingDeleted = true;


	callStackLock.lock();

	int failedWaits = 0;
	while (isreferenced())
	{
		if ((failedWaits > 6) && isreferenced())
			cout << "[rgat] Waiting for all threads to dereference graph: #" << threadReferences << endl;
		Sleep(40);
		if (failedWaits++ == 12 && isreferenced())
		{
			cerr << "[rgat] Warning: Not all threads dereferenced the graph. Proceeding with graph deletion, but it may crash..." << endl;
			break;
		}
	}
	AcquireSRWLockExclusive(&threadReferenceLock);

	delete mainnodesdata;
	delete mainlinedata;

	delete previewlines;
	delete previewnodes;

	delete conditionallines;
	delete conditionalnodes;
	delete heatmaplines;

	delete main_scalefactors;
	delete preview_scalefactors;

	delete animlinedata;
	delete animnodesdata;
}

//this is called by threads to indicate it is being used to prevent deletion
//should probably use a spinlock instead?
bool plotted_graph::increase_thread_references(int caller)
{
	if (dying || freeMe || beingDeleted) return false;

	if (TryAcquireSRWLockShared(&threadReferenceLock))
	{
		++threadReferences;
		//cout << "thread refs increased by caller " << caller << " to " << threadReferences << endl;
		return true;
	}
	return false;
}

void plotted_graph::decrease_thread_references(int caller)
{
	if (threadReferences <= 0)
	{
		cerr << "Assert in graph " << this << " due to decreasing refs from 0 " << endl;
		assert(threadReferences > 0);
	}

	ReleaseSRWLockShared(&threadReferenceLock);
	--threadReferences;

	//cout << "thread refs decreased by caller " << caller << " to " << threadReferences << endl;
}



//tracking how big the graph gets
void plotted_graph::updateStats(float a, float b, float c)
{
	//the extra work of 2xabs() happens so rarely that its worth avoiding
	//the stack allocations of a variable every call
	if (abs(a) > maxA) maxA = abs(a);
	if (abs(b) > maxB) maxB = abs(b);
}

bool plotted_graph::trySetGraphBusy()
{
	return graphBusyLock.trylock();
}

bool plotted_graph::setGraphBusy(bool set, int caller)
{
	if (set) 
	{
		graphBusyLock.lock();
		if (dying)
		{
			graphBusyLock.unlock();
			return false;
		}
	}
	else
	{
		graphBusyLock.unlock();
	}
	return true;
}

void plotted_graph::acquire_nodecoord_read()
{
	AcquireSRWLockShared(&nodeCoordLock);
}

void plotted_graph::acquire_nodecoord_write()
{
	AcquireSRWLockExclusive(&nodeCoordLock);
}

void plotted_graph::release_nodecoord_read()
{
	ReleaseSRWLockShared(&nodeCoordLock);
}

void plotted_graph::release_nodecoord_write()
{
	ReleaseSRWLockExclusive(&nodeCoordLock);
}

//display live or animated graph with active areas on faded areas
void plotted_graph::display_active(graphGLWidget *gltarget)
{
	GLsizei animnodesverts = animnodesdata->get_numVerts();
	GLsizei staticnodesverts = mainnodesdata->get_numVerts();
	GLsizei nodeLoadQty = min(animnodesverts, staticnodesverts);

	GLsizei animlinevertsQty = animlinedata->get_numVerts();
	GLsizei mainlinevertsQty = mainlinedata->get_numVerts();
	GLsizei edgeVertLoadQty = min(animlinevertsQty, mainlinevertsQty);

	//reload buffers if needed and not being written
	if (needVBOReload_active)
	{
		gltarget->load_VBO(VBO_NODE_POS, activeVBOs, POSITION_VERTS_SIZE(nodeLoadQty), mainnodesdata->readonly_pos());
		gltarget->load_VBO(VBO_NODE_COL, activeVBOs, COLOUR_VERTS_SIZE(nodeLoadQty), animnodesdata->readonly_col());
		animnodesdata->set_numLoadedVerts(nodeLoadQty);

		GLfloat *buf = mainlinedata->readonly_pos();
		if (!buf) return; 
		gltarget->load_VBO(VBO_LINE_POS, activeVBOs, POSITION_VERTS_SIZE(edgeVertLoadQty), buf);

		buf = animlinedata->readonly_col();
		if (!buf) return;

		gltarget->load_VBO(VBO_LINE_COL, activeVBOs, COLOUR_VERTS_SIZE(edgeVertLoadQty), buf);
		animlinedata->set_numLoadedVerts(edgeVertLoadQty);

		needVBOReload_active = false;
	}

	if (clientState->showNodes && animnodesdata->get_numLoadedVerts())
	{
		gltarget->array_render_points(VBO_NODE_POS, VBO_NODE_COL, activeVBOs, animnodesdata->get_numLoadedVerts());
		int err = glGetError();
		if (err) cerr << "GL error " << err << " in arr_r_pts (display active)" << endl;
	}

	if (clientState->showEdges &&  animlinedata->get_numLoadedVerts())
	{
		gltarget->array_render_lines(VBO_LINE_POS, VBO_LINE_COL, activeVBOs, animlinedata->get_numLoadedVerts());
		int err = glGetError();
		if (err) cerr << "GL error " << err << " in arr_r_edges (display active)" << endl;
	}
}

//display graph with everything bright and viewable
void plotted_graph::display_static(graphGLWidget *gltarget)
{
	if (needVBOReload_main)
	{
		//lock for reading if corrupt graphics happen occasionally
		gltarget->loadVBOs(graphVBOs, mainnodesdata, mainlinedata);
	
		needVBOReload_main = false;
	}

	if (clientState->showNodes)
		gltarget->array_render_points(VBO_NODE_POS, VBO_NODE_COL, graphVBOs, mainnodesdata->get_numLoadedVerts());

	if (clientState->showEdges)
		gltarget->array_render_lines(VBO_LINE_POS, VBO_LINE_COL, graphVBOs, mainlinedata->get_numLoadedVerts());
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
		animecol->at(index2 + AOFF) = (float)0.01; //TODO: config file entry for anim inactive

	animlinedata->set_numVerts(drawnVerts);
	animlinedata->release_col_write();
}

PLOT_TRACK plotted_graph::setLastNode(NODEINDEX nodeIdx)
{
	PLOT_TRACK lastnode;

	node_data *n;
	n = internalProtoGraph->safe_get_node(nodeIdx);
	lastnode.lastVertID = nodeIdx;

	if (n->external)
		lastnode.lastVertType = eNodeExternal;
	else
	{
		switch (n->ins->itype)
		{
		case eInsUndefined:
		{
			lastnode.lastVertType = n->conditional ? eNodeJump : eNodeNonFlow;
			break;
		}
		case eInsJump:
		{
			lastnode.lastVertType = eNodeJump;
			break;
		}
		case eInsReturn:
		{
			lastnode.lastVertType = eNodeReturn;
			break;
		}
		case eInsCall:
		{
			lastnode.lastVertType = eNodeCall;

			//let returns find their caller if they have one
			MEM_ADDRESS nextAddress = n->ins->address + n->ins->numbytes;

			callStackLock.lock();
			if (mainnodesdata->isPreview())
				previewCallStack.push_back(make_pair(nextAddress, n->index));
			else
				mainCallStack.push_back(make_pair(nextAddress, n->index));
			callStackLock.unlock();

			break;
		}
		//case ISYS: //todo: never used - intended for syscalls
		//	active_col = &al_col_grey;
		//	break;
		default:
			cerr << "[rgat]Error: add_node unknown itype " << n->ins->itype << endl;
			assert(0);
		}
	}
	return lastnode;
}

//create edges in opengl buffers
int plotted_graph::render_new_edges()
{
	GRAPH_DISPLAY_DATA *lines = get_mainlines();
	EDGELIST::iterator edgeIt;
	int edgesDrawn = 0;

	internalProtoGraph->getEdgeReadLock();

	edgeIt = internalProtoGraph->edgeList.begin();
	std::advance(edgeIt, lines->get_renderedEdges());

	EDGELIST::iterator end = internalProtoGraph->edgeList.end();
	if (edgeIt == end)
	{
		internalProtoGraph->dropEdgeReadLock();
		return 0;
	}

	needVBOReload_main = true;

	for (; edgeIt != end && !dying; ++edgeIt)
	{
		if (edgeIt->second == 85)
			cout << "d";

		//render source node if not already done
		if (edgeIt->first >= (NODEINDEX)mainnodesdata->get_numVerts())
		{
			node_data *n;
			n = internalProtoGraph->safe_get_node(edgeIt->first);
			add_node(n, &lastMainNode, mainnodesdata, animnodesdata, main_scalefactors);
		}
		else
			lastMainNode = setLastNode(edgeIt->first);


		//render target node if not already done
		if (edgeIt->second >= (NODEINDEX)mainnodesdata->get_numVerts())
		{
			edge_data *e = &internalProtoGraph->edgeDict.at(*edgeIt);
			if (e->edgeClass == eEdgeException)
				lastPreviewNode.lastVertType = eNodeException;

			node_data *n = internalProtoGraph->safe_get_node(edgeIt->second);
			add_node(n, &lastMainNode, mainnodesdata, animnodesdata, main_scalefactors);
		}
		else
			lastMainNode = setLastNode(edgeIt->second);
		
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

void plotted_graph::reset_animation_if_scheduled()
{
	if (!animation_needs_reset) return;

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

	animnodesdata->acquire_col_write()->at(0);

	newAnimEdgeTimes.clear();
	newAnimNodeTimes.clear();
	activeAnimEdgeTimes.clear();
	activeAnimNodeTimes.clear();
	unchainedWaitFrames = 0;
	currentUnchainedBlocks.clear();
	animBuildingLoop = false;
	animated = false;

	animnodesdata->release_col_write();
	animation_needs_reset = false;
}


void plotted_graph::set_node_alpha(NODEINDEX nIdx, GRAPH_DISPLAY_DATA *nodesdata, float alpha)
{
	unsigned long long bufIndex = nIdx*COLELEMS + AOFF;
	if (bufIndex >= nodesdata->col_buf_capacity_floats()) return;

	GLfloat *colarray = &nodesdata->acquire_col_write()->at(0);
	colarray[bufIndex] = alpha;
	nodesdata->release_col_write();
}

//fill nodelist with with all nodes corresponding to basic block (blockAddr/blockID) on the graph
bool plotted_graph::fill_block_nodelist(MEM_ADDRESS blockAddr, BLOCK_IDENTIFIER blockID, vector <NODEINDEX> *nodelist)
{
	PROCESS_DATA *piddata = internalProtoGraph->get_piddata();
	BB_DATA *externBlock = 0;
	INSLIST * block = piddata->getDisassemblyBlock(blockAddr, blockID, &internalProtoGraph->terminationFlag, &externBlock);
	if (!block && externBlock)
	{
		//assume it's an external block, find node in extern call list
		piddata->getExternDictReadLock();
		EDGELIST callvs = externBlock->thread_callers.at(tid);

		EDGELIST::iterator callvsIt = callvs.begin();
		for (; callvsIt != callvs.end(); ++callvsIt) //record each call by caller
		{
			if (callvsIt->first == lastAnimatedNode)
				nodelist->push_back(callvsIt->second);
		}
		piddata->dropExternDictReadLock();

		return true;
	}

	INSLIST::iterator blockIt = block->begin();
	for (; blockIt != block->end(); ++blockIt)
	{
		INS_DATA* activeInstruction = *blockIt;
		unordered_map<PID_TID, NODEINDEX>::iterator vertIt = activeInstruction->threadvertIdx.find(tid);
		if (vertIt == activeInstruction->threadvertIdx.end())
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
	map <NODEINDEX, int>::iterator nodeIt = activeAnimNodeTimes.begin();
	for (; nodeIt != activeAnimNodeTimes.end(); ++nodeIt)
		if (nodeIt->second == KEEP_BRIGHT)
			nodeIt->second = 0;

	internalProtoGraph->externCallsLock.lock();
	map <NODEINDEX, EXTTEXT>::iterator activeExternIt = activeExternTimes.begin();
	for (; activeExternIt != activeExternTimes.end(); ++activeExternIt)
		if (activeExternIt->second.framesRemaining == KEEP_BRIGHT)
			activeExternIt->second.framesRemaining = (int)(EXTERN_LIFETIME_FRAMES / 2);
	internalProtoGraph->externCallsLock.unlock();

	map <NODEPAIR, int>::iterator edgeIt = activeAnimEdgeTimes.begin();
	for (; edgeIt != activeAnimEdgeTimes.end(); ++edgeIt)
		if (edgeIt->second == KEEP_BRIGHT)
			edgeIt->second = 0;
}

//execution has returned to temporarily deinstrumented code
//rgat has just been informed where it was so resume animation from start of it
void plotted_graph::end_unchained(ANIMATIONENTRY *entry)
{
	currentUnchainedBlocks.clear();
	INSLIST* firstChainedBlock = internalProtoGraph->get_piddata()->getDisassemblyBlock(entry->blockAddr, entry->blockID,
		&internalProtoGraph->terminationFlag, 0);
	lastAnimatedNode = firstChainedBlock->back()->threadvertIdx.at(tid); //should this be front()?
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

		if (!(entry->entryType == eAnimUnchained && nodeIt == nodeIDList->begin()))
		{
			NODEPAIR edge = make_pair(lastAnimatedNode, nodeIdx);
			if (internalProtoGraph->edge_exists(edge, 0))
			{
				newAnimEdgeTimes[edge] = brightTime;
			}
			//if it doesn't exist it may be because user is skipping code with animation slider
		}

		lastAnimatedNode = nodeIdx;

		++instructionCount;
		if ((entry->entryType == eAnimExecException) && (instructionCount == (entry->count + 1))) break;
	}
}

//brightened a block, now want to brighten the edge between it (lastanimatednode) and the next block (in entry)
void plotted_graph::brighten_next_block_edge(ANIMATIONENTRY *entry, int brightTime)
{
		PROCESS_DATA *piddata = internalProtoGraph->get_piddata();
		NODEINDEX nextNode;
		NODEPAIR linkingPair;

		BB_DATA *externBlock = NULL;
		INSLIST* nextBlock = piddata->getDisassemblyBlock(entry->targetAddr, entry->targetID, &internalProtoGraph->terminationFlag, &externBlock);
		//if next block is external code, find its vert
		if (externBlock)
		{
			piddata->getExternCallerReadLock();

			EDGELIST callers = externBlock->thread_callers.at(tid);
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

			piddata->dropExternCallerReadLock();
		}
		else
		{
			//find vert in internal code
			INS_DATA* nextIns = nextBlock->front();
			unordered_map<PID_TID, NODEINDEX>::iterator threadVIt = nextIns->threadvertIdx.find(tid);
			if (threadVIt == nextIns->threadvertIdx.end())
				return;
			nextNode = threadVIt->second;
			linkingPair = make_pair(lastAnimatedNode, nextNode);
		}

		//check edge exists then add it to list of edges to brighten
		if (internalProtoGraph->edge_exists(linkingPair, 0))
		{
			newAnimEdgeTimes[linkingPair] = brightTime;
		}
		/*
		if it doesn't exist then assume it's because the user is skipping around the animation with the slider
		(there are other reasons but it helps me sleep at night)
		*/
}

void plotted_graph::process_live_update()
{
	//todo: eliminate need for competing with the trace handler for the lock using spsc ringbuffer
	AcquireSRWLockShared(&internalProtoGraph->animationListsSRWLOCK);
	ANIMATIONENTRY entry = internalProtoGraph->savedAnimationData.at(updateProcessingIndex);
	ReleaseSRWLockShared(&internalProtoGraph->animationListsSRWLOCK);

	if (entry.entryType == eAnimLoopLast)
	{
		++updateProcessingIndex;
		return;
	}

	if (entry.entryType == eAnimUnchainedResults)
	{
		remove_unchained_from_animation();

		++updateProcessingIndex;
		return;
	}

	if (entry.entryType == eAnimUnchainedDone)
	{
		end_unchained(&entry);
		++updateProcessingIndex;
		return;
	}

	int brightTime;
	if (entry.entryType == eAnimUnchained)
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
		if ((entry.entryType != eAnimExecException) ||	(nodeIDList.size() < entry.count)) 
			return;
	}

	//add all the nodes+edges in the block to the brightening list
	brighten_node_list(&entry, brightTime, &nodeIDList);

	//also add brighten edge to next unchained block
	if (entry.entryType == eAnimUnchained)
		brighten_next_block_edge(&entry, brightTime);

	++updateProcessingIndex;
}

void plotted_graph::process_live_animation_updates()
{
	//too many updates at a time damages interactivity
	//too few creates big backlogs which delays the animation (can still see realtime in Structure mode though)
	int updateLimit = animEntriesPerFrame; 
	while (updateProcessingIndex < internalProtoGraph->savedAnimationData.size() && updateLimit--)
	{
		process_live_update();
	}
}

#define ASSUME_INS_PER_BLOCK 10
//tries to make animation pause for long enough to represent heavy cpu usage but
//not too long to make it irritating (still a bit janky with very small traces though)
//if program is 1m instructions and takes 10s to execute then a 50k block should wait for ~.5s
unsigned long plotted_graph::calculate_wait_frames(unsigned long blockInstructions)
{
	//assume 10 instructions per step/frame
	int stepSize = clientState->animationStepRate;
	if (stepSize == 0) stepSize = 1;
	unsigned long frames = (internalProtoGraph->totalInstructions / ASSUME_INS_PER_BLOCK) / stepSize;

	float proportion = (float)blockInstructions / internalProtoGraph->totalInstructions;
	unsigned long waitFrames = proportion*frames;
	return waitFrames;
}

void plotted_graph::process_replay_update()
{
	ANIMATIONENTRY entry = internalProtoGraph->savedAnimationData.at(animationIndex);

	int stepSize = clientState->animationStepRate;
	if (stepSize == 0) stepSize = 1;

	//unchained area finished, stop highlighting it
	if (entry.entryType == eAnimUnchainedResults)
	{
		PROCESS_DATA *piddata = internalProtoGraph->get_piddata();
		INSLIST *block = piddata->getDisassemblyBlock(entry.blockAddr, entry.blockID, &internalProtoGraph->terminationFlag, NULL);
		unchainedWaitFrames += calculate_wait_frames(entry.count*block->size());

		unsigned int maxWait = (unsigned int)((float)maxWaitFrames / (float)stepSize);
		if (unchainedWaitFrames > maxWait)
			unchainedWaitFrames = maxWait;

		return;
	}

	//all consecutive unchained areas finished, wait until animation paused appropriate frames
	if (entry.entryType == eAnimUnchainedDone)
	{
		if (unchainedWaitFrames-- > 1)  return;

		remove_unchained_from_animation();
		end_unchained(&entry);
		return;
	}

	if (entry.entryType == eAnimLoopLast)
	{
		if (unchainedWaitFrames-- > 1) return;

		remove_unchained_from_animation();
		currentUnchainedBlocks.clear();
		animBuildingLoop = false;
		return;
	}

	int brightTime;
	if (entry.entryType == eAnimUnchained || animBuildingLoop)
	{
		currentUnchainedBlocks.push_back(entry);
		brightTime = KEEP_BRIGHT;
	}
	else
		brightTime = 20;

	if (entry.entryType == eAnimLoop)
	{
		PROCESS_DATA *piddata = internalProtoGraph->get_piddata();
		INSLIST *block = piddata->getDisassemblyBlock(entry.blockAddr, entry.blockID, &internalProtoGraph->terminationFlag, NULL);

		if (!block)
			unchainedWaitFrames += calculate_wait_frames(entry.count); //external
		else
			unchainedWaitFrames += calculate_wait_frames(entry.count*block->size());

		unsigned int maxWait = (unsigned int)((float)maxWaitFrames / (float)stepSize);
		if (unchainedWaitFrames > maxWait)
			unchainedWaitFrames = maxWait;

		animBuildingLoop = true;
	}

	vector <NODEINDEX> nodeIDList;

	if (!fill_block_nodelist(entry.blockAddr, entry.blockID, &nodeIDList) && entry.entryType != eAnimExecException)
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
	if (entry.entryType == eAnimUnchained)
	{
		brighten_next_block_edge(&entry, brightTime);
	}
}

int plotted_graph::process_replay_animation_updates(int optionalStepSize = 0)
{
	if (internalProtoGraph->savedAnimationData.empty()) 
	{ 
		replayState = eEnded;
		return ANIMATION_ENDED; 
	}

	int stepSize;
	if (optionalStepSize)
	{
		stepSize = optionalStepSize;
	}
	else
	{
		stepSize = (replayState != ePaused) ? clientState->animationStepRate : 0;
	}

	NODEINDEX targetAnimIndex = animationIndex + stepSize;
	if (targetAnimIndex >= internalProtoGraph->savedAnimationData.size())
		targetAnimIndex = internalProtoGraph->savedAnimationData.size() - 1;

	
	for (; animationIndex < targetAnimIndex; ++animationIndex)
	{
		process_replay_update();
	}

	internalProtoGraph->set_active_node(lastAnimatedNode);

	if (animationIndex >= internalProtoGraph->savedAnimationData.size() - 1)
	{
		replayState = eEnded;
		return ANIMATION_ENDED;
	}

	else 
		return 0;
}

void plotted_graph::clear_active()
{
	if (!animnodesdata->get_numVerts()) return;

	if (!activeAnimNodeTimes.empty())
	{
		map<NODEINDEX, int>::iterator nodeAPosTimeIt = activeAnimNodeTimes.begin();
		GLfloat *ncol = &animnodesdata->acquire_col_write()->at(0);

		for (; nodeAPosTimeIt != activeAnimNodeTimes.end(); ++nodeAPosTimeIt)
			ncol[nodeAPosTimeIt->first] = ANIM_INACTIVE_NODE_ALPHA;
		animnodesdata->release_col_write();
	}

	if (!activeAnimEdgeTimes.empty())
	{
		map<NODEPAIR, int>::iterator edgeIDIt = activeAnimEdgeTimes.begin();
		for (; edgeIDIt != activeAnimEdgeTimes.end(); ++edgeIDIt)
		{
			edge_data *pulsingEdge;
			if (internalProtoGraph->edge_exists(edgeIDIt->first, &pulsingEdge))
				set_edge_alpha(edgeIDIt->first, animlinedata, ANIM_INACTIVE_EDGE_ALPHA);
		}
	}
}

void plotted_graph::maintain_active()
{
	if (!animnodesdata->get_numVerts()) return;
	map<NODEINDEX, int>::iterator nodeAPosTimeIt = activeAnimNodeTimes.begin();

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
			assert(internalProtoGraph->edge_exists(edgeIDIt->first,0));

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
	set<NODEINDEX>::iterator alphaPosIt = fadingAnimNodes.begin();
	while (alphaPosIt != fadingAnimNodes.end())
	{
		NODEINDEX nodeAlphaIndex = *alphaPosIt;

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

		const size_t arrIndexNodeAlpha = (nodeIdx * COLELEMS) + AOFF;
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
			set <NODEINDEX>::iterator fadeIt = fadingAnimNodes.find(arrIndexNodeAlpha);
			if (fadeIt != fadingAnimNodes.end())
				fadingAnimNodes.erase(fadeIt);
		}
		else
			fadingAnimNodes.insert(arrIndexNodeAlpha);

		vertIDIt = newAnimNodeTimes.erase(vertIDIt);
	}
}

void plotted_graph::setAnimated(bool newState)
{
	if (isAnimated())
	{
		animation_needs_reset = true;
	}

	animated = newState;
}

void plotted_graph::brighten_new_active_extern_nodes()
{
	PROCESS_DATA *piddata = internalProtoGraph->get_piddata();
	map <NODEINDEX, EXTTEXT> newEntries;
	map <pair<NODEINDEX, unsigned long>, int>::iterator externTimeIt = newExternTimes.begin();
	while (externTimeIt != newExternTimes.end())
	{
		NODEINDEX externNodeIdx = externTimeIt->first.first;
		unsigned long callsSoFar = externTimeIt->first.second;

		internalProtoGraph->getNodeReadLock();

		node_data *externNode = internalProtoGraph->unsafe_get_node(externNodeIdx);
		ARGLIST *args = NULL;
		unsigned long callRecordIndex = NULL;

		internalProtoGraph->externCallsLock.lock();
		if (callsSoFar < externNode->callRecordsIndexs.size())
		{
			callRecordIndex = externNode->callRecordsIndexs.at(callsSoFar);
			//todo: maybe make a local copy instead of holding the mutex
			if (callRecordIndex < internalProtoGraph->externCallRecords.size())
				args = &internalProtoGraph->externCallRecords.at(callRecordIndex).argList; 
		}

		MEM_ADDRESS insaddr = externNode->address;
		int globalModIDule = externNode->globalModID;

		internalProtoGraph->dropNodeReadLock();

		string externString = generate_funcArg_string(internalProtoGraph->get_node_sym(externNodeIdx), args);
		internalProtoGraph->externCallsLock.unlock();

		boost::filesystem::path modulePath;
		piddata->get_modpath(globalModIDule, &modulePath);

		stringstream callLogEntry;
		callLogEntry << "0x" << std::hex << insaddr << ": ";
		callLogEntry << modulePath << " -> ";
		callLogEntry << externString << "\n";
		internalProtoGraph->loggedCalls.push_back(callLogEntry.str());

		EXTTEXT extEntry;
		extEntry.framesRemaining = externTimeIt->second;
		extEntry.displayString = externString;
		extEntry.yOffset = 10;

		newEntries[externNodeIdx] = extEntry;

		externTimeIt = newExternTimes.erase(externTimeIt);
	}

	internalProtoGraph->externCallsLock.lock();
	map <NODEINDEX, EXTTEXT>::iterator entryIt = newEntries.begin();
	for (; entryIt != newEntries.end(); ++entryIt)
		activeExternTimes[entryIt->first] = entryIt->second;
	internalProtoGraph->externCallsLock.unlock();
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
	if (!animnodesdata->get_numVerts()) return;

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


//makes the active highlight line point to the last instruction executed
void plotted_graph::highlight_last_active_node()
{
	if (internalProtoGraph->lastNode < mainnodesdata->get_numVerts())
		lastAnimatedNode = internalProtoGraph->lastNode;
}

void plotted_graph::render_live_animation(float fadeRate)
{
	process_live_animation_updates();
	render_animation(fadeRate);
}


void plotted_graph::render_replay_animation(float fadeRate)
{

	if (userSelectedAnimPosition != -1)
	{
		schedule_animation_reset();
		reset_animation_if_scheduled();

		setAnimated(true);

		int selectionDiff;
		if (userSelectedAnimPosition < 20 || internalProtoGraph->savedAnimationData.size() < 20)
		{
			animationIndex = 0;
			selectionDiff = userSelectedAnimPosition;
		}
		else
			animationIndex = userSelectedAnimPosition - 20;

		process_replay_animation_updates(20);
	}
	else
		process_replay_animation_updates();
	
	render_animation(fadeRate);

	if (userSelectedAnimPosition != -1)
		userSelectedAnimPosition = -1;
}

void plotted_graph::reset_mainlines()
{
	mainlinedata->reset();
	animlinedata->reset();
}


void plotted_graph::display_highlight_lines(vector<NODEINDEX> *nodePtrList, QColor *colour, int lengthModifier, graphGLWidget *gltarget)
{
	vector<NODEINDEX>::iterator nodeIt = nodePtrList->begin();
	for (; nodeIt != nodePtrList->end(); ++nodeIt)
	{
		drawHighlight(*nodeIt, main_scalefactors, colour, lengthModifier, gltarget);
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

//renders edgePerRender edges of graph onto the preview data
int plotted_graph::render_new_preview_edges()
{
	//draw edges
	EDGELIST::iterator edgeIt, edgeEnd;
	//todo, this should be done without the mutex using indexing instead of iteration
	internalProtoGraph->start_edgeL_iteration(&edgeIt, &edgeEnd);

	std::advance(edgeIt, previewlines->get_renderedEdges());
	if (edgeIt != edgeEnd)
		needVBOReload_preview = true;

	int remainingEdges = clientState->config.preview.edgesPerRender;
	for (; edgeIt != edgeEnd; ++edgeIt)
	{
		if (edgeIt->first >= previewnodes->get_numVerts())
		{
			node_data *n = internalProtoGraph->safe_get_node(edgeIt->first);
			add_node(n, &lastPreviewNode, previewnodes, 0, preview_scalefactors);
		}

		if (edgeIt->second >= previewnodes->get_numVerts())
		{
			edge_data *e = &internalProtoGraph->edgeDict.at(*edgeIt);
			if (e->edgeClass == eEdgeException)
				lastPreviewNode.lastVertType = eNodeException;

			node_data *n = internalProtoGraph->safe_get_node(edgeIt->second);
			add_node(n, &lastPreviewNode, previewnodes, 0, preview_scalefactors);
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

//displays heatmap of the active graph
void plotted_graph::display_big_heatmap(graphGLWidget *gltarget)
{
	if (!heatmaplines) return;

	if (needVBOReload_heatmap)
	{
		GLsizei heatlineVertsQty = heatmaplines->get_numVerts();
		if (!heatlineVertsQty) return;
		gltarget->load_VBO(0, heatmapEdgeVBO, COLOUR_VERTS_SIZE(heatlineVertsQty), heatmaplines->readonly_col());
		needVBOReload_heatmap = false;
		heatmaplines->set_numLoadedVerts(heatlineVertsQty);
	}

	GRAPH_DISPLAY_DATA *vertsdata = get_mainnodes();
	GRAPH_DISPLAY_DATA *linedata = get_mainlines();
	if (needVBOReload_main)
	{
		gltarget->loadVBOs(graphVBOs, vertsdata, linedata);
		needVBOReload_main = false;
	}

	if (clientState->showNodes)
		gltarget->array_render_points(VBO_NODE_POS, VBO_NODE_COL, graphVBOs, vertsdata->get_numLoadedVerts());

	if (clientState->showEdges)
	{
		
		gltarget->glBindBuffer(GL_ARRAY_BUFFER, graphVBOs[VBO_LINE_POS]);
		
		glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

		gltarget->glBindBuffer(GL_ARRAY_BUFFER, heatmapEdgeVBO[0]);
		glColorPointer(COLELEMS, GL_FLOAT, 0, 0);

		glDrawArrays(GL_LINES, 0, heatmaplines->get_numLoadedVerts());
	}

	float zmul = zoomFactor(cameraZoomlevel, main_scalefactors->plotSize);

	PROJECTDATA pd;
	gltarget->gather_projection_data(&pd);

	if (clientState->should_show_external_symbols(zmul))
		show_external_symbol_labels(&pd, gltarget);

	if (clientState->should_show_internal_symbols(zmul))
		show_internal_symbol_labels(&pd, gltarget);

	if (clientState->should_show_instructions(zmul) && internalProtoGraph->get_num_nodes() > 2)
		draw_edge_heat_text(zmul, &pd, gltarget);
}

#define VBO_COND_NODE_COLOUR 0
#define VBO_COND_LINE_COLOUR 1
//displays the conditionals of the active graph
void plotted_graph::display_big_conditional(graphGLWidget *gltarget)
{
	if (!conditionallines || !conditionalnodes) return;

	if (needVBOReload_conditional)
	{
		GLsizei nodeVertsQty = conditionalnodes->get_numVerts();
		GLsizei lineVertsQty = conditionallines->get_numVerts();

		if (!lineVertsQty || !nodeVertsQty) return;

		gltarget->load_VBO(VBO_COND_NODE_COLOUR, conditionalVBOs, COLOUR_VERTS_SIZE(nodeVertsQty), conditionalnodes->readonly_col());
		conditionalnodes->set_numLoadedVerts(nodeVertsQty);

		gltarget->load_VBO(VBO_COND_LINE_COLOUR, conditionalVBOs, COLOUR_VERTS_SIZE(lineVertsQty), conditionallines->readonly_col());
		conditionallines->set_numLoadedVerts(lineVertsQty);

		needVBOReload_conditional = false;
	}

	if (needVBOReload_main)
	{
		gltarget->loadVBOs(graphVBOs, get_mainnodes(), get_mainlines());
		needVBOReload_main = false;
	}

	if (clientState->showNodes)
	{
		gltarget->glBindBuffer(GL_ARRAY_BUFFER, graphVBOs[VBO_NODE_POS]);
		glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

		gltarget->glBindBuffer(GL_ARRAY_BUFFER, conditionalVBOs[VBO_COND_NODE_COLOUR]);
		glColorPointer(COLELEMS, GL_FLOAT, 0, 0);
		gltarget->glDrawArrays(GL_POINTS, 0, conditionalnodes->get_numLoadedVerts());
	}

	if (clientState->showEdges)
	{
		gltarget->glBindBuffer(GL_ARRAY_BUFFER, graphVBOs[VBO_LINE_POS]);
		glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

		gltarget->glBindBuffer(GL_ARRAY_BUFFER, conditionalVBOs[VBO_COND_LINE_COLOUR]);
		glColorPointer(COLELEMS, GL_FLOAT, 0, 0);
		gltarget->glDrawArrays(GL_LINES, 0, conditionallines->get_numLoadedVerts());

	}

	PROJECTDATA pd;
	gltarget->gather_projection_data(&pd);
	float zoomDiffMult = (cameraZoomlevel - main_scalefactors->plotSize) / 1000 - 1;

	if (clientState->should_show_instructions(zoomDiffMult) && internalProtoGraph->get_num_nodes() > 2)
		draw_condition_ins_text(zoomDiffMult, &pd, conditionalnodes, gltarget);

}



//should be same as rendering for main graph but - the animation + more pauses instead of all at once
int plotted_graph::render_preview_graph()
{
	bool doResize = false;
	needVBOReload_preview = true;

	if (previewNeedsResize)
	{
		assert(false);
		previewlines->reset();
		previewNeedsResize = false;
	}

	if (!render_new_preview_edges())
	{
		cerr << "ERROR: Failed drawing new edges in render_preview_graph! " << endl;
		//assert(0);
	}
	return 1;
}

void plotted_graph::updateMainRender()
{
	render_static_graph();
}

void plotted_graph::gen_graph_VBOs(graphGLWidget *gltarget)
{
	gltarget->glGenBuffers(4, graphVBOs);
	gltarget->glGenBuffers(4, previewVBOs);
	gltarget->glGenBuffers(1, heatmapEdgeVBO);
	gltarget->glGenBuffers(2, conditionalVBOs);
	gltarget->glGenBuffers(4, activeVBOs);
	VBOsGenned = true;
}


//iterate through all the nodes, draw instruction text for the ones in view
//TODO: in animation mode don't show text for inactive nodes
void plotted_graph::draw_instructions_text(int zdist, PROJECTDATA *pd, graphGLWidget *gltarget)
{

	gltarget->glBindBuffer(GL_ARRAY_BUFFER, 0);

	stringstream ss;
	DCOORD screenCoord;
	string displayText("?");

	SCREEN_QUERY_PTRS screenInfo;
	screenInfo.mainverts = get_mainnodes();
	screenInfo.pd = pd;
	screenInfo.show_all_always = clientState->config.instructionTextVisibility.fullPaths;

	int pp = 0;
	QPainter painter(gltarget);
	painter.setPen(clientState->config.mainColours.instructionText);
	painter.setFont(clientState->instructionFont);
	NODEINDEX numVerts = (NODEINDEX)internalProtoGraph->get_num_nodes();
	for (NODEINDEX i = 0; i < numVerts; ++i)
	{
		node_data *n = internalProtoGraph->safe_get_node(i);

		if (n->external) continue;
		if (!get_visible_node_pos(i, &screenCoord, &screenInfo, gltarget)) continue;

		if (screenInfo.show_all_always)
			displayText = n->ins->ins_text;
		else
		{
			//if zoomed in close show the full instruction, else show a mnemonic
			if (zdist < 5)
				displayText = n->ins->ins_text;
			else
				displayText = n->ins->mnemonic;
		}

		if (n->ins->itype == eNodeType::eInsCall || n->ins->itype == eNodeType::eInsJump)
		{
			//extract instruction address?
		}


		ss << std::dec << i;
		if (clientState->config.instructionTextVisibility.addresses)
			ss << " 0x"  << std::hex << n->ins->address;
		else
			ss << " +0x" << std::hex << (n->ins->address - get_protoGraph()->moduleBase);
		ss << ": " << displayText;


		painter.drawText(screenCoord.x + INS_X_OFF, gltarget->height() - screenCoord.y + INS_Y_OFF, ss.str().c_str());
		ss.str("");
		pp++;
	}
	painter.end();
	//cout << "drew " << pp << " ins texts" << endl;
}

void plotted_graph::draw_internal_symbol(DCOORD screenCoord, node_data *n, graphGLWidget *gltarget, QPainter *painter, const QFontMetrics *fontMetric)
{
	string symString;
	MEM_ADDRESS offset = n->address - get_protoGraph()->get_traceRecord()->modBounds.at(n->globalModID)->first;
	get_protoGraph()->get_piddata()->get_sym(n->globalModID, n->address, symString);
	if (symString.empty()) 
	{
		ADDRESS_OFFSET nodeoffset = n->address - internalProtoGraph->moduleBase;
		auto placeholderNameIt = internalPlaceholderFuncNames.find(nodeoffset);
		if (placeholderNameIt == internalPlaceholderFuncNames.end()) return;

		symString = placeholderNameIt->second.second;
	}

	
	int textLength = fontMetric->width(symString.c_str());
	int textHeight = fontMetric->height();

	TEXTRECT textrect;
	textrect.rect.setX(screenCoord.x - textLength);
	textrect.rect.setWidth(textLength);
	textrect.rect.setY(gltarget->height() - screenCoord.y + INS_Y_OFF - textHeight);
	textrect.rect.setHeight(textHeight);
	textrect.index = n->index;

	labelPositions.push_back(textrect);
	painter->drawText(textrect.rect.x(), textrect.rect.y() + textHeight, symString.c_str());
}

void plotted_graph::draw_internal_symbol(DCOORD screenCoord, node_data *n, graphGLWidget *gltarget, QPainter *painter, const QFontMetrics *fontMetric, string symbolText)
{
	int textLength = fontMetric->width(symbolText.c_str());
	int textHeight = fontMetric->height();

	TEXTRECT textrect;
	textrect.rect.setX(screenCoord.x - textLength);
	textrect.rect.setWidth(textLength);
	textrect.rect.setY(gltarget->height() - screenCoord.y + INS_Y_OFF - textHeight);
	textrect.rect.setHeight(textHeight);
	textrect.index = n->index;

	labelPositions.push_back(textrect);
	painter->drawText(textrect.rect.x(), textrect.rect.y() + textHeight, symbolText.c_str());
}

void plotted_graph::draw_func_args(QPainter *painter, DCOORD screenCoord, node_data *n, graphGLWidget *gltarget, const QFontMetrics *fontMetric)
{
	proto_graph * protoGraph = get_protoGraph();
	if (protoGraph->externalNodeList.empty()) return;

	PROCESS_DATA *piddata = protoGraph->get_piddata();

	boost::filesystem::path modulePath;
	piddata->get_modpath(n->globalModID, &modulePath);

	stringstream argstring;
	argstring << "(" << n->index << ")";
	if (clientState->config.externalSymbolVisibility.fullPaths)
		argstring << modulePath << ":";

	int numCalls = n->calls;
	string symString;

	MEM_ADDRESS offset = n->address - get_protoGraph()->get_traceRecord()->modBounds.at(n->globalModID)->first;

	if (!clientState->config.externalSymbolVisibility.addresses)
		piddata->get_sym(n->globalModID, offset, symString);


	//todo: might be better to find the first symbol in the DLL that has a lower address
	if (symString.empty())
		argstring << modulePath.filename().string();
	
	if (clientState->config.externalSymbolVisibility.addresses)
		argstring << ": 0x" << std::hex << n->address;
	else
		argstring << ": +0x" << std::hex << offset;

	if (numCalls > 1)
		argstring << " " << n->calls << "x";

	argstring << " " << symString;

	protoGraph->externCallsLock.lock();
	if (n->callRecordsIndexs.empty() || !clientState->config.externalSymbolVisibility.arguments)
		argstring << " ()";
	else
	{
		try
		{

			argstring << " (";

			unsigned long callRecordIndex = n->callRecordsIndexs.front();
			vector<ARGIDXDATA> *args = &protoGraph->externCallRecords.at(callRecordIndex).argList;
			vector<ARGIDXDATA>::iterator argIt = args->begin();

			while (argIt != args->end())
			{
				argstring << argIt->first << ": " << argIt->second;
				if (argIt++ != args->end())
					argstring << ", ";
			}
		}
		catch (std::exception const & e) {
			cerr << "[rgat]Warning: Exception building argstring." << endl;
		}

		int remainingCalls = n->callRecordsIndexs.size() - 1;
		if (remainingCalls)
			argstring << ") +" << remainingCalls << "saved";
		else
			argstring << ")";
	}
	protoGraph->externCallsLock.unlock();

	int textLength = fontMetric->width(argstring.str().c_str());
	int textHeight = fontMetric->height();

	TEXTRECT textrect;
	textrect.rect.setX(screenCoord.x + INS_X_OFF + 10);
	textrect.rect.setWidth(textLength);
	textrect.rect.setY(gltarget->height() - screenCoord.y + INS_Y_OFF - textHeight);
	textrect.rect.setHeight(textHeight);
	textrect.index = n->index;

	labelPositions.push_back(textrect);

	painter->drawText(textrect.rect.x(), textrect.rect.y() + textHeight, argstring.str().c_str());
}

//show functions/args for externs in active graph if settings allow
void plotted_graph::show_external_symbol_labels(PROJECTDATA *pd, graphGLWidget *gltarget)
{
	SCREEN_QUERY_PTRS screenInfo;
	screenInfo.mainverts = get_mainnodes();
	screenInfo.pd = pd;
	screenInfo.show_all_always = false;

	QPainter painter(gltarget);
	painter.setPen(clientState->config.mainColours.symbolTextExternal);
	painter.setFont(clientState->instructionFont);
	const QFontMetrics fm(clientState->instructionFont);

	TEXTRECT mouseoverNode;
	bool hasMouseover;
	hasMouseover = gltarget->getMouseoverNode(&mouseoverNode);

	vector<NODEINDEX> externalNodeList = internalProtoGraph->copyExternalNodeList();

	vector<NODEINDEX>::iterator externCallIt = externalNodeList.begin();
	for (; externCallIt != externalNodeList.end(); ++externCallIt)
	{
		node_data *n = internalProtoGraph->safe_get_node(*externCallIt);
		if (!n || !n->external)
			break;

		DCOORD screenCoord;
		if (get_visible_node_pos(n->index, &screenCoord, &screenInfo, gltarget))
		{
			if (hasMouseover && mouseoverNode.index == n->index)
			{
				painter.setPen(al_col_orange);
				draw_func_args(&painter, screenCoord, n, gltarget, &fm);
				painter.setPen(clientState->config.mainColours.symbolTextExternal);
			}
			else
				draw_func_args(&painter, screenCoord, n, gltarget, &fm);
		}
	}
	painter.end();

}

void plotted_graph::show_internal_symbol_labels(PROJECTDATA *pd, graphGLWidget *gltarget)
{
	if (this->animnodesdata->get_numVerts() == 0)
		return;

	SCREEN_QUERY_PTRS screenInfo;
	screenInfo.mainverts = get_mainnodes();
	screenInfo.pd = pd;
	screenInfo.show_all_always = false;

	QPainter painter(gltarget);
	painter.setPen(clientState->config.mainColours.symbolTextInternal);
	painter.setFont(clientState->instructionFont);
	const QFontMetrics fm(clientState->instructionFont);

	TEXTRECT mouseoverNode;
	bool hasMouseover;
	hasMouseover = gltarget->getMouseoverNode(&mouseoverNode);


	vector<NODEINDEX> internListCopy = internalProtoGraph->copyInternalNodeList();
	vector<NODEINDEX>::iterator internSymIt = internListCopy.begin();
	for (; internSymIt != internListCopy.end(); ++internSymIt)
	{
		node_data *n = internalProtoGraph->safe_get_node(*internSymIt);
		assert(!n->external);

		DCOORD screenCoord;
		if (get_visible_node_pos(n->index, &screenCoord, &screenInfo, gltarget))
		{
			if (hasMouseover && mouseoverNode.index == n->index)
			{
				painter.setPen(al_col_orange);
				draw_internal_symbol(screenCoord, n, gltarget, &painter, &fm);
				painter.setPen(clientState->config.mainColours.symbolTextInternal);
			}
			else
				draw_internal_symbol(screenCoord, n, gltarget, &painter, &fm);
			
		}
	}

	callStackLock.lock();
	map <ADDRESS_OFFSET, pair<NODEINDEX, string>> placeholderListCopy;
	placeholderListCopy.insert(internalPlaceholderFuncNames.begin(), internalPlaceholderFuncNames.end());
	callStackLock.unlock();

	auto internPlaceholderSymIt = placeholderListCopy.begin();
	for (; internPlaceholderSymIt != placeholderListCopy.end(); ++internPlaceholderSymIt)
	{
		node_data *n = internalProtoGraph->safe_get_node(internPlaceholderSymIt->second.first);
		assert(!n->external);

		DCOORD screenCoord;
		if (get_visible_node_pos(n->index, &screenCoord, &screenInfo, gltarget))
		{
			if (hasMouseover && mouseoverNode.index == n->index)
			{
				painter.setPen(al_col_orange);
				draw_internal_symbol(screenCoord, n, gltarget, &painter, &fm);
				painter.setPen(clientState->config.mainColours.symbolTextInternal);
			}
			else
				draw_internal_symbol(screenCoord, n, gltarget, &painter, &fm);

		}
	}

	painter.end();

}


void plotted_graph::apply_drag(double dx, double dy)
{
	dx = min(1.0, max(dx, -1.0));
	dy = min(1.0, max(dy, -1.0));

	// here we tailor drag speed to the zoom level
	float cameraDistance = abs(get_graph_size() - cameraZoomlevel);
	float slowdown = cameraDistance / 1000;
	if (slowdown > 0)
	{
		//reduce movement this much for every 1000 pixels camera is away
		float slowdownfactor = (float)0.035; 
		if (dx != 0) dx *= (slowdown * slowdownfactor);
		if (dy != 0) dy *= (slowdown * slowdownfactor);
	}

	view_shift_x -= dx;
	view_shift_y -= dy;
}

//only draws text for instructions with unsatisfied conditions
void plotted_graph::draw_condition_ins_text(float zdist, PROJECTDATA *pd, GRAPH_DISPLAY_DATA *vertsdata, graphGLWidget *gltarget)
{
	SCREEN_QUERY_PTRS screenInfo;
	screenInfo.mainverts = get_mainnodes();
	screenInfo.pd = pd;
	screenInfo.show_all_always = false;

	DCOORD screenCoord;

	QPainter painter(gltarget);
	painter.setFont(clientState->instructionFont);

	//iterate through nodes looking for ones that map to screen coords
	gltarget->glBindBuffer(GL_ARRAY_BUFFER, 0);
	
	NODEINDEX numVerts = vertsdata->get_numLoadedVerts();
	GLfloat *vcol = vertsdata->readonly_col();
	QColor textColour;
	textColour.setAlphaF(1);

	bool showMnemonic;

	
	if (clientState->config.instructionTextVisibility.fullPaths)
		showMnemonic = false; //force full instruction always
	else if (zdist > clientState->config.instructionTextVisibility.autoVisibleZoom)
		showMnemonic = false; //full instruction because zoomed in
	else
		showMnemonic = true;

	for (NODEINDEX i = 0; i < numVerts; ++i)
	{
		node_data *n = internalProtoGraph->safe_get_node(i);

		if (n->external || !n->ins->conditional) continue;

		if (!get_visible_node_pos(n->index, &screenCoord, &screenInfo, gltarget)) continue;

		//hmm.. should probably just read a success/fail colour
		//don't think the state is stored anywhere easy to get to (computed then discarded)
		const size_t vectNodePos = n->index*COLELEMS;
		textColour.setRedF(vcol[vectNodePos + ROFF]);
		textColour.setGreenF(vcol[vectNodePos + GOFF]);
		textColour.setBlueF(vcol[vectNodePos + BOFF]);

		string itext;
		if (showMnemonic) 
			itext = n->ins->mnemonic;
		else
			itext = n->ins->ins_text;

		stringstream ss;
		if (clientState->config.instructionTextVisibility.addresses)
			ss << "0x" << std::hex << n->ins->address << ": " << itext;
		else
			ss << "+0x" << std::hex << get_protoGraph()->moduleBase << ": " << itext;

		painter.setPen(textColour);
		painter.drawText(screenCoord.x + INS_X_OFF, gltarget->height() - screenCoord.y + COND_INSTEXT_Y_OFF, ss.str().c_str());
	}
	painter.end();
}


//draw number of times each edge has been executed in middle of edge
void plotted_graph::draw_edge_heat_text(int zdist, PROJECTDATA *pd, graphGLWidget *gltarget)
{
	if (clientState->show_heat_location == eHeatNone) return;

	SCREEN_QUERY_PTRS screenInfo;
	screenInfo.mainverts = get_mainnodes();
	screenInfo.pd = pd;
	screenInfo.show_all_always = false;


	gltarget->glBindBuffer(GL_ARRAY_BUFFER, 0);//need this to make text work

	//iterate through nodes looking for ones that map to screen coords
	int edgelistIdx = 0;
	int edgelistEnd = heatmaplines->get_renderedEdges();

	DCOORD screenCoord;
	set <node_data *> displayNodes;

	QPainter painter(gltarget);
	painter.setFont(clientState->instructionFont);
	painter.setPen(clientState->config.heatmap.lineTextCol);

	EDGELIST *edgelist = internalProtoGraph->edgeLptr();
	//assert(edgelistEnd <= edgelist->size());
	for (; edgelistIdx < edgelistEnd; ++edgelistIdx)
	{
		NODEPAIR *ePair = &edgelist->at(edgelistIdx);
		node_data *firstNode = internalProtoGraph->safe_get_node(ePair->first);

		//should these checks should be done on the midpoint rather than the first node?
		if (firstNode->external) continue; //don't care about instruction in library call

		DCOORD screenCoordA;
		if (!get_visible_node_pos(ePair->first, &screenCoordA, &screenInfo, gltarget)) continue;
	
		edge_data *e = internalProtoGraph->get_edge(*ePair);
		if (!e) {
			cerr << "[rgat]Warning: Heatmap bad edge skip: "<< ePair->first << "," << ePair->second << endl;
			continue;
		}

		if (ePair->second >= internalProtoGraph->get_num_nodes()) continue;
		DCOORD screenCoordB;

		if (!get_visible_node_pos(ePair->first, &screenCoordB, &screenInfo, gltarget)) continue;


		DCOORD screenCoordMid;
		midpoint(&screenCoordA, &screenCoordB, &screenCoordMid);

		if (screenCoordMid.x > gltarget->width() || screenCoordMid.x < -100) continue;
		if (screenCoordMid.y > gltarget->height() || screenCoordMid.y < -100) continue;

		if (clientState->show_heat_location == eHeatEdges)
		{
			unsigned long edgeWeight = e->chainedWeight;
			if (edgeWeight < 2) continue;

			string weightString = to_string(edgeWeight);
			painter.drawText(screenCoord.x + INS_X_OFF, gltarget->height() - screenCoordMid.y + INS_Y_OFF, weightString.c_str());
		}
		else
		{
			displayNodes.insert(firstNode);
			displayNodes.insert(internalProtoGraph->safe_get_node(ePair->second));
		}

	}

	if (clientState->show_heat_location == eHeatNodes)
	{
		QColor textColour;
		textColour.setAlphaF(1.0);
		set <node_data *>::iterator nodesIt = displayNodes.begin();
		for (; nodesIt != displayNodes.end(); ++nodesIt)
		{
			node_data *n = *nodesIt;
			if (n->executionCount == 1) continue;

			DCOORD screenCoordN;
			if (!get_visible_node_pos(n->index, &screenCoordN, &screenInfo, gltarget)) continue;


			QColor *textcol;
			textcol = n->unreliableCount ? &al_col_cyan : &al_col_white;

			painter.setPen(*textcol);
			painter.drawText(screenCoordN.x + INS_X_OFF, gltarget->height() - screenCoordN.y + INS_Y_OFF, to_string(n->executionCount).c_str());
		}
	}
}


void plotted_graph::gl_frame_setup(graphGLWidget *plotwindow)
{
	if (!VBOsGenned)
	{
		gen_graph_VBOs(plotwindow);
	}

	bool zoomedIn = false;
	float zmul = zoomFactor(cameraZoomlevel, main_scalefactors->plotSize);
	if (zmul < FORCE_NEARSIDE_ZOOMFACTOR)
		zoomedIn = true;

	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();

	double windowAspect = plotwindow->getAspect();
	if (zoomedIn || clientState->showNearSide)
	{
		gluPerspective(45, windowAspect, 1.8, abs(cameraZoomlevel) + 500);
		//cout << "noclip from " << 1.8 << " to " << abs(cameraZoomlevel) + 500 << endl;
	}
	else
		gluPerspective(45, windowAspect, 1.8, abs(cameraZoomlevel) + main_scalefactors->plotSize + 50);

	orient_to_user_view();

	
	glEnableClientState(GL_VERTEX_ARRAY);
	glEnableClientState(GL_COLOR_ARRAY);

	glEnable(GL_ALPHA_TEST);
	glEnable(GL_BLEND);
	glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
}


void plotted_graph::performDiffGraphDrawing(graphGLWidget *plotwindow, void *divergeNodePosition)
{
	if (!setGraphBusy(true, 0))
		return;

	GRAPH_DISPLAY_DATA *vertsdata = get_mainnodes();
	GRAPH_DISPLAY_DATA *linedata = get_mainlines();

	if (needVBOReload_main)
	{
		plotwindow->loadVBOs(graphVBOs, vertsdata, linedata);
		needVBOReload_main = false;
	}

	if (clientState->wireframe)
		maintain_draw_wireframe(plotwindow);

	if (clientState->showNodes)
		plotwindow->array_render_points(VBO_NODE_POS, VBO_NODE_COL, graphVBOs, vertsdata->get_numVerts());

	if (clientState->showEdges)
		plotwindow->array_render_lines(VBO_LINE_POS, VBO_LINE_COL, graphVBOs, linedata->get_numVerts());

	if (divergeNodePosition)
	{
		drawHighlight(divergeNodePosition, main_scalefactors, &al_col_orange, 10, plotwindow);
	}

	float zmul = zoomFactor(cameraZoomlevel, main_scalefactors->plotSize);

	PROJECTDATA pd;
	bool pdgathered = false;
	if (clientState->should_show_external_symbols(zmul))
	{
		plotwindow->gather_projection_data(&pd);
		pdgathered = true;
		show_external_symbol_labels(&pd, plotwindow);
	}

	if (clientState->should_show_internal_symbols(zmul))
	{
		plotwindow->gather_projection_data(&pd);
		pdgathered = true;
		show_internal_symbol_labels(&pd, plotwindow);
	}

	if (clientState->should_show_instructions(zmul) &&
		get_protoGraph()->get_num_nodes() > 2)
	{
		if (!pdgathered)
			plotwindow->gather_projection_data(&pd);
		draw_instructions_text(zmul, &pd, plotwindow);
	}

	setGraphBusy(false, 0);
}

void plotted_graph::changeZoom(double delta)
{
	if (delta > 0)
		delta = -500;
	else
		delta = 500;


	cameraZoomlevel += delta;
	if (cameraZoomlevel < 0)
		cameraZoomlevel = 1;
}

void plotted_graph::copy_node_data(GRAPH_DISPLAY_DATA *nodes)
{
	*mainnodesdata = *nodes;
}

void plotted_graph::setHighlightData(vector<NODEINDEX> *nodes, egraphHighlightModes highlightType)
{
	get_protoGraph()->highlightsLock.lock();

	highlightData.highlightNodes.clear();

	if (nodes)
		highlightData.highlightNodes = vector<NODEINDEX>(*nodes);

	highlightData.highlightState = highlightType;

	get_protoGraph()->highlightsLock.unlock();
}