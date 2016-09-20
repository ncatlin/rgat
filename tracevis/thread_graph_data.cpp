#include "stdafx.h"
#include "thread_graph_data.h"
#include "rendering.h"
#include "GUIStructs.h"
#include "serialise.h"

//display live or animated graph with active areas on faded areas
void thread_graph_data::display_active(bool showNodes, bool showEdges)
{
	GRAPH_DISPLAY_DATA *nodesdata = get_activenodes();
	GRAPH_DISPLAY_DATA *linedata = get_activelines();

	if (needVBOReload_active)// && !isGraphBusy())
	{
		setGraphBusy(true);
		printf("uploading graph\n");
		load_VBO(VBO_NODE_POS, activeVBOs, mainnodesdata->pos_size(), mainnodesdata->readonly_pos());
		load_VBO(VBO_NODE_COL, activeVBOs, animnodesdata->col_size(), animnodesdata->readonly_col());

		GLfloat *buf = mainlinedata->readonly_pos();
		if (!buf) return;
		int posbufsize = mainlinedata->get_numVerts() * POSELEMS * sizeof(GLfloat);
		load_VBO(VBO_LINE_POS, activeVBOs, posbufsize, buf);

		buf = animlinedata->readonly_col();
		if (!buf) return;
		int linebufsize = animlinedata->get_numVerts() * COLELEMS * sizeof(GLfloat);
		load_VBO(VBO_LINE_COL, activeVBOs, linebufsize, buf);

		needVBOReload_active = false;
		setGraphBusy(false);
		printf("uploaded graph\n");
	}
	else
	{
		if (needVBOReload_active) printf("didn't update!\n");
	}

	printf("drawing graph\n");
	if (showNodes)
		array_render_points(VBO_NODE_POS, VBO_NODE_COL, activeVBOs, nodesdata->get_numVerts());

	if (showEdges)
		array_render_lines(VBO_LINE_POS, VBO_LINE_COL, activeVBOs, linedata->get_numVerts());
}

//display graph with everything bright and viewable
void thread_graph_data::display_static(bool showNodes, bool showEdges)
{
	if (needVBOReload_main)
	{
		loadVBOs(graphVBOs, mainnodesdata, mainlinedata);
		needVBOReload_main = false;
	}
	
	if (showNodes)
		array_render_points(VBO_NODE_POS, VBO_NODE_COL, graphVBOs, mainnodesdata->get_numVerts());

	if (showEdges)
		array_render_lines(VBO_LINE_POS, VBO_LINE_COL, graphVBOs, mainlinedata->get_numVerts());
	//printf("drawn %d arrayl verts\n", mainlinedata->get_numVerts());
}

//create faded edge version of graph for use in animations
void thread_graph_data::extend_faded_edges()
{
	vector<GLfloat> *animecol = animlinedata->acquire_col("2c");
	vector<GLfloat> *mainecol = mainlinedata->acquire_col("2c");
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
	for (; index2 < end; index2 += 4)
	{
		animecol->at(index2 + AOFF) = 0; //0.01
	}
	animlinedata->set_numVerts(drawnVerts);
	animlinedata->release_col();
}

//draw edges
void thread_graph_data::render_new_edges(bool doResize, map<int, ALLEGRO_COLOR> *lineColoursArr)
{
	GRAPH_DISPLAY_DATA *lines = get_mainlines();
	EDGELIST::iterator edgeIt;
	obtainMutex(edMutex); //not sure if i should make a list-specific mutex
	if (doResize)
	{
		printf("resetting mainlines for resize\n");
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

INS_DATA* thread_graph_data::get_last_instruction(unsigned long sequenceId)
{
	obtainMutex(animationListsMutex, "get last ins", 1000);
	pair<unsigned long, int> targBlock_Size = bbsequence.at(sequenceId);
	int mutation = mutationSequence.at(sequenceId);
	dropMutex(animationListsMutex);

	unsigned long insAddr = targBlock_Size.first;
	int numInstructions = targBlock_Size.second;
	
	INS_DATA *ins = getDisassembly(insAddr, mutation, disassemblyMutex, disassembly, true);
	while (numInstructions > 1)
	{
		insAddr += ins->numbytes;
		//possible source of inaccuracy here, see comments within
		ins = getDisassembly(insAddr, mutation, disassemblyMutex, disassembly, false);
		numInstructions--;
	}
	return ins;
}

void thread_graph_data::highlight_externs(unsigned long targetSequence)
{
	//check if block called an extern
	INS_DATA* ins = get_last_instruction(targetSequence);
	int nodeIdx = ins->threadvertIdx[tid];

	obtainMutex(animationListsMutex, 0, 1000);
	map <unsigned int, EDGELIST>::iterator externit = externCallSequence.find(nodeIdx);
	if (externit == externCallSequence.end())
	{
		dropMutex(animationListsMutex, "highlight externs");
		return; 
	}

	EDGELIST callList = externit->second;

	unsigned int callsSoFar = callCounter[nodeIdx];
	callCounter[nodeIdx] = callsSoFar + 1;
	int targetExternIdx;
	
	if (callsSoFar < callList.size()) 
		targetExternIdx = callList.at(callsSoFar).second;
	else //todo. this should prob not happen?
		targetExternIdx = callList.at(0).second;

	dropMutex(animationListsMutex, "highlight externs");

	node_data *n = get_node(targetExternIdx);
	if (!n->funcargs.empty())
		return; //handled elsewhere by arg processor

	EXTERNCALLDATA ex;
	ex.edgeIdx = make_pair(nodeIdx, targetExternIdx);
	ex.nodeIdx = n->index;

	obtainMutex(funcQueueMutex, "End Highlight Externs", INFINITE);
	funcQueue.push(ex);
	dropMutex(funcQueueMutex, "End Highlight Externs");

}

string thread_graph_data::get_node_sym(unsigned int idx, PROCESS_DATA* piddata)
{
	node_data *n = get_node(idx);
	map <int, std::map<long, string>>::iterator symMapIt;
	symMapIt = piddata->modsyms.find(n->nodeMod);
	if (symMapIt == piddata->modsyms.end())
		return ("NOSYM2");

	map<long, string> *modSyms = &symMapIt->second;
	map<long, string>::iterator symIt = modSyms->find(n->address);
	if (symIt == modSyms->end())
		return("NOSYM");

	return symIt->second;
}

void thread_graph_data::emptyArgQueue()
{
	obtainMutex(funcQueueMutex, "End thread purge args", 3000);
	while (!funcQueue.empty()) funcQueue.pop();
	dropMutex(funcQueueMutex, "End thread purge args");
}

bool thread_graph_data::decrease_sequence()
{
	return true; //unimplemented
}

bool thread_graph_data::advance_sequence(bool skipLoop = false)
{
	if (sequenceIndex + 1 >= bbsequence.size()) return false;

	animInstructionIndex += bbsequence.at(sequenceIndex).second;
	//if not looping
	if (!loopStateList.at(sequenceIndex).first)
	{
		++sequenceIndex;
		highlight_externs(sequenceIndex);
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

	highlight_externs(sequenceIndex);

	//now set where to go next
	//last iteration of loop
	if (skipLoop || (loopStateList.at(sequenceIndex).second == animLoopProgress.at(animLoopIndex)))
	{
		//end of loop
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

	//end of loop
	else if (loopStateList.at(sequenceIndex).first != loopStateList.at(sequenceIndex + 1).first)
	{
		sequenceIndex = animLoopStartIdx;
		animLoopIndex = 0;
	}
	else
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


//return true if animation has ended
unsigned int thread_graph_data::updateAnimation(unsigned int updateSize, bool animationMode, bool skipLoop = false)
{
	if (nodeList.empty()) return ANIMATION_ENDED;

	performStep(updateSize, skipLoop);
	if (!animationMode) return 0;

	bool animation_end = false;

	if (sequenceIndex == bbsequence.size() - 1)
		return ANIMATION_ENDED;


	return 0;
}

//25% of the cpu activity of the visualiser here
void thread_graph_data::darken_animation(float alphaDelta)
{
	if (!animlinedata->get_numVerts()) return;
	GLfloat *ecol = &animlinedata->acquire_col("2a")->at(0);

	map<NODEPAIR, edge_data *>::iterator activeEdgeIt = activeEdgeMap.begin();
	bool update = false;

	if (activeEdgeIt != activeEdgeMap.end()) 
		update = true;
	while (activeEdgeIt != activeEdgeMap.end())
	{
		edge_data *e = activeEdgeIt->second;
		unsigned long edgeStart = e->arraypos;
		float edgeAlpha;
		float newEdgeAlpha;
		assert(e->vertSize);
		for (unsigned int i = 0; i < e->vertSize; ++i)
		{
			const int colBufIndex = edgeStart + i*COLELEMS + AOFF;
			if (colBufIndex >= animlinedata->col_buf_capacity_floats())
			{
				printf("skip darkening\n");
				break;
			}
			edgeAlpha = ecol[colBufIndex];
			//TODO: problems here!
			//streaks left on graph
			//0.05 stored as 0.05000000002
			//0.06 stored as 0.59999999999997
			newEdgeAlpha = fmax(MINIMUM_FADE_ALPHA, edgeAlpha - alphaDelta);
			ecol[colBufIndex] = newEdgeAlpha;
		}	

		if (newEdgeAlpha <= MINIMUM_FADE_ALPHA)
			activeEdgeIt = activeEdgeMap.erase(activeEdgeIt);
		else
			++activeEdgeIt;
	}
	animlinedata->release_col();

	GLfloat *ncol = &animnodesdata->acquire_col("2b")->at(0);
	int colBufSize = animnodesdata->col_buf_capacity_floats();

	map<unsigned int, unsigned int>::iterator activeNodeIt = activeNodeMap.begin();
	if (activeNodeIt != activeNodeMap.end()) update = true;
	while (activeNodeIt != activeNodeMap.end())
	{
		node_data *n = get_node(activeNodeIt->first);
		unsigned int nodeIndex = n->index;

		int colBufIndex = (nodeIndex * COLELEMS) + AOFF;
		if (colBufIndex >= colBufSize) break;
		float currentAlpha = ncol[colBufIndex];
		currentAlpha = fmax(0.00, currentAlpha - alphaDelta);
		ncol[colBufIndex] = currentAlpha;
		if (currentAlpha == 0.00)
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
		highlight_externs(animPosition);
		//dont re-brighten on same animation frame

		if (recentHighlights.count(animPosition)) continue;
		recentHighlights[animPosition] = true;
		GLfloat *ncol = &animnodesdata->acquire_col("1m")->at(0);
		GLfloat *ecol = &animlinedata->acquire_col("1m")->at(0);

		while (!ncol || !ecol) 
		{
			animnodesdata->release_col();
			animlinedata->release_col();
			printf("BBbright fail\n");
			Sleep(75);
			ncol = &animnodesdata->acquire_col("1m2")->at(0);
			ecol = &animlinedata->acquire_col("1m2")->at(0);
		}


		obtainMutex(animationListsMutex);
		pair<unsigned long, int> targBlock_Size = bbsequence.at(animPosition);
		int mutation = mutationSequence.at(animPosition);
		dropMutex(animationListsMutex);
		

		unsigned long insAddr = targBlock_Size.first;
		int numInstructions = targBlock_Size.second;
		
		//not happy about this locking the disassembly db. Move the vertexlist elsewhere
		INS_DATA *ins = getDisassembly(insAddr,mutation,disassemblyMutex,disassembly, true);
		unordered_map<int, int>::iterator vertIt = ins->threadvertIdx.find(tid);
		if (vertIt == ins->threadvertIdx.end())
		{
			printf("WARNING: BrightenBBs going too far? Breaking!\n");
			animnodesdata->release_col();
			animlinedata->release_col();
			break;
		}
		
		obtainMutex(disassemblyMutex, 0, 50); //do we need this?
		unsigned int nodeIdx = vertIt->second;
		dropMutex(disassemblyMutex, 0);

		//link lastbb to this
		if (lastNodeIdx)
		{
			//if going between two different blocks, draw long edge between them
			if (animPosition && (bbsequence.at(animPosition) != bbsequence.at(animPosition - 1)))
			{
				pair<unsigned int, unsigned int> edgePair = make_pair(lastNodeIdx, nodeIdx);
				edge_data *linkingEdge;
				if (!edge_exists(edgePair, &linkingEdge)) {
					printf("WARNING: BrightenBBs: lastnode %d->node%d not in edgedict. seq:%d, seqsz:%d\n", 
						lastNodeIdx, nodeIdx, animPosition, bbsequence.size()); 
					continue;
				}

				int numEdgeVerts = linkingEdge->vertSize;
				for (int i = 0; i < numEdgeVerts; ++i) 
				{
					const int colArrIndex = linkingEdge->arraypos + i*COLELEMS + AOFF;
					if (colArrIndex >= animlinedata->col_buf_capacity_floats())
					{
						printf("DROPOUT EDGE\n");
						dropout = true;
						break;
					}
					ecol[colArrIndex] = (float)1.0;
				}

				if (!activeEdgeMap.count(edgePair))
					activeEdgeMap[edgePair] = linkingEdge;
			}
		}

		
		for (int blockIdx = 0; blockIdx < numInstructions; ++blockIdx)
		{

			const int colArrIndex = (nodeIdx * COLELEMS) + AOFF;
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
			unsigned long nextAddress = ins->address + ins->numbytes;
			INS_DATA* nextIns = getDisassembly(nextAddress, mutation, disassemblyMutex, disassembly, false);
			unsigned int nextInsIndex = nextIns->threadvertIdx.at(tid);
			pair<unsigned int, unsigned int> edgePair = make_pair(nodeIdx, nextInsIndex);

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

}

//replay
void thread_graph_data::update_animation_render(float fadeRate)
{
	darken_animation(fadeRate);

	firstAnimatedBB = sequenceIndex - ANIMATION_WIDTH;
	brighten_BBs();
}

unsigned int thread_graph_data::derive_anim_node()
{

	//TODO this code appears 3 times, genericise it
	obtainMutex(animationListsMutex);
	pair<unsigned long, int> seq_size = bbsequence.at(sequenceIndex);
	int mutation = mutationSequence.at(sequenceIndex);
	dropMutex(animationListsMutex);

	unsigned long bbseq = seq_size.first;
	int remainingInstructions = blockInstruction;
	
	INS_DATA *target_ins = getDisassembly(bbseq, mutation, disassemblyMutex, disassembly, true);
	
	//would put the end sequence instead of doing this
	//but that ruins us if something jumps in middle of an opcode
	while (remainingInstructions)
	{
		bbseq += target_ins->numbytes;
		target_ins = getDisassembly(bbseq, mutation, disassemblyMutex, disassembly, false);
		remainingInstructions--;
	}

	return target_ins->threadvertIdx.at(tid);

}

void thread_graph_data::reset_mainlines() 
{
	mainlinedata->reset();
	animlinedata->reset();
}

bool thread_graph_data::edge_exists(NODEPAIR edge, edge_data **edged)
{
	
	obtainMutex(edMutex);
	EDGEMAP::iterator edgeit = edgeDict.find(edge);
	dropMutex(edMutex);

	if (edgeit == edgeDict.end()) return false;

	*edged = &edgeit->second;
	return true;
}

inline edge_data *thread_graph_data::get_edge(NODEPAIR edgePair)
{
	obtainMutex(edMutex);
	edge_data *linkingEdge = &edgeDict.at(edgePair);
	dropMutex(edMutex);
	return linkingEdge;
}

int thread_graph_data::render_edge(NODEPAIR ePair, GRAPH_DISPLAY_DATA *edgedata, map<int, ALLEGRO_COLOR> *lineColours,
	ALLEGRO_COLOR *forceColour, bool preview)
{

	node_data *sourceNode = get_node(ePair.first);
	node_data *targetNode = get_node(ePair.second);
	edge_data *e = get_edge(ePair);

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
		assert(e->edgeClass < lineColours->size());
		edgeColour = &lineColours->at(e->edgeClass);
	}

	
	int vertsDrawn = drawCurve(edgedata, &srcc, &targc,
		edgeColour, e->edgeClass, scaling, &arraypos);

	if (!preview)
	{
		//printf("drawing main edge %d->%d (size %d)\n", ePair.first, ePair.second, vertsDrawn);
		e->vertSize = vertsDrawn;
		e->arraypos = arraypos;
	}

	return 1;

}

VCOORD *thread_graph_data::get_active_node_coord()
{
	if (nodeList.empty()) return NULL;

	obtainMutex(animationListsMutex, 0, 1000);
	VCOORD *result = &latest_active_node_coord;
	dropMutex(animationListsMutex);

	return result;
}

thread_graph_data::thread_graph_data(map <unsigned long, INSLIST> *disasPtr, HANDLE mutex)
{
	disassembly = disasPtr;
	disassemblyMutex = mutex;

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
	obtainMutex(edMutex);
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
	obtainMutex(edMutex);
	*edgeIt = edgeDict.begin();
	*edgeEnd = edgeDict.end();
}

void thread_graph_data::highlightNodes(vector<node_data *> *nodePtrList, ALLEGRO_COLOR *colour, int lengthModifier)
{
	int nodeListSize = nodePtrList->size();
	for (int nodeIdx = 0; nodeIdx != nodeListSize; ++nodeIdx)
		drawHighlight(&nodePtrList->at(nodeIdx)->vcoord, m_scalefactors, colour, lengthModifier);
}

void thread_graph_data::insert_node(int targVertID, node_data node)
{
	if (!nodeList.empty()) assert(targVertID == nodeList.back().index + 1);
	obtainMutex(nodeLMutex, "Insert Vert");
	nodeList.push_back(node);
	dropMutex(nodeLMutex, "Insert Vert");

}

void thread_graph_data::stop_edgeD_iteration()
{
	dropMutex(edMutex);
}

void thread_graph_data::add_edge(edge_data e, NODEPAIR edgePair)
{
	obtainMutex(edMutex);
	edgeDict.insert(make_pair(edgePair, e));
	edgeList.push_back(edgePair);
	dropMutex(edMutex);
}

thread_graph_data::~thread_graph_data()
{
	printf("deleting animlinedata after threaed die");
	delete animlinedata;
	printf("deleting animvertsdata after threaed die");
	delete animnodesdata;
}


void thread_graph_data::set_edge_alpha(NODEPAIR eIdx, GRAPH_DISPLAY_DATA *edgesdata, float alpha)
{
	edge_data *e = get_edge(eIdx);
	const unsigned int bufsize = edgesdata->col_buf_capacity_floats();
	GLfloat *colarray = &edgesdata->acquire_col("2e")->at(0);
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
	GLfloat *colarray = &nodesdata->acquire_col("2f")->at(0);
	colarray[bufIndex] = alpha;
	nodesdata->release_col();
}


void thread_graph_data::assign_modpath(PROCESS_DATA *pidinfo) 
{
	baseMod = get_node(0)->nodeMod;
	if (baseMod >= (int)pidinfo->modpaths.size()) return;
	string longmodPath = pidinfo->modpaths[baseMod];

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
	EDGEMAP::iterator edgeDIt = edgeDict.begin();
	for (; edgeDIt != edgeDict.end(); ++edgeDIt)
		edgeDIt->second.serialise(file, edgeDIt->first.first, edgeDIt->first.second);
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
		<< totalInstructions
		<< "}S,";

	*file << "A{";
	for (unsigned long i = 0; i < bbsequence.size(); ++i)
	{
		pair<unsigned long, int> seq_size = bbsequence.at(i);
		int mutation = mutationSequence.at(i);

		*file << seq_size.first << "," << seq_size.second << ","
			<< mutationSequence[i] << ","
			<< loopStateList[i].first << ",";
		if (loopStateList[i].first )
			*file << loopStateList[i].second << ",";
	}
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
		//getline(*file, address_s, ',');
		//if (!caught_stol(address_s, &address, 10)) return false;
		externList.push_back(index);
	}
}

bool thread_graph_data::unserialise(ifstream *file, map <unsigned long, INSLIST> *disassembly)
{
	if (!loadNodes(file, disassembly)) { printf("Node load failed\n");  return false; }
	if (!loadEdgeDict(file)) { printf("EdgeD load failed\n");  return false; }
	if (!loadExterns(file)) { printf("Externs load failed\n");  return false; }
	if (!loadStats(file)) { printf("Stats load failed\n");  return false; }
	if (!loadAnimationData(file)) { printf("Animation load failed\n");  return false; }
	if (!loadCallSequence(file)) { printf("Call sequence load failed\n"); return false; }

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

bool thread_graph_data::loadNodes(ifstream *file, map <unsigned long, INSLIST> *disassembly)
{

	if (!verifyTag(file, tag_START, 'N')) {
		printf("Bad node data\n");
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
	pair<unsigned long, int> seq_size;
	pair<unsigned int, unsigned long> loopstateIdx_Its;
	int mutation;

	while (true)
	{
		getline(*file, sequence_s, ',');
		if (sequence_s == "}A") return true;
		if (!caught_stol(sequence_s, &seq_size.first, 10)) break;
		getline(*file, size_s, ',');
		if (!caught_stoi(size_s, &seq_size.second, 10)) break;
		bbsequence.push_back(seq_size);

		getline(*file, mutation_s, ',');
		if (!caught_stoi(mutation_s, &mutation, 10)) break;
		mutationSequence.push_back(mutation);

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