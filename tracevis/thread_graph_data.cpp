#include "stdafx.h"
#include "thread_graph_data.h"
#include "rendering.h"
#include "GUIStructs.h"


//display live or animated graph with active areas on faded areas
void thread_graph_data::display_active(bool showNodes, bool showEdges)
{
	GRAPH_DISPLAY_DATA *vertsdata = get_activeverts();
	GRAPH_DISPLAY_DATA *linedata = get_activelines();

	if (needVBOReload_active)
	{
		//todo - main ones probably already loaded?
		//void loadVBOs(GLuint *VBOs, GRAPH_DISPLAY_DATA *verts, GRAPH_DISPLAY_DATA *lines)
		//{
		//GLuint *VBOs = graph->activeVBOs;
		glGenBuffers(4, activeVBOs);

		load_VBO(VBO_NODE_POS, activeVBOs, mainvertsdata->pos_size(), mainvertsdata->readonly_pos());
		load_VBO(VBO_NODE_COL, activeVBOs, animvertsdata->col_size(), animvertsdata->readonly_col());

		int posbufsize = mainlinedata->get_numVerts() * POSELEMS * sizeof(GLfloat);
		load_VBO(VBO_LINE_POS, activeVBOs, posbufsize, mainlinedata->readonly_pos());

		int linebufsize = animlinedata->get_numVerts() * COLELEMS * sizeof(GLfloat);
		load_VBO(VBO_LINE_COL, activeVBOs, linebufsize, animlinedata->readonly_col());

		needVBOReload_active = false;
	}

	if (showNodes)
		array_render_points(VBO_NODE_POS, VBO_NODE_COL, activeVBOs, vertsdata->get_numVerts());

	if (showEdges)
		array_render_lines(VBO_LINE_POS, VBO_LINE_COL, activeVBOs, linedata->get_numVerts());
}

//display graph with everything bright and viewable
void thread_graph_data::display_static(bool showNodes, bool showEdges)
{
	if (needVBOReload_main)
	{
		loadVBOs(graphVBOs, mainvertsdata, mainlinedata);
		needVBOReload_main = false;
	}

	if (showNodes)
		array_render_points(VBO_NODE_POS, VBO_NODE_COL, graphVBOs, mainvertsdata->get_numVerts());

	if (showEdges)
		array_render_lines(VBO_LINE_POS, VBO_LINE_COL, graphVBOs, mainlinedata->get_numVerts());
}

//create faded edge version of graph for use in animations
void thread_graph_data::extend_faded_edges()
{
	GLfloat *animecol = animlinedata->acquire_col("2c");
	GLfloat *mainecol = mainlinedata->acquire_col("2c");
	unsigned int drawnVerts = mainlinedata->get_numVerts();
	unsigned int animatedVerts = animlinedata->get_numVerts();

	assert(drawnVerts >= animatedVerts);
	int pendingVerts = drawnVerts - animatedVerts;
	if (!pendingVerts) return;

	unsigned int fadedIndex = animlinedata->get_numVerts() *COLELEMS;
	unsigned int copysize = pendingVerts*COLELEMS * sizeof(GLfloat);
	void *targaddr = animecol + fadedIndex;
	void *srcaddr = mainecol + fadedIndex;
	memcpy(targaddr, srcaddr, copysize);
	mainlinedata->release_col();

	unsigned int index2 = (animlinedata->get_numVerts() *COLELEMS);
	unsigned int end = drawnVerts*COLELEMS;
	for (; index2 < end; index2 += 4)
		animecol[index2 + 3] = 0.1;

	animlinedata->set_numVerts(drawnVerts);
	animlinedata->release_col();
}

//draw edges
void thread_graph_data::render_new_edges(bool doResize, vector<ALLEGRO_COLOR> *lineColoursArr)
{

	GRAPH_DISPLAY_DATA *lines = get_mainlines();
	vector<pair<unsigned int, unsigned int>>::iterator edgeIt;
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
	pair<unsigned long, int> targBlock_Size = bbsequence[sequenceId];
	unsigned long insAddr = targBlock_Size.first;
	int numInstructions = targBlock_Size.second;
	int mutation = mutationSequence[sequenceId];
	INS_DATA *ins = getDisassembly(insAddr, mutation, disassemblyMutex, disassembly, true);
	while (numInstructions > 1)
	{
		insAddr += ins->numbytes;
		//bad feeling about blindly using same mutation here
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

	obtainMutex(callSeqMutex, 0, 1000);
	if (!externCallSequence.count(nodeIdx)) 
	{
		dropMutex(callSeqMutex, "highlight externs");
		return; 
	}

	vector<pair<int, int>> callList = externCallSequence.at(nodeIdx);

	unsigned int callsSoFar = callCounter[nodeIdx];
	callCounter[nodeIdx] = callsSoFar + 1;
	int targetExternIdx;
	
	if (callsSoFar < callList.size()) 
		targetExternIdx = callList.at(callsSoFar).second;
	else //todo. this should prob not happen?
		targetExternIdx = callList.at(0).second;

	dropMutex(callSeqMutex, "highlight externs");

	node_data *n = &vertDict[targetExternIdx];
	if (!n->funcargs.empty())
		return; //handled elsewhere by arg processor

	printf("node %d calls node %d (%s)\n", nodeIdx, targetExternIdx, n->nodeSym.c_str());
	EXTERNCALLDATA ex;
	ex.edgeIdx = make_pair(nodeIdx, targetExternIdx);
	ex.nodeIdx = n->index;

	obtainMutex(funcQueueMutex, "End Highlight Externs", INFINITE);
	funcQueue.push(ex);
	dropMutex(funcQueueMutex, "End Highlight Externs");

}

void thread_graph_data::emptyArgQueue()
{
	obtainMutex(funcQueueMutex, "End thread purge args", 3000);
	while (!funcQueue.empty()) funcQueue.pop();
	dropMutex(funcQueueMutex, "End thread purge args");
}

bool thread_graph_data::decrease_sequence()
{
	return true;
}

bool thread_graph_data::advance_sequence(bool skipLoop = false)
{
	if (sequenceIndex + 1 >= bbsequence.size()) return false;

	animInstructionIndex += bbsequence[sequenceIndex].second;
	//if not looping
	if (!loopStateList.at(sequenceIndex).first)
	{
		sequenceIndex++;
		highlight_externs(sequenceIndex);
		return true;
	}

	//first we update loop progress

	//just started loop
	if (!animLoopStartIdx)
	{
		
		targetIterations = loopStateList.at(sequenceIndex).second;
		printf("start loop %d seq:%d, %d its\n", loopsPlayed, sequenceIndex, targetIterations);
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
		loopIteration = animLoopProgress.at(animLoopIndex) +1;
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
			
			printf("End loop %d seq:%d\n", loopsPlayed, sequenceIndex);
			loopsPlayed++;
			animLoopProgress.clear();
			animLoopStartIdx = 0;
			animLoopIndex = 0;
		}
		else
			animLoopIndex++;
		
		if (sequenceIndex + 1 >= bbsequence.size()) return false;
		sequenceIndex++;

		if (skipLoop)
			while (loopStateList.at(sequenceIndex).first)
				sequenceIndex++;
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
		sequenceIndex++;
		animLoopIndex++;
	}
	return true;
}

void thread_graph_data::performStep(int stepSize, bool skipLoop = false)
{

	if (stepSize > 0)
	{
		for (int i = 0; i < stepSize; i++)
			if (!advance_sequence(skipLoop)) break;

	}
	else if (stepSize < 0)
	{
		stepSize *= -1;
		for (int i = 0; i < stepSize; i++)
			decrease_sequence();
	}

	latest_active_node = derive_anim_node();
}


//return true if animation has ended
unsigned int thread_graph_data::updateAnimation(unsigned int updateSize, bool animationMode, bool skipLoop = false)
{
	if (vertDict.empty()) return ANIMATION_ENDED;

	performStep(updateSize, skipLoop);
	if (!animationMode) return 0;

	bool animation_end = false;

	if (sequenceIndex == bbsequence.size() - 1)
		return ANIMATION_ENDED;


	return 0;
}

void thread_graph_data::darken_animation(float alphaDelta)
{
	
	GLfloat *ecol = animlinedata->acquire_col("2a");

	vector<pair<unsigned int, unsigned int>>::iterator activeEdgeIt = activeEdgeList.begin();

	while (activeEdgeIt != activeEdgeList.end())
	{
		edge_data *e = get_edge(*activeEdgeIt);
		unsigned long edgeStart = e->arraypos;
		float edgeAlpha;
		if (!e->vertSize)
		{
			printf("WARNING: 0 vertsize in darken\n"); animlinedata->release_col();  return;
		}
		for (unsigned int i = 0; i < e->vertSize; i++)
		{
			edgeAlpha = ecol[edgeStart + i*COLELEMS + 3];
			edgeAlpha = fmax(MINIMUM_FADE_ALPHA, edgeAlpha - alphaDelta);
			ecol[edgeStart + i*COLELEMS + 3] = edgeAlpha;
		}	

		if (edgeAlpha == MINIMUM_FADE_ALPHA)
			activeEdgeIt = activeEdgeList.erase(activeEdgeIt);
		else
			activeEdgeIt++;
	}
	animlinedata->release_col();

	GLfloat *ncol = animvertsdata->acquire_col("2b");
	vector<unsigned int>::iterator activeNodeIt = activeNodeList.begin();

	while (activeNodeIt != activeNodeList.end())
	{
		node_data *n = &vertDict[*activeNodeIt];
		unsigned int nodeIndex = n->index;
		float currentAlpha = ncol[(nodeIndex * COLELEMS) + 3];
		currentAlpha = fmax(0.02, currentAlpha - alphaDelta);
		ncol[(nodeIndex * COLELEMS) + 3] = currentAlpha;
		if (currentAlpha == 0.02)
			activeNodeIt = activeNodeList.erase(activeNodeIt);
		else
			activeNodeIt++;
	}

	animvertsdata->release_col();
	needVBOReload_active = true;
}

void thread_graph_data::reset_animation()
{

	last_anim_start = 0;
	last_anim_stop = 0;
	animInstructionIndex = 0;
	newanim = true;

	sequenceIndex = 0;
	blockInstruction = 0;
	if (!vertDict.empty())
		latest_active_node = &vertDict.at(0);
	darken_animation(1.0);
	firstAnimatedBB = 0;
	lastAnimatedBB = 0;
	activeEdgeList.clear();
	activeNodeList.clear();
	loopsPlayed = 0;
	loopIteration = 0;
	targetIterations = 0;
	callCounter.clear();
}

void thread_graph_data::brighten_BBs()
{

	unsigned int lastNodeIdx = 0;
	unsigned int animEnd = sequenceIndex;

	unsigned int animPosition = firstAnimatedBB; 
	if (animPosition == animEnd) return;
	

	map <unsigned long, bool> recentHighlights;
	//place active on new active
	for (; animPosition < animEnd; animPosition++)
	{
		highlight_externs(animPosition);
		//dont re-brighten on same animation frame
		if (recentHighlights.count(animPosition)) continue;
		recentHighlights[animPosition] = true;
		
		
		GLfloat *ncol = animvertsdata->acquire_col("1m");
		GLfloat *ecol = animlinedata->acquire_col("1m");
		while (!ncol || !ecol)
		{
			animvertsdata->release_col();
			animlinedata->release_col();
			printf("BBbright fail\n");
			Sleep(75);
			ncol = animvertsdata->acquire_col("1m2");
			ecol = animlinedata->acquire_col("1m2");
		}

		pair<unsigned long, int> targBlock_Size = bbsequence[animPosition];
		unsigned long insAddr = targBlock_Size.first;
		int numInstructions = targBlock_Size.second;
		int mutation = mutationSequence[animPosition];
		INS_DATA *ins = getDisassembly(insAddr,mutation,disassemblyMutex,disassembly, true);
		if (!ins->threadvertIdx.count(tid))
		{
			printf("WARNING: BrightenBBs going too far? Breaking!\n");
			animvertsdata->release_col();
			animlinedata->release_col();
			break;
		}
	
		unsigned int nodeIdx = ins->threadvertIdx.at(tid);

		//link lastbb to this
		if (lastNodeIdx)
		{
			//if going between two different blocks, draw edges between
			if (animPosition && (bbsequence.at(animPosition) != bbsequence.at(animPosition - 1)))
			{
				pair<unsigned int, unsigned int> edgePair = make_pair(lastNodeIdx, nodeIdx);
				if (!edge_exists(edgePair)) {
					printf("WARNING: BrightenBBs: lastnode %d->node%d not in edgedict. seq:%d, seqsz:%d\n", 
						lastNodeIdx, nodeIdx, animPosition, bbsequence.size()); 
					continue;
				}

				edge_data *linkingEdge = get_edge(edgePair);

				int numEdgeVerts = linkingEdge->vertSize;
				for (int i = 0; i < numEdgeVerts; i++) {
					ecol[linkingEdge->arraypos + i*COLELEMS + 3] = (float)1.0;
				}
				if (std::find(activeEdgeList.begin(), activeEdgeList.end(), edgePair) == activeEdgeList.end())
					activeEdgeList.push_back(edgePair);
			}
		}

		for (int blockIdx = 0; blockIdx < numInstructions; blockIdx++)
		{
			ncol[(nodeIdx * COLELEMS) + 3] = 1;

			if (std::find(activeNodeList.begin(), activeNodeList.end(), nodeIdx) == activeNodeList.end())
				activeNodeList.push_back(nodeIdx);
			if (blockIdx == numInstructions - 1) break;

			//brighten short edges between internal nodes
			unsigned long nextAddress = ins->address + ins->numbytes;
			INS_DATA* nextIns = getDisassembly(nextAddress, mutation, disassemblyMutex, disassembly, false);

			unsigned int nextInsIndex = nextIns->threadvertIdx.at(tid);
			pair<unsigned int, unsigned int> edgePair = make_pair(nodeIdx, nextInsIndex);

			unsigned long edgeColPos = get_edge(edgePair)->arraypos;
			ecol[edgeColPos + 3] = (float)1.0;
			ecol[edgeColPos + COLELEMS + 3] = (float)1.0;
			if (std::find(activeEdgeList.begin(), activeEdgeList.end(), edgePair) == activeEdgeList.end())
				activeEdgeList.push_back(edgePair);

			nodeIdx = nextInsIndex;
			ins = nextIns;
		}
		lastNodeIdx = nodeIdx;
		animvertsdata->release_col();
		animlinedata->release_col();
	}

	needVBOReload_active = true;
}

/*
take the latestnode-ANIMATION_WIDTH->latestnode steps from the main graph
take the rest from the faded graph
combine, season to taste
*/
void thread_graph_data::animate_latest()
{
	darken_animation(ANIMATION_FADE_RATE);

	sequenceIndex = bbsequence.size() - 1;
	
	firstAnimatedBB = lastAnimatedBB;
	lastAnimatedBB = sequenceIndex;

	brighten_BBs();	
}

void thread_graph_data::update_animation_render()
{
	darken_animation(ANIMATION_FADE_RATE);

	firstAnimatedBB = sequenceIndex - ANIMATION_WIDTH;
	brighten_BBs();
}

node_data *thread_graph_data::derive_anim_node()
{

	//good thing we are only doing this once per frame
	pair<unsigned long, int> seq_size = bbsequence[sequenceIndex];
	unsigned long bbseq = seq_size.first;
	int remainingInstructions = blockInstruction;
	int mutation = mutationSequence[sequenceIndex];
	INS_DATA *target_ins = getDisassembly(bbseq, mutation, disassemblyMutex, disassembly, true);
	
	//would put the end sequence instead of doing this
	//but that ruins us if something jumps in middle of an opcode
	while (remainingInstructions)
	{
		bbseq += target_ins->numbytes;
		target_ins = getDisassembly(bbseq, mutation, disassemblyMutex, disassembly, false);
		remainingInstructions--;
	}

	node_data *n = &vertDict[target_ins->threadvertIdx.at(tid)];
	return n;

}

void thread_graph_data::reset_mainlines() {
	delete mainlinedata;
	mainlinedata = new GRAPH_DISPLAY_DATA(40000);
	delete animlinedata;
	animlinedata = new GRAPH_DISPLAY_DATA(40000);
}

bool thread_graph_data::edge_exists(pair<int, int> edgePair)
{
	bool result = false;
	obtainMutex(edMutex);
	if (edgeDict.count(edgePair)) result = true;
	dropMutex(edMutex);
	return result;
}

edge_data *thread_graph_data::get_edge(pair<int, int> edgePair)
{
	obtainMutex(edMutex);
	edge_data *linkingEdge = &edgeDict.at(edgePair);
	dropMutex(edMutex);
	return linkingEdge;
}

int thread_graph_data::render_edge(pair<int, int> ePair, GRAPH_DISPLAY_DATA *edgedata, vector<ALLEGRO_COLOR> *lineColours,	
	ALLEGRO_COLOR *forceColour, bool preview)
{

	node_data *sourceNode = &vertDict.at(ePair.first);
	node_data *targetNode = &vertDict.at(ePair.second);
	edge_data *e = get_edge(ePair);

	MULTIPLIERS *scaling;
	if (preview)
		scaling = p_scalefactors;
	else
		scaling = m_scalefactors;

	FCOORD srcc = sourceNode->sphereCoordB(scaling, 0);
	FCOORD targc = targetNode->sphereCoordB(scaling, 0);

	unsigned int eClass = e->edgeClass;
	if (eClass >= lineColours->size())
	{
		printf("ILLEGAL COLOUR!\n");
		return 0;
	}

	int arraypos = 0;
	ALLEGRO_COLOR *edgeColour;
	if (forceColour) edgeColour = forceColour;
	else
		edgeColour = &lineColours->at(e->edgeClass);

	int vertsDrawn = drawCurve(edgedata, &srcc, &targc,
		edgeColour, e->edgeClass, scaling, &arraypos);
	
	if (!preview)
	{
		e->vertSize = vertsDrawn;
		e->arraypos = arraypos;
	}

	return 1;

}

node_data* thread_graph_data::get_active_node()
{
	if (!latest_active_node && !vertDict.empty())
		latest_active_node = &vertDict[0];
	return latest_active_node;
}

thread_graph_data::thread_graph_data(map <unsigned long, vector<INS_DATA*>> *disasPtr, HANDLE mutex)
{
	disassembly = disasPtr;
	disassemblyMutex = mutex;

	mainvertsdata = new GRAPH_DISPLAY_DATA(40000);
	mainlinedata = new GRAPH_DISPLAY_DATA(40000);

	animlinedata = new GRAPH_DISPLAY_DATA(40000);
	animvertsdata = new GRAPH_DISPLAY_DATA(40000);

	previewlines = new GRAPH_DISPLAY_DATA(40000);
	previewlines->setPreview();
	previewverts = new GRAPH_DISPLAY_DATA(40000);
	previewverts->setPreview();

	conditionallines = new GRAPH_DISPLAY_DATA(40000);
	conditionalverts = new GRAPH_DISPLAY_DATA(40000);
	heatmaplines = new GRAPH_DISPLAY_DATA(40000);
	needVBOReload_conditional = true;
	needVBOReload_heatmap = true;
	needVBOReload_main = true;
	needVBOReload_preview = true;
	m_scalefactors = new MULTIPLIERS;
	p_scalefactors = new MULTIPLIERS;
	p_scalefactors->HEDGESEP = 0.15;
	p_scalefactors->VEDGESEP = 0.11;
	p_scalefactors->radius = 200;
}


void thread_graph_data::start_edgeL_iteration(vector<pair<unsigned int, unsigned int>>::iterator *edgeIt,
	vector<pair<unsigned int, unsigned int>>::iterator *edgeEnd)
{
	obtainMutex(edMutex);
	*edgeIt = edgeList.begin();
	*edgeEnd = edgeList.end();
}

void thread_graph_data::stop_edgeL_iteration()
{
	dropMutex(edMutex);
}

void thread_graph_data::start_edgeD_iteration(map<std::pair<unsigned int, unsigned int>, edge_data>::iterator *edgeIt,
	map<std::pair<unsigned int, unsigned int>, edge_data>::iterator *edgeEnd)
{
	obtainMutex(edMutex);
	*edgeIt = edgeDict.begin();
	*edgeEnd = edgeDict.end();
}

void thread_graph_data::insert_vert(int targVertID, node_data node)
{
	obtainMutex(vertDMutex, "Insert Vert");
	vertDict.insert(make_pair(targVertID, node));
	dropMutex(vertDMutex, "Insert Vert");
}

void thread_graph_data::stop_edgeD_iteration()
{
	dropMutex(edMutex);
}

void thread_graph_data::add_edge(edge_data e, pair<int, int> edgePair)
{
	obtainMutex(edMutex);
	edgeDict.insert(make_pair(edgePair, e));
	edgeList.insert(edgeList.end(), edgePair);
	dropMutex(edMutex);
}

thread_graph_data::~thread_graph_data()
{
}


void thread_graph_data::set_edge_alpha(pair<unsigned int, unsigned int> eIdx, GRAPH_DISPLAY_DATA *edgesdata, float alpha)
{
	edge_data *e = get_edge(eIdx);
	GLfloat *colarray = edgesdata->acquire_col("2e");
	for (unsigned int i = 0; i < e->vertSize; i++)
	{
		colarray[e->arraypos + i*COLELEMS + 3] = alpha;
	}
	edgesdata->release_col();
}

void thread_graph_data::set_node_alpha(unsigned int nIdx, GRAPH_DISPLAY_DATA *nodesdata, float alpha)
{
	GLfloat *colarray = nodesdata->acquire_col("2f");
	colarray[nIdx*COLELEMS + 3] = alpha;
	nodesdata->release_col();
}


void thread_graph_data::assign_modpath(PID_DATA *pidinfo) 
{
	baseMod = vertDict[0].nodeMod;
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
	map<unsigned int, node_data>::iterator vertit = vertDict.begin();
	for (; vertit != vertDict.end(); vertit++)
		vertit->second.serialise(file);
	*file << "}N,";

	*file << "D{";
	map<std::pair<unsigned int, unsigned int>, edge_data>::iterator edgeDit = edgeDict.begin();
	for (; edgeDit != edgeDict.end(); edgeDit++)
		edgeDit->second.serialise(file, edgeDit->first.first, edgeDit->first.second);
	*file << "}D,";

	*file << "L{";
	vector<pair<unsigned int, unsigned int>>::iterator edgeLit = edgeList.begin();
	for (; edgeLit != edgeList.end(); edgeLit++)
	{
		*file << edgeLit->first << "," << edgeLit->second << ",";
		pair<int, int> testpair = make_pair(edgeLit->first, edgeLit->second);
		if (edgeDict.count(testpair) == 0)
			printf("SAVE ERROR: LIST ITEM NOT IN DICT %d,%d\n", edgeLit->first, edgeLit->second);
	}
	*file << "}L,";

	*file << "E{";
	vector<pair<int, long>>::iterator externit = externList.begin();
	for (; externit != externList.end(); externit++)
		*file << externit->first << "," << externit->second << ",";
	*file << "}E,";

	//S for stats
	*file << "S{" << maxA << ","
		<< maxB << ","
		<< maxWeight << "}S";

	*file << "}";
	return true;
}