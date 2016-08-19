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

INS_DATA* thread_graph_data::get_last_instruction(unsigned long sequenceId)
{
	pair<unsigned long, int> targBlock_Size = bbsequence[sequenceId];
	unsigned long insAddr = targBlock_Size.first;
	int numInstructions = targBlock_Size.second;
	INS_DATA *ins = disassembly->at(insAddr);
	while (numInstructions > 1)
	{
		insAddr += ins->numbytes;
		ins = disassembly->at(insAddr);
		numInstructions--;
	}
	return ins;
}

void thread_graph_data::highlight_externs(unsigned long targetSequence)
{
	//check if block called an extern
	INS_DATA* ins = get_last_instruction(targetSequence);
	int nodeIdx = ins->threadvertIdx[tid];

	obtainMutex(callSeqMutex, "highlight externs", 1000);
	if (!externCallSequence.count(nodeIdx)) 
	{
		dropMutex(callSeqMutex, "highlight externs");
		return; 
	}
		vector<pair<int, int>> callList = externCallSequence.at(nodeIdx);

		int callsSoFar = callCounter[nodeIdx];
		callCounter[nodeIdx] = callsSoFar + 1;
		int targetExternIdx;
	
		if (callsSoFar < callList.size()) 
			targetExternIdx = callList.at(callsSoFar).second;
		else //todo. this should prob not happen
			targetExternIdx = callList.at(0).second;
	dropMutex(callSeqMutex, "highlight externs");

	node_data *n = &vertDict[targetExternIdx];
	//printf("node %d calls node %d (%s)\n", nodeIdx, targetExternIdx, n->nodeSym.c_str());
	EXTERNCALLDATA ex;
	ex.edgeIdx = make_pair(nodeIdx, targetExternIdx);
	ex.nodeIdx = n->index;
	if (!n->funcargs.empty()) 
	{
		callsSoFar = callCounter[n->index];
		if (callsSoFar < n->funcargs.size())
			ex.fdata = n->funcargs.at(callsSoFar);

		callCounter[n->index] = callsSoFar + 1;
	}

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
	vector <pair<unsigned int, unsigned int>> edgeRemovalList;

	while (activeEdgeIt != activeEdgeList.end())
	{
		edge_data *e = &edgeDict[*activeEdgeIt];
		unsigned long edgeStart = e->arraypos;
		float edgeAlpha;
		for (unsigned int i = 0; i < e->vertSize; i++)
		{
			edgeAlpha = ecol[edgeStart + i*COLELEMS + 3];
			edgeAlpha = fmax(MINIMUM_FADE_ALPHA, edgeAlpha - alphaDelta);
			ecol[edgeStart + i*COLELEMS + 3] = edgeAlpha;

		}	
		if (!edgeAlpha)
			edgeRemovalList.push_back(*activeEdgeIt);
		activeEdgeIt++;
	}
	animlinedata->release_col();

	GLfloat *ncol = animvertsdata->acquire_col("2b");
	vector<unsigned int>::iterator activeNodeIt = activeNodeList.begin();
	vector <unsigned int> nodeRemovalList;

	while (activeNodeIt != activeNodeList.end())
	{
		node_data *n = &vertDict[*activeNodeIt];
		unsigned int nodeIndex = n->index;
		float currentAlpha = ncol[(nodeIndex * COLELEMS) + 3];
		currentAlpha = fmax(0, currentAlpha - alphaDelta);
		ncol[(nodeIndex * COLELEMS) + 3] = currentAlpha;
		if (!currentAlpha)
			nodeRemovalList.push_back(*activeNodeIt);
		activeNodeIt++;
	}

	animvertsdata->release_col();

	
	vector <unsigned int>::iterator nodeRemovalIt = nodeRemovalList.begin();
	while (nodeRemovalIt != nodeRemovalList.end())
	{
		vector <unsigned int>::iterator nodePos = find(activeNodeList.begin(), activeNodeList.end(), *nodeRemovalIt);
		activeNodeList.erase(nodePos);
		nodeRemovalIt++;
	}

	//it might be time for some typedefs
	vector<pair<unsigned int, unsigned int>>::iterator edgeRemovalIt = edgeRemovalList.begin();
	while (edgeRemovalIt != edgeRemovalList.end())
	{
		vector <pair<unsigned int, unsigned int>>::iterator edgePos = find(activeEdgeList.begin(), activeEdgeList.end(), *edgeRemovalIt);
		activeEdgeList.erase(edgePos);
		edgeRemovalIt++;
	}

	needVBOReload_active = true;
}

void thread_graph_data::clear_final_BBs()
{
	GLfloat *ncol = animvertsdata->acquire_col("1k");
	GLfloat *ecol = animlinedata->acquire_col("1k");
	unsigned int lastNodeIdx = 0;
	//place faded on expired active (outside window)
	for (; last_anim_start < last_anim_stop; last_anim_start++)
	{
		//find the verts + copy low alpha into them
		pair<unsigned long, int> targBlock_Size = bbsequence[last_anim_start];
		unsigned long insAddr = targBlock_Size.first;
		int numInstructions = targBlock_Size.second;
		INS_DATA *ins = disassembly->at(insAddr);
		unsigned int nodeIdx = ins->threadvertIdx.at(tid);

		if (last_anim_start > 0)
		{
			if (!lastNodeIdx)
			{
				pair<unsigned long, int> lastBlock_Size = bbsequence.at(last_anim_start - 1);
				unsigned long lastAddr = lastBlock_Size.first;
				int numlastins = lastBlock_Size.second;
				INS_DATA *lastins = disassembly->at(lastAddr);

				while (numlastins-- > 1) {
					lastAddr = lastins->address + lastins->numbytes;
					lastins = disassembly->at(lastAddr);
				}
				lastNodeIdx = lastins->threadvertIdx.at(tid);
			}

			edge_data *linkingEdge = &edgeDict.at(make_pair(lastNodeIdx, nodeIdx));
			int numEdgeVerts = linkingEdge->vertSize;
			for (int i = 0; i < numEdgeVerts; i++) {
				ecol[linkingEdge->arraypos + i*COLELEMS + 3] = (float)0.0;
			}
		}

		for (int blockIdx = 0; blockIdx < numInstructions; blockIdx++)
		{

			ncol[(nodeIdx * COLELEMS) + 3] = 0;

			if (blockIdx == numInstructions - 1) break;
			//fade short edges between internal nodes
			INS_DATA* nextIns = disassembly->at(ins->address + ins->numbytes);

			unsigned int nextInsIndex = nextIns->threadvertIdx.at(tid);
			edge_data *internalEdge = &edgeDict[make_pair(nodeIdx, nextInsIndex)];
			unsigned long edgeColPos = internalEdge->arraypos;

			ecol[edgeColPos + 3] = (float)0.0;
			ecol[edgeColPos + 4 + 3] = (float)0.0;
			nodeIdx = nextInsIndex;
			ins = nextIns;
		}
		lastNodeIdx = nodeIdx;
	}
	animlinedata->release_col();
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
	if(!obtainMutex(edMutex, "Before BB brighten", 3000)) return;

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
		
		pair<unsigned long, int> targBlock_Size = bbsequence[animPosition];
		unsigned long insAddr = targBlock_Size.first;
		int numInstructions = targBlock_Size.second;
		map <unsigned long, INS_DATA*>::iterator insIt = disassembly->find(insAddr);
		if (insIt == disassembly->end()) break;
		INS_DATA *ins = insIt->second;
		unsigned int nodeIdx = ins->threadvertIdx.at(tid);

		//link lastbb to this
		if (lastNodeIdx)
		{
			//if going between two different blocks, draw edges between
			if (animPosition && (bbsequence[animPosition] != bbsequence[animPosition - 1]))
			{
				//or does it crash here
				pair<unsigned int, unsigned int> edgePair = make_pair(lastNodeIdx, nodeIdx);
				if (!edgeDict.count(edgePair)) {
					printf("WARNING 22\n"); continue;
				}
				//still crashes with out of range! todo...
				//some sort of esp moan
				edge_data linkingEdge = edgeDict.at(edgePair);
				int numEdgeVerts = linkingEdge.vertSize;
				for (int i = 0; i < numEdgeVerts; i++) {
					ecol[linkingEdge.arraypos + i*COLELEMS + 3] = (float)1.0;
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
			INS_DATA* nextIns = disassembly->at(ins->address + ins->numbytes);

			unsigned int nextInsIndex = nextIns->threadvertIdx.at(tid);
			pair<unsigned int, unsigned int> edgePair = make_pair(nodeIdx, nextInsIndex);
			edge_data *internalEdge = &edgeDict[edgePair];
			unsigned long edgeColPos = internalEdge->arraypos;
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

	dropMutex(edMutex, "Brighten BBs end");
	//printf("latest active: %d\n", lastNodeIdx);
	latest_active_node = &vertDict[lastNodeIdx];
	//shouldn't be called if nothing to animate
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

	needVBOReload_active = true;
}

void thread_graph_data::set_block_alpha(unsigned long firstInstruction,unsigned int quantity, 
	GLfloat *nodecols, GLfloat *edgecols, float alpha)
{
	INS_DATA* ins = disassembly->at(firstInstruction);
	unsigned int nodeIdx = ins->threadvertIdx[tid];

	//fade short edges between internal nodes
	for (int blockIdx = 0; blockIdx < quantity; blockIdx++)
	{

		nodecols[(nodeIdx * COLELEMS) + 3] = alpha;
		if (blockIdx == quantity - 1) break;

		ins = disassembly->at(ins->address + ins->numbytes);

		unsigned int nextInsIndex = ins->threadvertIdx.at(tid);
		edge_data *internalEdge = &edgeDict[make_pair(nodeIdx, nextInsIndex)];
		unsigned long edgeColPos = internalEdge->arraypos;

		edgecols[edgeColPos + 3] = alpha;
		edgecols[edgeColPos + COLELEMS + 3] = alpha;
		nodeIdx = nextInsIndex;
	}
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
	INS_DATA *target_ins = disassembly->at(bbseq);
	
	//would put the end sequence instead of doing this
	//but that ruins us if something jumps in middle of an opcode
	while (remainingInstructions)
	{
		bbseq += target_ins->numbytes;
		target_ins = disassembly->at(bbseq);
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

int thread_graph_data::render_edge(pair<int, int> ePair, GRAPH_DISPLAY_DATA *edgedata, vector<ALLEGRO_COLOR> *lineColours,	
	ALLEGRO_COLOR *forceColour, bool preview)
{

	node_data *sourceNode = &vertDict[ePair.first];
	node_data *targetNode = &vertDict[ePair.second];
	edge_data *e = &edgeDict[ePair];
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

thread_graph_data::thread_graph_data(map <unsigned long, INS_DATA*> *disasPtr)
{
	disassembly = disasPtr;
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


thread_graph_data::~thread_graph_data()
{
}


void thread_graph_data::set_edge_alpha(pair<unsigned int, unsigned int> eIdx, GRAPH_DISPLAY_DATA *edgesdata, float alpha)
{
	edge_data *e = &edgeDict.at(eIdx);
	GLfloat *colarray = edgesdata->acquire_col("2e");
	for (int i = 0; i < e->vertSize; i++)
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