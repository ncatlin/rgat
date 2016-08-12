#include "stdafx.h"
#include "thread_graph_data.h"
#include "rendering.h"
#include "GUIStructs.h"


//create faded edge version of graph for use in animations
void thread_graph_data::extend_faded_edges()
{
	GLfloat *animecol = animlinedata->acquire_col();
	GLfloat *mainecol = mainlinedata->acquire_col();
	unsigned int endVerts = mainlinedata->get_numVerts();
	//printf("Fade start tid%d with endverts %d\n", tid, endVerts*COLELEMS);
	int pendingVerts = endVerts - animlinedata->get_numVerts();
	if (!pendingVerts) return;

	unsigned int fadedIndex = animlinedata->get_numVerts() *COLELEMS;
	unsigned int copysize = pendingVerts*COLELEMS * sizeof(GLfloat);
	void *targaddr = animecol + fadedIndex;
	void *srcaddr = mainecol + fadedIndex;
	memcpy(targaddr, srcaddr, copysize);
	mainlinedata->release_col();

	unsigned int index2 = (animlinedata->get_numVerts() *COLELEMS);
	unsigned int end = endVerts*COLELEMS;
	for (; index2 < end; index2 += 4)
	{
		animecol[index2 + 3] = 0.1;
		//animecol[index2 + 4 +3] = 0.1;
	}
	animlinedata->set_numVerts(endVerts);
	//printf("Fade done tid %d with endverts %d\n", tid, endVerts*COLELEMS);
	
	animlinedata->release_col();
}


void thread_graph_data::advance_anim_instructions(map <unsigned long, INS_DATA*> *disassembly, int stepSize)
{
	unsigned long lastInstruction = totalInstructions - 1;
	if (stepSize > 0 && animInstructionIndex < lastInstruction)
	{
		//if trying to jump past last instruction, point to last
		if (animInstructionIndex + stepSize > lastInstruction)
		{
			animInstructionIndex = lastInstruction;
			sequenceIndex = bbsequence.size() - 1;
			pair<unsigned long, int> targBlock_Size = bbsequence[sequenceIndex];
			unsigned long blockAddr = targBlock_Size.first;
			int numInstructions = targBlock_Size.second;
			blockInstruction = numInstructions - 1;
		}
		//iterate through instructions to desired step. THIS. IS. SLOOOOOOOOOW.
		else
		{
			pair<unsigned long, int> targBlock_Size = bbsequence[sequenceIndex];
			unsigned long blockAddr = targBlock_Size.first;
			int numInstructions = targBlock_Size.second;

			while (stepSize > 0)
			{
				int bbremaining = (numInstructions - 1) - blockInstruction;
				if (bbremaining >= stepSize)
				{
					blockInstruction += stepSize;
					animInstructionIndex += stepSize;
					stepSize = 0;
					break;
				}
				stepSize -= (bbremaining + 1);
				animInstructionIndex += (bbremaining + 1);
				sequenceIndex++;

				if (sequenceIndex >= bbsequence.size())
				{
					blockInstruction = numInstructions-1;
					break;
				}

				pair<unsigned long, int> targBlock_Size = bbsequence[sequenceIndex];
				unsigned long insAddr = targBlock_Size.first;
				numInstructions = targBlock_Size.second;;
	
				if (!disassembly->count(insAddr))
					sequenceIndex++;
				blockInstruction = 0;
			}
		}
	}
}

void thread_graph_data::decrease_anim_instructions(map <unsigned long, INS_DATA*> *disassembly, int stepSize)
{

	if (stepSize < 0 && animInstructionIndex > 0)
	{
		//if trying to jump past first instruction, point to first
		if (((signed long)animInstructionIndex + stepSize) < 0)
		{
			animInstructionIndex = 0;
			sequenceIndex = 0;
			blockInstruction = 0;
		}
		//iterate through blocks to desired step. THIS. IS. SLOOOOOOOOOW.
		else
		{

			while (stepSize < 0)
			{
				if (blockInstruction >= abs(stepSize))
				{
					blockInstruction += stepSize;
					animInstructionIndex += stepSize;
					stepSize = 0;
					break;
				}
				stepSize += (blockInstruction + 1);
				animInstructionIndex -= (blockInstruction + 1);
				sequenceIndex--;

				pair<unsigned long, int> targBlock_Size = bbsequence[sequenceIndex];
				unsigned long insAddr = targBlock_Size.first;
				int numInstructions = targBlock_Size.second;

				if (!disassembly->count(insAddr))
					sequenceIndex--;
				blockInstruction = numInstructions-1;
			}
		}
	}
}

void thread_graph_data::performStep(map <unsigned long, INS_DATA*> *disassembly, bool stepBBs, int stepSize)
{
	if (stepBBs)
	{
		if (stepSize > 0)
		{
			if ((sequenceIndex + stepSize) >= bbsequence.size() - 1)
				sequenceIndex = bbsequence.size() - 1;
			else
				sequenceIndex += stepSize;

		}
		else if (stepSize < 0)
		{
			if (((signed long)sequenceIndex + stepSize) < 0)
				sequenceIndex = 0;
			else
				sequenceIndex += stepSize;
		}
	}
	else
	{
		if (stepSize > 0)
			advance_anim_instructions(disassembly, stepSize);
		else if (stepSize < 0)
			decrease_anim_instructions(disassembly, stepSize);
	}

	latest_active_node = derive_anim_node(disassembly, stepBBs);
}


//return true if animation has ended
unsigned int thread_graph_data::updateAnimation(map <unsigned long, INS_DATA*> *disassembly, unsigned int updateSize, bool stepBBs, bool animationMode)
{
	if (vertDict.empty()) return ANIMATION_ENDED;

	performStep(disassembly, stepBBs, updateSize);
	if (!animationMode) return 0;

	bool animation_end = false;

	if (stepBBs)
	{
		if (sequenceIndex == bbsequence.size() - 1)
		{
			animation_end = true;
			clear_final_BBs(disassembly);
		}
	}
	else if (animInstructionIndex == (totalInstructions - 1))
	{
		animation_end = true;
	}

	if (animation_end)
	{
		last_anim_start = 0;
		last_anim_stop = 0;
		sequenceIndex = 0;
		blockInstruction = 0;
		animInstructionIndex = 0;
		newanim = true;
		latest_active_node = &vertDict[0];
		return ANIMATION_ENDED;
	}

	return 0;
}


void thread_graph_data::clear_graph(map <unsigned long, INS_DATA*> *disassembly)
{
	GLfloat *ncol = animvertsdata->acquire_col();
	GLfloat *ecol = animlinedata->acquire_col();
	unsigned int lastNodeIdx = 0;

	unsigned int numEdgeVerts = animlinedata->get_numVerts();
	printf("clearning %d edge verts\n", numEdgeVerts);
	for (unsigned int i = 0; i < numEdgeVerts; i++)
	{
		ecol[i*COLELEMS + 3] = (float)0.0;
	}

	unsigned int numNodeVerts = animvertsdata->get_numVerts();
	for (unsigned int i = 0; i < numNodeVerts; i++)
	{
		ncol[i*COLELEMS + 3] = (float)0.0;
	}

	animlinedata->release_col();
	animvertsdata->release_col();
	needVBOReload_active = true;
}

void thread_graph_data::clear_final_BBs(map <unsigned long, INS_DATA*> *disassembly)
{
	GLfloat *ncol = animvertsdata->acquire_col();
	GLfloat *ecol = animlinedata->acquire_col();
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

void thread_graph_data::render_last(map <unsigned long, INS_DATA*> *disassembly, bool stepBBs)
{
	unsigned int lastNodeIdx = 0;
	if (stepBBs)
	{
		unsigned int animEnd = sequenceIndex;
		unsigned int animPosition = animEnd - ANIMATION_WIDTH;

		GLfloat *ncol = animvertsdata->acquire_col();
		GLfloat *ecol = animlinedata->acquire_col();
		
	

		//place active on new active
		for (; animPosition < animEnd; animPosition++)
		{
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
				edge_data *linkingEdge = &edgeDict.at(make_pair(lastNodeIdx, nodeIdx));
				int numEdgeVerts = linkingEdge->vertSize;
				for (int i = 0; i < numEdgeVerts; i++) {
					ecol[linkingEdge->arraypos + i*COLELEMS + 3] = (float)1.0;
				}
			}

			for (int blockIdx = 0; blockIdx < numInstructions; blockIdx++)
			{
				ncol[(nodeIdx * COLELEMS) + 3] = 1;
				if (blockIdx == numInstructions - 1) break;

				//brighten short edges between internal nodes
				INS_DATA* nextIns = disassembly->at(ins->address + ins->numbytes);

				unsigned int nextInsIndex = nextIns->threadvertIdx.at(tid);
				edge_data *internalEdge = &edgeDict[make_pair(nodeIdx, nextInsIndex)];
				unsigned long edgeColPos = internalEdge->arraypos;
				ecol[edgeColPos + 3] = (float)1.0;
				ecol[edgeColPos + COLELEMS + 3] = (float)1.0;
				nodeIdx = nextInsIndex;
				ins = nextIns;
			}
			lastNodeIdx = nodeIdx;
		}

	}
	else
	{
		do me with instructions
	}


	animvertsdata->release_col();
	animlinedata->release_col();
	latest_active_node = &vertDict[lastNodeIdx];
	//shouldn't be called if nothing to animate
	needVBOReload_active = true;
}

/*
take the latestnode-ANIMATION_WIDTH->latestnode steps from the main graph
take the rest from the faded graph
combine, season to taste
*/
void thread_graph_data::animate_to_last(map <unsigned long, INS_DATA*> *disassembly, bool stepBBs)
{
	clear_graph(disassembly);
	if (stepBBs)
	{
		sequenceIndex = bbsequence.size() - 1;
		render_last(disassembly, stepBBs);
	}
	//shouldn't be called if nothing to animate
	needVBOReload_active = true;
}

/*
take the latestnode-ANIMATION_WIDTH->latestnode steps from the main graph
take the rest from the faded graph
combine, season to taste
*/
void thread_graph_data::update_animation_render(map <unsigned long, INS_DATA*> *disassembly, bool stepBBs)
{
	if (stepBBs)
	{
		unsigned int animEnd = sequenceIndex;
		unsigned int animStart;
		if (sequenceIndex < ANIMATION_WIDTH)
			animStart = 0;
		else
			animStart = sequenceIndex - ANIMATION_WIDTH;

		//new animation, find everything in active window
		if (newanim)
		{
			last_anim_start = animStart;
			last_anim_stop = animStart;
			newanim = false;
		}

		GLfloat *ncol = animvertsdata->acquire_col();
		GLfloat *ecol = animlinedata->acquire_col();
		unsigned int lastNodeIdx = 0;

		//place faded on expired active (outside window)
		for (; last_anim_start < animStart; last_anim_start++)
		{
			//find the verts + copy low alpha into them
			pair<unsigned long,int> targBlock_Size = bbsequence[last_anim_start];
			unsigned long insAddr = targBlock_Size.first;
			int numInstructions = targBlock_Size.second;
			INS_DATA *ins = disassembly->at(insAddr);
			unsigned int nodeIdx = ins->threadvertIdx.at(tid);

			//unlink lastbb
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

				std::pair<unsigned int , unsigned int> linkingPair = make_pair(lastNodeIdx, nodeIdx);
				map<std::pair<unsigned int, unsigned int>, edge_data>::iterator edgeIt = edgeDict.find(linkingPair);
				if (edgeIt == edgeDict.end()) break;

				int numEdgeVerts = edgeIt->second.vertSize;
				for (int i = 0; i < numEdgeVerts; i++) {
					ecol[edgeIt->second.arraypos + i*COLELEMS + 3] = (float)0.0;
				}
			}

			//fade short edges between internal nodes
			for (int blockIdx = 0; blockIdx < numInstructions; blockIdx++)
			{

				ncol[(nodeIdx * COLELEMS) + 3] = 0;
				if (blockIdx == numInstructions - 1) break;
				
				INS_DATA* nextIns = disassembly->at(ins->address + ins->numbytes);

				unsigned int nextInsIndex = nextIns->threadvertIdx.at(tid);
				edge_data *internalEdge = &edgeDict[make_pair(nodeIdx, nextInsIndex)];
				unsigned long edgeColPos = internalEdge->arraypos;

				ecol[edgeColPos + 3] = (float)0.0;
				ecol[edgeColPos + COLELEMS + 3] = (float)0.0;
				nodeIdx = nextInsIndex;
				ins = nextIns;

			}
		}
			
		lastNodeIdx = 0;
		//place active on new active
		for (; last_anim_stop < animEnd; last_anim_stop++)
		{
			pair<unsigned long, int> targBlock_Size = bbsequence[last_anim_stop];
			unsigned long insAddr = targBlock_Size.first;
			int numInstructions = targBlock_Size.second;
			INS_DATA *ins = disassembly->at(insAddr);
			unsigned int nodeIdx = ins->threadvertIdx.at(tid);

			//link lastbb to this
			if (last_anim_stop > 0)
			{
				if (!lastNodeIdx)
				{
					pair<unsigned long, int> lastBlock_Size = bbsequence.at(last_anim_stop - 1);
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
					ecol[linkingEdge->arraypos + i*COLELEMS + 3] = (float)1.0;
				}
			}

			for (int blockIdx = 0; blockIdx < numInstructions; blockIdx++)
			{
				ncol[(nodeIdx * COLELEMS) + 3] = 1;
				if (blockIdx == numInstructions-1) break;

				//brighten short edges between internal nodes
				INS_DATA* nextIns = disassembly->at(ins->address+ins->numbytes);
				
				unsigned int nextInsIndex = nextIns->threadvertIdx.at(tid);
				edge_data *internalEdge = &edgeDict[make_pair(nodeIdx, nextInsIndex)];
				unsigned long edgeColPos = internalEdge->arraypos;
				ecol[edgeColPos + 3] = (float)1.0;
				ecol[edgeColPos + COLELEMS + 3] = (float)1.0;
				nodeIdx = nextInsIndex;
				ins = nextIns;
			}
			lastNodeIdx = nodeIdx;
		}
		animvertsdata->release_col();
		animlinedata->release_col();
	}
	//shouldn't be called if nothing to animate
	needVBOReload_active = true;
}

node_data *thread_graph_data::derive_anim_node(map <unsigned long, INS_DATA*> *disassembly, bool stepBBs)
{

	//good thing we are only doing this once per frame
	pair<unsigned long, int> seq_size = bbsequence[sequenceIndex];
	unsigned long bbseq = seq_size.first;
	int remainingInstructions = blockInstruction;
	INS_DATA *target_ins = disassembly->at(bbseq);
	
	if (!stepBBs)
	{	
		//would put the end sequence instead of doing this
		//but that ruins us if something jumps in middle of an opcode
		while (remainingInstructions)
		{
			bbseq += target_ins->numbytes;
			target_ins = disassembly->at(bbseq);
			remainingInstructions--;
		}
	}

	node_data *n = &vertDict[target_ins->threadvertIdx.at(tid)];
	return n;

}

void thread_graph_data::reset_mainlines() {
	delete mainlinedata;
	mainlinedata = new GRAPH_DISPLAY_DATA(40000);
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
	e->vertSize = vertsDrawn;
	e->arraypos = arraypos;

	return 1;

}

node_data* thread_graph_data::get_active_node()
{
	if (!latest_active_node && !vertDict.empty())
		latest_active_node = &vertDict[0];
	return latest_active_node;
}

thread_graph_data::thread_graph_data()
{
	mainvertsdata = new GRAPH_DISPLAY_DATA(40000);
	mainlinedata = new GRAPH_DISPLAY_DATA(40000);

	//fadedlinedata = new GRAPH_DISPLAY_DATA(40000);
	//fadedvertsdata = new GRAPH_DISPLAY_DATA(40000);

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