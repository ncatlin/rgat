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
Class describing each node
*/
#include "stdafx.h"
#include "node_data.h"
#include "b64.h"
#include "graphicsMaths.h"
#include "GUIConstants.h"

//take the a/b/bmod coords, convert to opengl coordinates based on supplied sphere multipliers/size
FCOORD node_data::sphereCoordB(MULTIPLIERS *dimensions, float diamModifier) 
{
	FCOORD result;
	float adjB = vcoord.b + float(vcoord.bMod * BMODMAG);
	sphereCoord(vcoord.a, adjB, &result, dimensions, diamModifier);
	return result;
}

//this fails if we are drawing a node that has been recorded on the graph but not rendered graphically
bool node_data::get_screen_pos(GRAPH_DISPLAY_DATA *vdata, PROJECTDATA *pd, DCOORD *screenPos)
{
	FCOORD graphPos;
	if (!vdata->get_coord(index, &graphPos)) return false;

	gluProject(graphPos.x, graphPos.y, graphPos.z,
		pd->model_view, pd->projection, pd->viewport,
		&screenPos->x, &screenPos->y, &screenPos->z);
	return true;
}

bool node_data::serialise(ofstream *outfile)
{
	*outfile << index << "{";
	*outfile << vcoord.a << "," <<
		vcoord.b << "," <<
		vcoord.bMod << "," <<
		conditional << "," << nodeMod << ",";
	*outfile << address << ",";
	*outfile << external << ",";

	if (!external)
		*outfile << ins->mutationIndex;
	else
	{
		*outfile << funcargs.size() << "{"; //number of calls
		vector<ARGLIST>::iterator callIt = funcargs.begin();
		ARGLIST::iterator argIt;
		for (; callIt != funcargs.end(); callIt++)
		{
			*outfile << callIt->size() << ",";
			for (argIt = callIt->begin(); argIt != callIt->end(); argIt++)
			{
				string argstring = argIt->second;
				const unsigned char* cus_argstring = reinterpret_cast<const unsigned char*>(argstring.c_str());
				*outfile << argIt->first << "," << base64_encode(cus_argstring, argstring.size()) << ",";
			}
		}
	}
	*outfile << "}";

	return true;
}