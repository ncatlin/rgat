#include "stdafx.h"
#include "node_data.h"
#include "b64.h"
#include "graphicsMaths.h"
#include "GUIConstants.h"

node_data::node_data()
{
}


node_data::~node_data()
{
}

//take the a/b/bmod coords, convert to opengl coordinates based on supplied sphere multipliers/size
FCOORD node_data::sphereCoordB(MULTIPLIERS *dimensions, float diamModifier) 
{
	FCOORD result;
	float adjB = vcoord.b + float(vcoord.bMod * BMODMAG);
	sphereCoord(vcoord.a, adjB, &result, dimensions, diamModifier);
	return result;
}

DCOORD node_data::get_screen_pos(GRAPH_DISPLAY_DATA *vdata, PROJECTDATA *pd)
{
	DCOORD result;
	FCOORD fcoord = vdata->get_coord(index);
	gluProject(fcoord.x, fcoord.y, fcoord.z,
		pd->model_view, pd->projection, pd->viewport,
		&result.x, &result.y, &result.z);
	return result;
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
	printf("saving Node %d address %lx\n", index, address);

	if (!external)
		*outfile << mutation;
	else
	{
		*outfile << funcargs.size() << "{"; //number of calls
		vector<vector<pair<int, string>>>::iterator callIt = funcargs.begin();
		vector<pair<int, string>>::iterator argIt;
		printf("node %d: Saving %d calls\n", index,funcargs.size());
		for (; callIt != funcargs.end(); callIt++)
		{
			printf("\tnSaving %d args\n", callIt->size());
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