#include "stdafx.h"
#include "edge_data.h"


edge_data::edge_data()
{
}


edge_data::~edge_data()
{
}

bool edge_data::serialise(ofstream *file, int source, int target)
{
	*file << weight << "," <<
		source << "," <<
		target << "," <<
		edgeClass << "@";

	return true;
}