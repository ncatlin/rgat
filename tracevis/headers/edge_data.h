#pragma once
class edge_data
{
public:
	edge_data();
	~edge_data();
	bool serialise(ofstream *file, int source, int target);

	unsigned long weight = 0; //number of times executed
	unsigned int vertSize = 0;
	unsigned int arraypos = 0;
	char edgeClass = 0;
};

