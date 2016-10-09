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
Class describing each edge
*/
#pragma once
class edge_data
{
public:
	edge_data();
	~edge_data();
	//write to provided file. This class doesn't actually contain the source
	//and the target of the edge, so pass those along too
	bool serialise(ofstream *file, int source, int target);

	//number of verticies taken up in OpenGL data
	unsigned int vertSize = 0; 
	//position in rendering data structure
	unsigned int arraypos = 0; 
	//type of edge (call,extern,etc)
	char edgeClass = 0;  

	//number of times executed, temporary variable used by heatmap solver
	unsigned long chainedWeight = 0;
};

