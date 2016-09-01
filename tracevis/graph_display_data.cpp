#include <graph_display_data.h>
#include <traceMisc.h>

//time to split line/node data sperate
GRAPH_DISPLAY_DATA::GRAPH_DISPLAY_DATA(int initialValue)
{
	posmutex = CreateMutex(NULL, FALSE, NULL);
	colmutex = CreateMutex(NULL, FALSE, NULL);
	numVerts = 0;
	edgesRendered = 0;
}

GRAPH_DISPLAY_DATA::~GRAPH_DISPLAY_DATA()
{
	obtainMutex(colmutex, "Destruct", INFINITE);
	obtainMutex(posmutex, "Destruct", INFINITE);
}

bool GRAPH_DISPLAY_DATA::get_coord(unsigned int index, FCOORD* result)
{
	const int listIndex = index*POSELEMS;
	if (listIndex >= vposarray.size()) return false;

	obtainMutex(posmutex, 0, 6000);
	result->x = vposarray.at(listIndex);
	result->y = vposarray.at(listIndex + 1);
	result->z = vposarray.at(listIndex + 2);
	dropMutex(posmutex, 0);
	return true;
}

vector<float> *GRAPH_DISPLAY_DATA::acquire_pos(char *location = 0)
{
	bool result = obtainMutex(posmutex, 0, 50);
	if (!result) return 0;
	return &vposarray;
}

vector<float> *GRAPH_DISPLAY_DATA::acquire_col(char *location = 0)
{

	bool result = obtainMutex(colmutex, location, 150);
	if (!result) {
		printf("failed to obtain colmutex %x\n", (unsigned int)colmutex); return 0;
	}
	return &vcolarray;
}

void GRAPH_DISPLAY_DATA::release_pos()
{
	dropMutex(posmutex);	
}

void GRAPH_DISPLAY_DATA::release_col()
{
	dropMutex(colmutex);
}

//TODO: this is awful. need to add to vector ert by vert
//when number of verts increases also checks buffer sizes
//mutexes are bit dodgy, expect them to be held by caller
void GRAPH_DISPLAY_DATA::set_numVerts(unsigned int num)
{ 
	assert(num >= numVerts);
	numVerts = num;
}

void GRAPH_DISPLAY_DATA::clear()
{
	acquire_pos();
	acquire_col();
	fill(vposarray.begin(), vposarray.end(), 0);
	fill(vcolarray.begin(), vcolarray.end(), 0);
	edgesRendered = 0;
	release_col();
	release_pos();
}