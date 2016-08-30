#include <graph_display_data.h>
#include <traceMisc.h>

//time to split line/node data sperate
GRAPH_DISPLAY_DATA::GRAPH_DISPLAY_DATA(int initialValue)
{
	posmutex = CreateMutex(NULL, FALSE, NULL);
	colmutex = CreateMutex(NULL, FALSE, NULL);
	vposarray.assign(initialValue, 0);
	vcolarray.assign(initialValue, 0);
	numVerts = 0;
	edgesRendered = 0;
}

GRAPH_DISPLAY_DATA::~GRAPH_DISPLAY_DATA()
{
	obtainMutex(colmutex, "Destruct", INFINITE);
	obtainMutex(posmutex, "Destruct", INFINITE);
}

FCOORD GRAPH_DISPLAY_DATA::get_coord(unsigned int index)
{
	FCOORD result;
	obtainMutex(posmutex, 0, 6000);
	result.x = vposarray.at(index * POSELEMS);
	result.y = vposarray.at(index * POSELEMS + 1);
	result.z = vposarray.at(index * POSELEMS + 2);
	dropMutex(posmutex, 0);
	return result;
}

float *GRAPH_DISPLAY_DATA::acquire_pos(char *location = 0)
{
	bool result = obtainMutex(posmutex, 0, 50);
	if (!result) return 0;
	return &vposarray[0];
}

float *GRAPH_DISPLAY_DATA::acquire_col(char *location = 0)
{

	bool result = obtainMutex(colmutex, location, 150);
	if (!result) {
		printf("failed to obtain colmutex %x\n", (unsigned int)colmutex); return 0;
	}
	return &vcolarray[0];
}

void GRAPH_DISPLAY_DATA::release_pos()
{
	dropMutex(posmutex);	
}

void GRAPH_DISPLAY_DATA::release_col()
{
	dropMutex(colmutex);
}

//when number of verts increases also checks buffer sizes
//mutexes are bit dodgy, expect them to be held by caller
void GRAPH_DISPLAY_DATA::set_numVerts(unsigned int num)
{ 
	
	numVerts = num;
	unsigned int currentMaxSize = col_buf_size_floats();
	unsigned int targetDataSize = numVerts * COLELEMS * sizeof(GLfloat);
	if (targetDataSize > currentMaxSize)
	{
		acquire_pos();
		acquire_col(); //todo: move this into the if, if we can
		printf("Resizing to %d\n", targetDataSize + 64000);
		//this is a big bottleneck... must be a better way
		vposarray.resize(targetDataSize + 64000, 0);
		vcolarray.resize(targetDataSize + 64000, 0);
		release_col();
		release_pos();
	}

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