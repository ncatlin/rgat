#include <graph_display_data.h>
#include <traceMisc.h>

//time to split line/node data sperate
GRAPH_DISPLAY_DATA::GRAPH_DISPLAY_DATA(int initialValue)
{
	posmutex = CreateMutex(NULL, FALSE, NULL);
	colmutex = CreateMutex(NULL, FALSE, NULL);
	vposarray = (float *)malloc(initialValue);
	assert(vposarray);
	memset(vposarray, 0, initialValue);
	vpsize = initialValue;
	vcolarray = (float *)malloc(initialValue);
	assert(vcolarray);
	vcsize = initialValue;
	memset(vcolarray, 0, initialValue);
	numVerts = 0;
	edgesRendered = 0;
}

GRAPH_DISPLAY_DATA::~GRAPH_DISPLAY_DATA()
{
	obtainMutex(colmutex, "Destruct", INFINITE);
	obtainMutex(posmutex, "Destruct", INFINITE);
	cholder = string("destruct");
	colmutex = 0;
	posmutex = 0;
	free(vcolarray);
	free(vposarray);
	dropMutex(colmutex);
}

FCOORD GRAPH_DISPLAY_DATA::get_coord(unsigned int index)
{
	FCOORD result;
	result.x = vposarray[(index * POSELEMS)];
	result.y = vposarray[(index * POSELEMS) + 1];
	result.z = vposarray[(index * POSELEMS) + 2];
	return result;
}

float *GRAPH_DISPLAY_DATA::acquire_pos(char *location = 0)
{
	bool result = obtainMutex(posmutex, 0, 50);
	if (!result) return 0;
	return vposarray;
}

float *GRAPH_DISPLAY_DATA::acquire_col(char *location = 0)
{

	bool result = obtainMutex(colmutex, location, 50);
	if (!result) {
		printf("failed to obtain colmutex %x\n", (unsigned int)colmutex); return 0;
	}
	return vcolarray;
}

void GRAPH_DISPLAY_DATA::release_pos()
{
	dropMutex(posmutex);	
}

void GRAPH_DISPLAY_DATA::release_col()
{
	cholder.clear();
	dropMutex(colmutex);
}

void GRAPH_DISPLAY_DATA::expand(unsigned int minsize) {
	obtainMutex(colmutex,"expand", INFINITE);
	cholder = "expand";
	obtainMutex(posmutex, "expand", INFINITE);

	unsigned int expandValue = max(minsize, 30000);
	vpsize += expandValue;
	vcsize += expandValue;

	float* newAddress;
	newAddress = (float *)realloc(vposarray, vpsize);
	if (newAddress) vposarray = newAddress;
	newAddress = (float *)realloc(vcolarray, vcsize);
	if (newAddress) vcolarray = newAddress;

	release_col();
	release_pos();
}

//when number of verts increases also checks buffer sizes
//mutexes are bit dodgy, expect them to be held by caller
void GRAPH_DISPLAY_DATA::set_numVerts(unsigned int num)
{ 
	obtainMutex(posmutex, "set", INFINITE);
	obtainMutex(colmutex, "set", INFINITE);
	numVerts = num;

	int posremaining = vpsize - numVerts * POSELEMS * sizeof(float);
	int colremaining = vcsize - numVerts * COLELEMS * sizeof(float);

	assert(posremaining >= 0 && colremaining >= 0);

	float* newAddress;
	if (posremaining < 15000) {
		vpsize += 30000;
		newAddress = (float *)realloc(vposarray, vpsize);
		if (newAddress) vposarray = newAddress;
	}
	if (colremaining < 15000) {
		vcsize += 30000;
		newAddress = (float *)realloc(vcolarray, vcsize);
		if (newAddress) vcolarray = newAddress;
	}
	release_col();
	release_pos();
}
