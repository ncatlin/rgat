#include <graph_display_data.h>

//time to split line/node data sperate
GRAPH_DISPLAY_DATA::GRAPH_DISPLAY_DATA(int initialValue)
{
	posmutex = CreateMutex(NULL, FALSE, NULL);
	colmutex = CreateMutex(NULL, FALSE, NULL);
	coordmutex = CreateMutex(NULL, FALSE, NULL);
	vposarray = (float *)malloc(initialValue);
	memset(vposarray, 0, initialValue);
	vpsize = initialValue;
	vcolarray = (float *)malloc(initialValue);
	memset(vcolarray, 0, initialValue);

	vcsize = initialValue;
	fcoordarray = (float *)malloc(initialValue);
	numVerts = 0;
	edgesRendered = 0;
}

GRAPH_DISPLAY_DATA::~GRAPH_DISPLAY_DATA()
{
	WaitForSingleObject(colmutex, INFINITE);
	WaitForSingleObject(posmutex, INFINITE);
	WaitForSingleObject(coordmutex, INFINITE);
	free(vcolarray);
	free(vposarray);
	free(fcoordarray);
}

FCOORD GRAPH_DISPLAY_DATA::get_coord(unsigned int index)
{
	FCOORD result;
	result.x = fcoordarray[(index * POSELEMS)];
	result.y = fcoordarray[(index * POSELEMS) + 1];
	result.z = fcoordarray[(index * POSELEMS) + 2];
	return result;
}

float *GRAPH_DISPLAY_DATA::acquire_pos()
{
	WaitForSingleObject(posmutex, INFINITE);
	return vposarray;
}

float *GRAPH_DISPLAY_DATA::acquire_col()
{
	WaitForSingleObject(colmutex, INFINITE);
	return vcolarray;
}

float *GRAPH_DISPLAY_DATA::acquire_fcoord()
{
	WaitForSingleObject(coordmutex, INFINITE);
	return fcoordarray;
}

void GRAPH_DISPLAY_DATA::release_pos()
{
	ReleaseMutex(posmutex);	
}

void GRAPH_DISPLAY_DATA::release_col()
{
	ReleaseMutex(colmutex);
}

void GRAPH_DISPLAY_DATA::release_fcoord()
{
	ReleaseMutex(coordmutex);
}

void GRAPH_DISPLAY_DATA::debg(int m)
{
	int delme = 0;
	printf("debg%d: ",m);
	for (; delme < 50; delme++)
		printf("%0.1f,", vcolarray[delme]);
	printf("\n");
}

void GRAPH_DISPLAY_DATA::expand(unsigned int minsize) {
	WaitForSingleObject(colmutex, INFINITE);
	WaitForSingleObject(posmutex, INFINITE);
	WaitForSingleObject(coordmutex, INFINITE);

	unsigned int expandValue = max(minsize, 30000);
	vpsize += expandValue;
	vcsize += expandValue;

	float* newAddress;
	newAddress = (float *)realloc(vposarray, vpsize);
	if (newAddress) vposarray = newAddress;
	newAddress = (float *)realloc(fcoordarray, vpsize);
	if (newAddress) fcoordarray = newAddress;
	newAddress = (float *)realloc(vcolarray, vcsize);
	if (newAddress) vcolarray = newAddress;

	ReleaseMutex(colmutex);
	ReleaseMutex(posmutex);
	ReleaseMutex(coordmutex);
}

//when number of verts increases also checks buffer sizes
//mutexes are bit dodgy, expect them to be held by caller
void GRAPH_DISPLAY_DATA::set_numVerts(unsigned int num)
{ 
	numVerts = num;

	int posremaining = vpsize - numVerts * POSELEMS * sizeof(float);
	int colremaining = vcsize - numVerts * COLELEMS * sizeof(float);

	assert(posremaining >= 0 && colremaining >= 0);

	float* newAddress;
	if (posremaining < 15000) {
		vpsize += 30000;
		newAddress = (float *)realloc(vposarray, vpsize);
		if (newAddress) vposarray = newAddress;
		newAddress = (float *)realloc(fcoordarray, vpsize);
		if (newAddress) fcoordarray = newAddress;
	}
	if (colremaining < 15000) {
		vcsize += 30000;
		newAddress = (float *)realloc(vcolarray, vcsize);
		if (newAddress) vcolarray = newAddress;
	}
}
