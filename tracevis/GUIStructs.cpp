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
Client state functions
*/
#include "stdafx.h"
#include "GUIStructs.h"
#include "plotted_graph.h"

void* VISSTATE::obtain_activeGraph_ptr()
{
	while (!returnGraphPonters)
		Sleep(1);
	
#ifdef XP_COMPATIBLE
	obtainMutex(graphPtrMutex, 0);
#else
	AcquireSRWLockShared(&graphPtrLock);
#endif

	return activeGraph;
}

void VISSTATE::discard_activeGraph_ptr()
{
#ifdef XP_COMPATIBLE
	dropMutex(graphPtrMutex, 0);
#else
	ReleaseSRWLockShared(&graphPtrLock);
#endif
	
}