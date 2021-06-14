
#include "iostream"
#include "utilities.h"


//todo: remove block addresses from tag. block ID will do fine!

void printTagCache(threadObject *thread)
{
	if (!thread->tagIdx && !thread->cacheRepeats) return;
	//std::cout << "Sending tag cache" << std::endl;
	size_t byteswritten = 0;
	int cacheEnd;
	//first print out any complete loops
	if (thread->cacheRepeats)
	{
		cacheEnd = thread->loopEnd;

		byteswritten += fprintf(thread->threadpipeFILE, "RS%d\x01", thread->cacheRepeats); //loop start <count> marker
		for (int i = 0; i <= cacheEnd; ++i)
		{
			//byteswritten += fprintf(thread->threadpipeFILE, TRACE_TAG_MARKER"%p,%p,%llx\x01",
			//	thread->tagCache[i], thread->targetAddresses[i], thread->blockID_counts[i]);
			byteswritten += fprintf(thread->threadpipeFILE, TRACE_TAG_MARKER"%lx,%lx\x01", thread->blockIDCache[i], thread->targetAddresses[i]);
			//printf("WritingA: j%lx,%lx\x01\n", thread->blockIDCache[i], thread->targetAddresses[i]);
		}
		byteswritten += fprintf(thread->threadpipeFILE, "RE\x01"); //loop end marker
	}

	cacheEnd = thread->tagIdx;
	int tagi = 0;
	//messages >1024 bytes seem to cause problems. this fragments larger tag caches
	while ((cacheEnd - tagi) > 25)
	{
		for (int fragmenti = 0; fragmenti < 20; ++tagi && ++fragmenti) 
		{
			byteswritten += fprintf(thread->threadpipeFILE, TRACE_TAG_MARKER"%lx,%lx\x01", thread->blockIDCache[tagi], thread->targetAddresses[tagi]);
			//printf("WritingB: j%lx,%lx\x01\n", thread->blockIDCache[tagi], thread->targetAddresses[tagi]);
		}
		fflush(thread->threadpipeFILE);
	}
	for (; tagi < cacheEnd; ++tagi)	{
		byteswritten += fprintf(thread->threadpipeFILE, TRACE_TAG_MARKER"%lx,%lx\x01", thread->blockIDCache[tagi], thread->targetAddresses[tagi]);
		//printf("WritingC: j%lx,%lx\x01\n", thread->blockIDCache[tagi], thread->targetAddresses[tagi]);
	}

	if ((int)byteswritten <= 0)
		std::cerr << "[drgat]CALLING ABORT! WRITE FAIL 2!"<<std::endl;

	//pipe closed, rgat probably closed too
	if ((int)byteswritten <= 0 && (thread->tagIdx || thread->loopEnd))
	{
		PIN_Sleep(1500);
		std::cout << "[drgat]CALLING ABORT! WRITE FAIL!";
		PIN_ExitApplication(-1);
	}

	fflush(thread->threadpipeFILE);
	thread->tagIdx = 0;
	thread->loopEnd = 0;
	thread->cacheRepeats = 0;
}

void DeclareTerribleEventAndExit(const wchar_t *eventText) {
	wprintf(L"[pinGAT]FATAL: %S\n\n", eventText);
	PIN_ExitApplication(-1);
}

void DeclareTerribleEventAndExit(std::wstring eventText) {
	wprintf(L"[pinGAT]FATAL: %S\n\n", eventText.c_str());
	PIN_ExitApplication(-1);
}

//https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c/41094722#41094722
static const int B64index[256] = { 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62, 63, 62, 62, 63, 52, 53, 54, 55,
56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6,
7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,
0,  0,  0, 63,  0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 };


std::string b64decode(const void* data, const size_t len)
{
	unsigned char* p = (unsigned char*)data;
	int pad = len > 0 && (len % 4 || p[len - 1] == '=');
	const size_t L = ((len + 3) / 4 - pad) * 4;
	std::string str(L / 4 * 3 + pad, '\0');

	for (size_t i = 0, j = 0; i < L; i += 4)
	{
		int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
		str[j++] = n >> 16;
		str[j++] = n >> 8 & 0xFF;
		str[j++] = n & 0xFF;
	}
	if (pad)
	{
		int n = B64index[p[L]] << 18 | B64index[p[L + 1]] << 12;
		str[str.size() - 1] = n >> 16;

		if (len > L + 2 && p[L + 2] != '=')
		{
			n |= B64index[p[L + 2]] << 6;
			str.push_back(n >> 8 & 0xFF);
		}
	}


	return str;
}