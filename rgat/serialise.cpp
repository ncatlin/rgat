/*
Copyright 2016-2017 Nia Catlin

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
Graph/Process Saving/Loading routines
*/
#include "stdafx.h"
#include "serialise.h"
#include "OSspecific.h"
#include "graphplots/cylinder_graph.h"
#include "traceRecord.h"
#include "binaryTargets.h"

#include "rapidjson/document.h"
using namespace rapidjson;

bool getJSON(boost::filesystem::path traceFilePath, rapidjson::Document *saveJSON)
{
	FILE* pFile;
	fopen_s(&pFile, traceFilePath.string().c_str(), "rb");
	if (!pFile)
	{
		cerr << "[rgat]Warning: Could not open file for reading. Abandoning Load." << endl;
		return false;
	}

	char buffer[65536];
	rapidjson::FileReadStream is(pFile, buffer, sizeof(buffer));

	saveJSON->ParseStream<0, rapidjson::UTF8<>, rapidjson::FileReadStream>(is);
	fclose(pFile);

	if (!saveJSON->IsObject())
	{
		cerr << "[rgat]Warning: Corrupt file. Abandoning Load." << endl;
		if (saveJSON->HasParseError())
		{
			cerr << "\t rapidjson parse error "<< saveJSON->GetParseError() << " at offset " << saveJSON->GetErrorOffset() << endl;
		}
		return false;
	}
	return true;
}

void saveModulePaths(PROCESS_DATA *piddata, Writer<rapidjson::FileWriteStream>& writer)
{
	writer.Key("ModulePaths");
	writer.StartArray();

	vector<boost::filesystem::path>::iterator pathIt = piddata->modpaths.begin();
	for (; pathIt != piddata->modpaths.end(); pathIt++)
	{
		string pathstr = pathIt->string();
		const unsigned char* cus_pathstring = reinterpret_cast<const unsigned char*>(pathstr.c_str());
		writer.StartObject();
		writer.Key("B64");
		writer.String(base64_encode(cus_pathstring, (unsigned int)pathIt->size()).c_str());
		writer.EndObject();
	}

	writer.EndArray();
}

//big, but worth doing in case environments differ
void saveModuleSymbols(PROCESS_DATA *piddata, Writer<FileWriteStream>& writer)
{
	writer.Key("ModuleSymbols");
	writer.StartArray();

	map <int, std::map<MEM_ADDRESS, string>>::iterator modSymIt = piddata->modsymsPlain.begin();
	for (; modSymIt != piddata->modsymsPlain.end(); ++modSymIt)
	{
		writer.StartObject();

		writer.Key("ModuleID");
		writer.Int(modSymIt->first);

		writer.Key("Symbols");
		writer.StartArray();
		map<MEM_ADDRESS, string> ::iterator symIt = modSymIt->second.begin();
		for (; symIt != modSymIt->second.end(); symIt++)
		{
			writer.StartArray();
			writer.Uint64(symIt->first); //symbol address
			writer.String(symIt->second.c_str()); //symbol string
			writer.EndArray();
		}
		writer.EndArray();

		writer.EndObject();
	}

	writer.EndArray();
}

void saveDisassembly(PROCESS_DATA *piddata, Writer<FileWriteStream>& writer)
{
	writer.Key("Disassembly");
	writer.StartArray();

	piddata->getDisassemblyReadLock();
	map <MEM_ADDRESS, INSLIST>::iterator disasIt = piddata->disassembly.begin();
	for (; disasIt != piddata->disassembly.end(); ++disasIt)
	{
		writer.StartArray();

		writer.Int64(disasIt->first); //address

		writer.Int(disasIt->second.front()->globalmodnum); //module
		
		writer.StartArray(); //opcode data for each mutation found at address
		INSLIST::iterator mutationIt = disasIt->second.begin();
		for (; mutationIt != disasIt->second.end(); ++mutationIt)
		{
			INS_DATA *ins = *mutationIt;
			writer.StartArray();

			writer.String(ins->opcodes.c_str());

			//threads containing it
			writer.StartArray();
			unordered_map<PID_TID, NODEINDEX>::iterator threadVertIt = ins->threadvertIdx.begin();
			for (; threadVertIt != ins->threadvertIdx.end(); ++threadVertIt)
			{
				writer.StartArray();

				writer.Int64(threadVertIt->first); //could make file smaller by doing a lookup table.
				writer.Uint64(threadVertIt->second);

				writer.EndArray();
			}
			writer.EndArray(); //end array of indexes for this mutation

			writer.EndArray(); //end mutation
		}
		writer.EndArray(); //end array of mutations for this address

		writer.EndArray(); //end address

	}
	piddata->dropDisassemblyReadLock();
	writer.EndArray(); // end array of disassembly data for trace
}

void saveExternDict(PROCESS_DATA *piddata, Writer<FileWriteStream>& writer)
{
	writer.Key("Externs");
	writer.StartArray();

	map <MEM_ADDRESS, BB_DATA *>::iterator externIt = piddata->externdict.begin();
	for (; externIt != piddata->externdict.end(); ++externIt)
	{
		writer.StartObject();

		writer.Key("A");	//address
		writer.Int64(externIt->first); 

		writer.Key("M");	//module number
		writer.Int(externIt->second->globalmodnum);

		writer.Key("S");	//has symbol?
		writer.Bool(externIt->second->hasSymbol);

		//todo: should this object even be written if empty?
		if (!externIt->second->thread_callers.empty())
		{
			writer.Key("C");	//thread callers
			writer.StartArray();
			map<DWORD, EDGELIST>::iterator threadCallIt = externIt->second->thread_callers.begin();
			for (; threadCallIt != externIt->second->thread_callers.end(); ++threadCallIt)
			{
				writer.StartArray();

				//thread id
				writer.Uint64(threadCallIt->first);

				//edges
				writer.StartArray();
				EDGELIST::iterator edgeIt = threadCallIt->second.begin();
				for (; edgeIt != threadCallIt->second.end(); ++edgeIt)
				{
					writer.StartArray();
					//source, target
					writer.Uint64(edgeIt->first);
					writer.Uint64(edgeIt->second);

					writer.EndArray();
				}
				writer.EndArray(); //end edge array

				writer.EndArray(); //end thread callers object for this thread
			}
			writer.EndArray(); //end thread callers array for this address
		}
		writer.EndObject(); //end object for this extern entry
	}

	writer.EndArray(); //end externs array
}

void saveBlockData(PROCESS_DATA *piddata, Writer<FileWriteStream>& writer)
{
	writer.Key("BasicBlocks");
	writer.StartArray();
	piddata->getDisassemblyReadLock();
	map <MEM_ADDRESS, map<BLOCK_IDENTIFIER, INSLIST *>>::iterator blockIt = piddata->blocklist.begin();
	for (; blockIt != piddata->blocklist.end(); ++blockIt)
	{
		writer.StartArray();

		//block address
		writer.Uint64(blockIt->first);

		//instructions 
		writer.StartArray();
		map<BLOCK_IDENTIFIER, INSLIST *>::iterator blockIDIt = blockIt->second.begin();
		for (; blockIDIt != blockIt->second.end(); ++blockIDIt)
		{
			writer.StartArray();

			INSLIST *blockInstructions = blockIDIt->second;

			writer.Uint64(blockIDIt->first); //block ID

			writer.StartArray(); //mutations for each instruction

			INSLIST::iterator blockInsIt = blockInstructions->begin();
			for (; blockInsIt != blockInstructions->end(); ++blockInsIt)
			{
				//write instruction address+mutation loader can look them up in disassembly
				INS_DATA* ins = *blockInsIt;

				writer.StartArray();

				writer.Uint64(ins->address);
				writer.Uint64(ins->mutationIndex);
				
				writer.EndArray();
			}
			
			writer.EndArray(); //end mutations array for this instruction

			writer.EndArray(); //end this instruction
		}

		writer.EndArray();	//end instructions array for this address

		writer.EndArray(); //end basic block object for this address
	}
	piddata->dropDisassemblyReadLock();
	writer.EndArray(); //end array of basic blocks
}

void saveMetaData(PROCESS_DATA *piddata, Writer<FileWriteStream>& writer)
{
	writer.Key("BitWidth");
	if (piddata->bitwidth == 32)
		writer.Uint(32);
	else if (piddata->bitwidth == 64)
		writer.Uint(64);
	else
	{
		cerr << "[rgat] Error: Trace not locked while saving. Proto-graph has invalid bitwidth marker " << piddata->bitwidth << endl;
		assert(false);
		return;
	}

	writer.Key("RGATVersionMaj");
	writer.Uint(RGAT_VERSION_MAJ);
	writer.Key("RGATVersionMin");
	writer.Uint(RGAT_VERSION_MIN);
	writer.Key("RGATVersionFeature");
	writer.Uint(RGAT_VERSION_FEATURE);
}

void saveTargetData(PROCESS_DATA *piddata, Writer<FileWriteStream>& writer)
{
	writer.StartObject();

	saveMetaData(piddata, writer);
	saveModulePaths(piddata, writer);
	saveModuleSymbols(piddata, writer);
	saveDisassembly(piddata, writer);
	saveBlockData(piddata, writer);
	saveExternDict(piddata, writer);

	writer.EndObject();
}

//if dir doesn't exist in config defined path, create
bool ensureDirExists(string dirname, rgatState *clientState)
{
	return true;
}


FILE * setupSaveFile(clientConfig *config, traceRecord *trace)
{
	binaryTarget *target = (binaryTarget *)trace->get_binaryPtr();
	boost::filesystem::path path;
	time_t startedTime;
	trace->getStartedTime(&startedTime);
	boost::filesystem::path filename = getSaveFilename(target->path().filename(), startedTime, trace->getPID());
	if (!getSavePath(config->saveDir, filename,  &path))
	{
		cerr << "[rgat]WARNING: Couldn't save to " << config->saveDir << endl;

		config->saveDir = getModulePath() + "\\saves\\";
		cout << "[rgat]Attempting to use " << config->saveDir << endl;

		if (!getSavePath(config->saveDir, filename, &path))
		{
			cerr << "[rgat]ERROR: Failed to save to path " << config->saveDir << ", giving up." << endl;
			cerr << "[rgat]Add path of a writable directory to CLIENT_PATH in rgat.cfg" << endl;
			return NULL;
		}
		config->updateSavePath(config->saveDir);
	}

	cout << "[rgat]Saving trace " << dec << trace->getPID() << " to " << path << endl;

	FILE *savefile;
	if ((fopen_s(&savefile, path.string().c_str(), "wb") != 0))// non-Windows use "w"?
	{
		cerr << "[rgat]Failed to open " << path << "for writing" << endl;
		return NULL;
	}

	return savefile;
}

wstring time_string(time_t startedTime)
{
	struct tm timedata;
	localtime_s(&timedata, &startedTime);
	wstringstream savetime;
	savetime << timedata.tm_mon + 1 << timedata.tm_mday << "-" << timedata.tm_hour << timedata.tm_min << timedata.tm_sec;
	return savetime.str();
}

boost::filesystem::path getSaveFilename(boost::filesystem::path binaryFilename, time_t startedTime, PID_TID PID)
{
	wstringstream filenameSS;
	filenameSS << binaryFilename.wstring() << "-" << PID << "-" << time_string(startedTime) << ".rgat";
	return boost::filesystem::path(filenameSS.str());
}



//returns path for saving files, tries to create if it doesn't exist
bool getSavePath(boost::filesystem::path saveDir, boost::filesystem::path saveFilename, boost::filesystem::path *result)
{
	//if directory doesn't exist, create
	if (!boost::filesystem::is_directory(saveDir))
	{
		if (!boost::filesystem::create_directory(saveDir))
		{
			cerr << "[rgat]Error: Could not create non-existant directory " << saveDir << endl;
			return false;
		}
	}

	boost::filesystem::path savepath(saveDir);
	savepath /= saveFilename;

	*result = savepath;
	return true;
}


