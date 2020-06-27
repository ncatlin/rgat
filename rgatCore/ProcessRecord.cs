using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{
    class ProcessRecord
    {

		public ProcessRecord(int binaryBitWidth) { bitwidth = binaryBitWidth; }

		/*
		public bool get_sym(uint modNum, ulong mem_addr, string &sym);
		public bool get_modpath(uint modNum, boost::filesystem::path* path);
		//bool get_modbase(uint modNum, ulong &moduleBase);


		public bool get_extern_at_address(ulong address, int moduleNum, ROUTINE_STRUCT** BB);
		public void save(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
		*/
		public bool load(Newtonsoft.Json.Linq.JObject tracejson)
		{
			/*
			Value::ConstMemberIterator procDataIt = saveJSON.FindMember("ProcessData");


			if (procDataIt == saveJSON.MemberEnd())
			{
				cout << "[rgat]ERROR: Process data load failed" << endl;
				return false;
			}
			const Value& procDataJSON = procDataIt->value;

			*/
			if (!loadModules(tracejson))
			{
				Console.WriteLine("[rgat]ERROR: Failed to load module paths");
				return false;
			}
			/*
			if (!loadSymbols(procDataJSON))
			{
				cerr << "[rgat]ERROR: Failed to load symbols" << endl;
				return false;
			}

			if (!loadDisassembly(procDataJSON))
			{
				cerr << "[rgat]ERROR: Disassembly reconstruction failed" << endl;
				return false;
			}
	
			if (!loadBlockData(procDataJSON))
			{
				cerr << "[rgat]ERROR: Basic block reconstruction failed" << endl;
				return false;
			}

			if (!loadExterns(procDataJSON))
			{
				cerr << "[rgat]ERROR: Extern call loading failed" << endl;
				return false;
			}
			*/
			return true;
			
		}
		/* 
		public INSLIST* getDisassemblyBlock(ulong blockaddr, BLOCK_IDENTIFIER blockID, ROUTINE_STRUCT** externBlock);
		public int find_containing_module(ulong address);

		public List<string> modpaths;
		public Dictionary<string, long> globalModuleIDs;
		public Dictionary<int, Dictionary<ulong, string>> modsymsPlain;
		public List<Tuple<ulong, ulong>> modBounds;
	
		public ulong instruction_before(ulong addr);

		public Tuple<ulong, BLOCK_DESCRIPTOR*> blockDetails(BLOCK_IDENTIFIER blockid);
		public ulong numBlocksSeen() { return blockList.size(); }
		//must already have disassembly write lock
		public void addBlock_HaveLock(ulong addr, BLOCK_DESCRIPTOR* blk) { blockList.push_back(make_pair(addr, blk)); }
		*/
		//maps instruction addresses to all data about it
		public Dictionary<ulong, List<InstructionData>> disassembly;
		//useful for mapping return addresses to callers without a locking search
		public Dictionary<ulong, ulong> previousInstructionsCache;
			
		//list of basic blocks
		//   address		    blockID			instructionlist
		//map <ulong, Dictionary<BLOCK_IDENTIFIER, INSLIST *>> addressBlockMap;
		public List<Tuple<ulong, List<InstructionData>>> blockList;


		public Dictionary<ulong, ROUTINE_STRUCT> externdict;
		public int bitwidth;

		/*
	private void saveDisassembly(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
		private void saveExternDict(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
		private void saveBlockData(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
		private void saveMetaData(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
		private void saveModules(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
		private void saveSymbols(rapidjson::Writer<rapidjson::FileWriteStream>& writer);

		private bool loadSymbols(const rapidjson::Value& saveJSON);
		*/
	private bool loadModules(Newtonsoft.Json.Linq.JObject tracejson)
	{
	//display_only_status_message("Loading Modules", clientState);
	Console.WriteLine("[rgat]Loading Module Paths");

			/*
	jsnreader.
	Value::ConstMemberIterator procDataIt = processDataJSON.FindMember("ModulePaths");
	if (procDataIt == processDataJSON.MemberEnd())
	{
		Console.WriteLine("[rgat] Failed to find ModulePaths in trace" );
		return false;
	}

	const Value& modPathArray = procDataIt->value;

		Console.WriteLine("Loading "+modPathArray.Count+" modules");

	//display_only_status_message(pathLoadMsg.str(), clientState);

	Value::ConstValueIterator modPathIt = modPathArray.Begin();
	for (; modPathIt != modPathArray.End(); modPathIt++)
	{

		Value::ConstMemberIterator pathDataIt = modPathIt->FindMember("B64");
		if (pathDataIt == modPathIt->MemberEnd())
		{
			Console.WriteLine("[rgat]ERROR: Module Paths load failed: No path string");
			return false;
		}

string b64path = pathDataIt->value.GetString();
string plainpath = base64_decode(b64path);

modpaths.push_back(plainpath);
	}


	procDataIt = processDataJSON.FindMember("ModuleBounds");
	if (procDataIt == processDataJSON.MemberEnd())
	{
		Console.WriteLine("[rgat] Failed to find ModuleBounds in trace");
		return false;
	}
	const Value& modsBoundArray = procDataIt->value;

	modBounds.clear();
	Value::ConstValueIterator modsBoundIt = modsBoundArray.Begin();
	for (; modsBoundIt != modsBoundArray.End(); modsBoundIt++)
	{
		const Value& moduleBounds = * modsBoundIt;
auto boundPair = new pair<MEM_ADDRESS, MEM_ADDRESS>;
boundPair->first = moduleBounds[0].GetUint64();
boundPair->second = moduleBounds[1].GetUint64();
modBounds.push_back(boundPair);
	}
			*/
	return true;
	}
	
	/*
	private bool loadDisassembly(const rapidjson::Value& saveJSON);
	private bool loadBlockData(const rapidjson::Value& saveJSON);
	private bool loadExterns(const rapidjson::Value& processDataJSON);

	private bool unpackModuleSymbolArray(const rapidjson::Value& modSymArray, int globalmodNum);
		*/


		private bool running = true;
		private bool killed = false;
		public bool dieFlag = false;
	}
}
