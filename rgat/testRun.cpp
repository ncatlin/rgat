#include "stdafx.h"
#include "testRun.h"
#include "serialise.h"

testRun::testRun(boost::filesystem::path testsDirectory, rgatState *clistate)
{
	_testsDirectory = testsDirectory;
	_testsDirectory += "\\";
	clientState = clistate;

	testResults[false];
	testResults[true];
}


testRun::~testRun()
{
}

void testRun::printResults()
{
	cout << "------------------------------------------" << endl;
	cout << "\t\tTests Complete\n" << endl;
	cout << "\tx86" << endl;
	cout << "\t\tSucceeded: " << testResults[true]["a86"].size() << endl;
	cout << "\t\tFailed: " << testResults[false]["a86"].size() << endl;
	if (!testResults[false]["a86"].empty())
	{
		for each(boost::filesystem::path path in testResults[false]["a86"])
		{
			cout << "\t\t\t " << path.string() << endl;
		}
	}
	cout << endl;

	cout << "\tx64" << endl;
	cout << "\t\tSucceeded: " << testResults[true]["a64"].size() << endl;
	cout << "\t\tFailed: " << testResults[false]["a64"].size() << endl;
	if (!testResults[false]["a64"].empty())
	{
		for each(boost::filesystem::path path in testResults[false]["a64"])
		{
			cout << "\t\t\t " << path.string() << endl;
		}
	}
	cout << endl;
	cout << "------------------------------------------" << endl;
}

void testRun::beginTests()
{
	clientState->testsRunning = true;

	using namespace boost::filesystem;
	for (directory_iterator itr(_testsDirectory); itr != directory_iterator(); ++itr)
	{
		if (itr->path().extension() != ".json") continue;

		rapidjson::Document testJSON;
		if (!getJSON(*itr, &testJSON)) {
			cerr << "[rgat]  Failed to load test " << *itr << endl;
			continue;
		}

		rapidjson::Value::ConstMemberIterator expectedResults86 = testJSON.FindMember("a86");
		if (expectedResults86 != testJSON.MemberEnd())
		{
			boost::filesystem::path teststem = itr->path().stem();
			bool result = runTest(teststem, expectedResults86, "a86");

			testResults[result]["a86"].push_back(teststem);
		}

		rapidjson::Value::ConstMemberIterator expectedResults64 = testJSON.FindMember("a64");
		if (expectedResults64 != testJSON.MemberEnd())
		{
			boost::filesystem::path teststem = itr->path().stem();
			bool result = runTest(teststem, expectedResults64, "a64");

			testResults[result]["a64"].push_back(teststem);
		}
	}

	printResults();
}

bool testRun::runTest(boost::filesystem::path testStem, rapidjson::Value::ConstMemberIterator expectedResults, string modifier)
{
	boost::filesystem::path testExe = _testsDirectory;
	testExe += testStem;
	if (modifier == "a64")
	{
		testExe += ".64.exe";
		cout << "Running 64 bit test - " << testExe << endl;
	}
	else if (modifier == "a86")
	{
		testExe += ".86.exe";
		cout << "Running 32 bit test - " << testExe << endl;
	}

	binaryTarget *newTarget;
	clientState->testTargets.getTargetByPath(testExe.generic_path(), &newTarget);

	execute_tracer(newTarget, &clientState->config);

	traceRecord *testtrace = NULL;
	while (true)
	{
		Sleep(100);
		testtrace = newTarget->getFirstTrace();
		if (!testtrace) continue;
		if (testtrace->isRunning()) continue;
		Sleep(100);
		break;
	}

	bool success = validateTestResults(testtrace, expectedResults);
	if (!success)
		cout << "\n ----- \n\t Test for " << testStem.string() << "(" << modifier << ") failed \n ----- " << endl;
	else
		cout << "Test for " << testStem.string() << "(" << modifier << ") success" << endl;

	return success;
}

bool testRun::validateTestResults(traceRecord *testtrace, rapidjson::Value::ConstMemberIterator expectedResults)
{

	rapidjson::Value::ConstMemberIterator expectedResultIt = expectedResults->value.FindMember("GRAPHS");
	if (expectedResultIt == expectedResults->value.MemberEnd())
	{
		cerr << "[rgat] Error: No graph count in expected results - bad test" << endl;
		return false;
	}
	int graphsExpected = expectedResultIt->value.GetUint();

	vector<proto_graph *> protographs;
	testtrace->getProtoGraphs(&protographs);

	if (protographs.size() != graphsExpected)
	{
		cout << "Test Failed: Expected (" << graphsExpected << ") threads but (" << protographs.size() << ") threads traced" << endl;
		return false;
	}

	proto_graph *firstgraph = protographs.at(0);

	expectedResultIt = expectedResults->value.MemberBegin();
	for (; expectedResultIt != expectedResults->value.MemberEnd(); expectedResultIt++)
	{
		string resultType = expectedResultIt->name.GetString();

		if (resultType == "GRAPHS") continue;

		if (resultType == "EDGES")
		{
			unsigned long expectedEdges = expectedResultIt->value.GetUint64();
			if (firstgraph->edgeList.size() != expectedEdges)
			{
				cout << "Test Failed: Expected (" << expectedEdges << ") edges but (" << firstgraph->edgeList.size() << ") edges traced" << endl;
				return false;
			}
			continue;
		}

		if (resultType == "NODES")
		{
			unsigned long expectedNodes = expectedResultIt->value.GetUint64();
			if (firstgraph->nodeList.size() != expectedNodes)
			{
				cout << "Test Failed: Expected (" << expectedNodes << ") nodes but (" << firstgraph->nodeList.size() << ") nodes traced" << endl;
				return false;
			}
			continue;
		}

		if (resultType == "EXTERNS")
		{
			unsigned long expectedExterns = expectedResultIt->value.GetUint64();
			if (firstgraph->externalNodeList.size() != expectedExterns)
			{
				cout << "Test Failed: Expected (" << expectedExterns << ") externs but (" << firstgraph->externalNodeList.size() << ") external nodes traced" << endl;
				return false;
			}
			continue;
		}

		if (resultType == "EXCEPTIONS")
		{
			unsigned long expectedExceptions = expectedResultIt->value.GetUint64();
			if (firstgraph->exceptionSet.size() != expectedExceptions)
			{
				cout << "Test Failed: Expected (" << expectedExceptions << ") blocks but (" << firstgraph->exceptionSet.size() << ") exceptions traced" << endl;
				return false;
			}
			continue;
		}

		if (resultType == "NODEDETAILS")
		{
			if (!testNodeDetails(firstgraph, expectedResultIt)) return false;
			continue;
		}

		cerr << "Error: Invalid test " << resultType << endl;
		return false;
	}
	return true;
}

bool testRun::testNodeDetails(proto_graph *graph, rapidjson::Value::ConstMemberIterator expectedResultIt)
{
	rapidjson::Value::ConstValueIterator nodelistIt = expectedResultIt->value.Begin();
	for (; nodelistIt != expectedResultIt->value.End(); nodelistIt++)
	{
		NODEINDEX nodeidx = nodelistIt->FindMember("IDX")->value.GetUint64();
		node_data *node = graph->safe_get_node(nodeidx);
		if (!node)
		{
			cout << "Test Failed: Expected unique instruction (" << nodeidx << ") but failed to retrieve it. "
				<< graph->nodeList.size() << " instructions traced" << endl;
			return false;
		}

		rapidjson::Value::ConstMemberIterator nodeDetailIt = nodelistIt->MemberBegin();
		for (; nodeDetailIt != nodelistIt->MemberEnd(); nodeDetailIt++)
		{
			string valuename = nodeDetailIt->name.GetString();
			if (valuename == "IDX") continue;
			if (valuename == "QTY")
			{
				unsigned long expectedQuantity = nodeDetailIt->value.GetUint64();
				if (node->executionCount != expectedQuantity)
				{
					cout << "Test Failed: Expected (" << expectedQuantity << ") executions of node " << nodeidx <<
						" but (" << node->executionCount << ") executions traced" << endl;
					return false;
				}
				continue;
			}

			cerr << "Error: Invalid test " << valuename << " in NODEDETAILS" << endl;
			return false;
		}
	}
}