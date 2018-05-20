#include "stdafx.h"
#include "testRun.h"
#include "serialise.h"
#include "processLaunching.h"
#include "rgat.h"

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

		int timeLimit;
		auto timeoutIt = testJSON.FindMember("TIMEOUT");
		if (timeoutIt != testJSON.MemberEnd())
			timeLimit = timeoutIt->value.GetUint() * 1000;
		else
			timeLimit = 10000;

		rapidjson::Value::ConstMemberIterator expectedResults86 = testJSON.FindMember("a86");
		if (expectedResults86 != testJSON.MemberEnd())
		{
			boost::filesystem::path teststem = itr->path().stem();
			bool result = runTest(teststem, expectedResults86, timeLimit, "a86");

			testResults[result]["a86"].push_back(teststem);
		}

		rapidjson::Value::ConstMemberIterator expectedResults64 = testJSON.FindMember("a64");
		if (expectedResults64 != testJSON.MemberEnd())
		{
			boost::filesystem::path teststem = itr->path().stem();
			bool result = runTest(teststem, expectedResults64, timeLimit, "a64");

			testResults[result]["a64"].push_back(teststem);
		}
	}

	printResults();
}

bool testRun::runTest(boost::filesystem::path testStem, rapidjson::Value::ConstMemberIterator expectedResults, uint timeLimit, string modifier)
{
	boost::filesystem::path testExe = _testsDirectory;
	testExe += testStem;
	if (modifier == "a64")
	{
		testExe += ".64.exe";
		cout << "Running 64 bit test - " << testExe << " with " << timeLimit << "s timeout" << endl;
	}
	else if (modifier == "a86")
	{
		testExe += ".86.exe";
		cout << "Running 32 bit test - " << testExe << " with " << timeLimit << "s timeout" << endl;
	}
	else
	{
		cerr << "Bad test modifier " << modifier << endl;
		return false;
	}

	binaryTarget *newTarget;
	clientState->testTargets.getTargetByPath(testExe.generic_path(), &newTarget);

	BWPATHLISTS newdata;
	newdata.inWhitelistMode = false;
	newdata.BLDirs.push_back(boost::filesystem::path("C:/windows"));
	newTarget->setIncludelistData(newdata);

	clock_t timeend, timestart = clock();
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	if (!execute_tracer(newTarget, clientState->config, clientState->getTempDir(), ui->tracePinRadio->isChecked()))
	{
		cerr << "error executing tests tracer" << endl;
		return false;
	}

	traceRecord *testtrace = NULL;

	while (true)
	{
		if (timeLimit <= 0) {
			cerr << "No results for test after " << timeLimit << " seconds - possibly still running?" << std::endl;
			cerr << "\tGiving up and marking it as failed." << endl;
			return false;
		}
		Sleep(100);
		timeLimit -= 100;

		testtrace = newTarget->getFirstTrace();		
		if (!testtrace) continue;
		if (testtrace->isRunning()) continue;

		timeend = clock();
		break;
	}

	clock_t duration = (timeend - timestart)/1000;
	Sleep(100);

	bool success = validateTestResults(testtrace, expectedResults);
	if (!success)
		cout << "\n ----- \n\t Test for " << testStem.string() << "(" << modifier << ") failed \n ----- " << endl;
	else
	{
		cout << "Test for " << testStem.string() << "(" << modifier << ") success";
		if (duration > 1)
			cout << " after " << duration << " seconds" << endl;
		else
			cout << endl;
	}

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
				if ((firstgraph->nodeList.back().external == true) && (firstgraph->externalNodeList.size() == (expectedExterns + 1)))
					continue; //returning to the threadinitthunk is technically entering external code, but shouldn't count

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
			if (!testNodeDetails(firstgraph, expectedResultIt)) 
				return false;
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

			if (valuename == "COND")
			{

				string expectedCond = nodeDetailIt->value.GetString();
				if (expectedCond == "NONE" && (node->conditional == 0)) continue;
				if (expectedCond != "NONE" && ((node->conditional & ISCONDITIONAL) != ISCONDITIONAL))
				{
					cout << "Test Failed: Expected node (" << nodeidx << ") to be conditional, but it is not. Flags: " << node->conditional << endl;
					return false;
				}

				if (expectedCond == "BOTH")
				{
					if ((node->conditional & CONDCOMPLETE) != CONDCOMPLETE)
					{
						cout << "Test Failed: Expected conditional node (" << nodeidx << ") to be taken and not-taken, but this was false. Flags: " << node->conditional << endl;
						return false;
					}
					continue;
				}

				if (expectedCond == "TAKEN")
				{
					if ((node->conditional & CONDTAKEN) != CONDTAKEN)
					{
						cout << "Test Failed: Expected conditional node (" << nodeidx << ") to only be taken but this was false. Flags: " << node->conditional << endl;
						return false;
					}
					continue;
				}

				if (expectedCond == "FELLTHROUGH")
				{
					if ((node->conditional & CONDFELLTHROUGH) != CONDFELLTHROUGH)
					{
						cout << "Test Failed: Expected conditional node (" << nodeidx << ") to only fall through but this was false. Flags: " << node->conditional << endl;
						return false;
					}
					continue;
				}

				cerr << "Error: Invalid conditional test " << expectedCond << " in NODEDETAILS" << endl;
				return false;
			}

			cerr << "Error: Invalid test " << valuename << " in NODEDETAILS" << endl;
			return false;
		}
	}
	return true;
}