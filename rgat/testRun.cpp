#include "stdafx.h"
#include "testRun.h"
#include "serialise.h"
#include "proto_graph.h"

testRun::testRun(boost::filesystem::path testsDirectory, rgatState *clistate)
{
	_testsDirectory = testsDirectory;
	_testsDirectory += "\\";
	clientState = clistate;
}


testRun::~testRun()
{
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
			runx86Test(itr->path().stem(), expectedResults86);
		}

		rapidjson::Value::ConstMemberIterator expectedResults64 = testJSON.FindMember("a64");
		if (expectedResults64 != testJSON.MemberEnd())
		{
			runx64Test(itr->path().stem(), expectedResults64);
		}

	}
}

void testRun::runx86Test(boost::filesystem::path testStem, rapidjson::Value::ConstMemberIterator expectedResults)
{
	boost::filesystem::path testExe = _testsDirectory;
	testExe += testStem;
	testExe += ".86.exe";

	cout << "Running 32 bit test - " << testExe << endl;

	//execute_tracer(activeTarget, &clientState->config);
}

void testRun::runx64Test(boost::filesystem::path testStem, rapidjson::Value::ConstMemberIterator expectedResults)
{
	boost::filesystem::path testExe = _testsDirectory;
	testExe += testStem;
	testExe += ".64.exe";

	cout << "Running 64 bit test - " << testExe << endl;

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

	if (!validateTestResults(testtrace, expectedResults))
		cout << "Test for " << testStem.string() << " failed" << endl;
	else
		cout << "Test for " << testStem.string() << " success" << endl;
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

		if (resultType == "BLOCKSRUN")
		{
			unsigned long expectedBlocks = expectedResultIt->value.GetUint64();
			if (firstgraph->savedAnimationData.size() != expectedBlocks)
			{
				cout << "Test Failed: Expected (" << expectedBlocks << ") blocks but (" << firstgraph->savedAnimationData.size() << ") blocks traced" << endl;
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

	}
	return true;
}