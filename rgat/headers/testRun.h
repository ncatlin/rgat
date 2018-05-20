#pragma once
#include "rgatState.h"
#include "proto_graph.h"


class testRun
{
public:
	testRun(boost::filesystem::path testsDirectory, rgatState *clistate);
	~testRun();
	void beginTests();

private:
	boost::filesystem::path _testsDirectory;
	bool runTest(boost::filesystem::path testStem, rapidjson::Value::ConstMemberIterator expectedResults, uint timeLimit, string modifier);
	bool validateTestResults(traceRecord *testtrace, rapidjson::Value::ConstMemberIterator expectedResults);
	bool testNodeDetails(proto_graph *graph, rapidjson::Value::ConstMemberIterator expectedResultIt);
	void printResults();

	rgatState *clientState;
	map <bool, map <string, vector<boost::filesystem::path>>> testResults;
};

