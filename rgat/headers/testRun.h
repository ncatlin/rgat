#pragma once
#include "rgatState.h"


class testRun
{
public:
	testRun(boost::filesystem::path testsDirectory, rgatState *clistate);
	~testRun();
	void beginTests();
private:
	boost::filesystem::path _testsDirectory;
	void runx86Test(boost::filesystem::path testStem, rapidjson::Value::ConstMemberIterator expectedResults);
	void runx64Test(boost::filesystem::path testStem, rapidjson::Value::ConstMemberIterator expectedResults);
	bool validateTestResults(traceRecord *testtrace, rapidjson::Value::ConstMemberIterator expectedResults);

	rgatState *clientState;
};

