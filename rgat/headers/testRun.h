#pragma once
#include "rgatState.h"


class testRun
{
public:
	testRun(boost::filesystem::path testsDirectory);
	~testRun();
	void beginTests();
private:
	boost::filesystem::path _testsDirectory;
	void runx86Test(boost::filesystem::path testStem, rapidjson::Value::ConstMemberIterator expectedResults);
	void runx64Test(boost::filesystem::path testStem, rapidjson::Value::ConstMemberIterator expectedResults);
};

