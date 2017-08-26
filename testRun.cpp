#include "stdafx.h"
#include "testRun.h"
#include "serialise.h"


testRun::testRun(boost::filesystem::path testsDirectory)
{
	_testsDirectory = testsDirectory;
	_testsDirectory += "\\";
}


testRun::~testRun()
{
}

void testRun::beginTests()
{

	using namespace boost::filesystem;
	for (directory_iterator itr(_testsDirectory); itr != directory_iterator(); ++itr)
	{
		if (itr->path().extension() != ".json") continue;

		rapidjson::Document testJSON;
		if (!getJSON(*itr, &testJSON)) {
			cerr << "[rgat]  Failed to load test " << *itr << endl;
			continue;
		}

		rapidjson::Value::ConstMemberIterator expectedResults86 = testJSON.FindMember("86");
		if (expectedResults86 == testJSON.MemberEnd())
		{
			runx86Test(itr->path().stem(), expectedResults86);
		}

		rapidjson::Value::ConstMemberIterator expectedResults64 = testJSON.FindMember("64");
		if (expectedResults64 == testJSON.MemberEnd())
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


}

void testRun::runx64Test(boost::filesystem::path testStem, rapidjson::Value::ConstMemberIterator expectedResults)
{
	boost::filesystem::path testExe = _testsDirectory;
	testExe += testStem;
	testExe += ".64.exe";


}