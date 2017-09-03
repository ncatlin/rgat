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
Container for all binary targets rgat has analyzed this session
*/

#pragma once
#include "binaryTarget.h"

class binaryTargets
{
public:
	binaryTargets() { };
	~binaryTargets() { };

	bool binaryTargets::getTargetByPath(boost::filesystem::path path, binaryTarget **target);
	vector<binaryTarget *> getTargetsList();

	bool exists(boost::filesystem::path file) { return targets.count(file) > 0;}
	bool exists(binaryTarget * target) { return (std::find(targetsList.begin(), targetsList.end(), target) != targetsList.end()); }

	size_t count() { return targets.size(); }
	void registerChild(PID_TID parentPID, traceRecord *trace);
	void clear();

private:
	rgatlocks::UntestableLock targetsLock;
	map <boost::filesystem::path, binaryTarget *> targets;
	vector<binaryTarget *> targetsList;
	binaryTarget *activeTarget = NULL;
};

