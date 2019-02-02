#include <QtWidgets>

#define RGAT_VERSION_MAJ 0
#define RGAT_VERSION_MIN 5
#define RGAT_VERSION_FEATURE 3
#define RGAT_VERSION_DESCRIPTION "QT-Beta"


#include <boost\process.hpp>
#include <boost\filesystem.hpp>
#include <boost\thread\shared_mutex.hpp>
#include <boost\thread\locks.hpp>

typedef boost::shared_mutex Lock;
typedef boost::unique_lock< Lock > WriteLock;
typedef boost::shared_lock< Lock > ReadLock;

using namespace std;
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <set>
#include <map>
#include <queue>
#include <unordered_map>
#include <math.h>
#include <queue>
#include <chrono>
#include <mutex>
#include <thread>
#include <shared_mutex>


#include <capstone.h>



