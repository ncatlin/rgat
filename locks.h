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
A couple of platform independent exclusive locks using std::atomic
Untestable is a little faster but can't be queried for availability
*/

#pragma once
#include <atomic>
#include <thread>

namespace rgatlocks {
	class UntestableLock
	{
		std::atomic_flag locked = ATOMIC_FLAG_INIT;
	public:
		void lock() {
			while (locked.test_and_set(std::memory_order_acquire)) {
				std::this_thread::yield();
			}
		}

		void unlock() {			
			locked.clear(std::memory_order_release);
		}
	};

	class TestableLock
	{
		std::atomic<bool> locked = false;
	public:
		void lock() {
			while (locked.load()) {	
				std::this_thread::yield();	
			}
			locked.store(true, std::memory_order_acquire);
		}

		bool trylock() {
			if (locked.load()) return false;
			lock();
			return true;
		}

		void unlock() {
			locked.store(false, std::memory_order_release);
		}
	};

}