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
				std::this_thread::yield(); //<- this is not in the source but might improve performance. 
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
				std::this_thread::yield(); //<- this is not in the source but might improve performance. 
			}
			locked.store(true, std::memory_order_release);
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