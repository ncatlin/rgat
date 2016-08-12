/*   _____                           
 * /\  _  \                     __    
 * \ \ \_\ \      __    __  __ /\_\   
 *  \ \  __ \   /'_ `\ /\ \/\ \\/\ \  
 *   \ \ \/\ \ /\ \_\ \\ \ \_\ \\ \ \ 
 *    \ \_\ \_\\ \____ \\ \____/ \ \_\
 *     \/_/\/_/ \/____\ \\/___/   \/_/
 *                /\____/             
 *                \_/__/              
 *
 * Copyright (c) 2011 Joshua Larouche
 * 
 *
 * License: (BSD)
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of Agui nor the names of its contributors may
 *    be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "Agui/BaseTypes.hpp"

namespace agui {
	
	bool NumericStringCompare::compare( const std::string& a, const std::string& b )
	{
		size_t i = 0;
		//assume no number index
		int aNumIndex = -1;
		int bNumIndex = -1;

		//try to find a digit
		for(i = 0; i < a.length(); ++i)
		{
			if(a[i] > 47 && a[i] < 58)
			{
				aNumIndex = (int)i;
				break;
			}
		}

		for(i = 0; i < b.length(); ++i)
		{
			if(b[i] > 47 && b[i] < 58)
			{
				bNumIndex = (int)i;
				break;
			}
		}

		bool similar = false;

		//do the numbers both start at the same place
		if(aNumIndex > -1 && aNumIndex == bNumIndex)
		{
			similar = true;

			//is the string the same up until the number
			for(short i = 0; i < aNumIndex; ++i)
			{
				if(a[i] != b[i])
				{
					similar = false;
				}
			}
		}

		//return a basic string compare
		if(!similar)
		{
			return a < b;
		}

		int aNum;
		int bNum;

		//extract the numbers and compare them
		aNum = atoi(&a[aNumIndex]);
		bNum = atoi(&b[bNumIndex]);

		return aNum < bNum;
	}

	NumericStringCompare::~NumericStringCompare()
	{
	}

}



