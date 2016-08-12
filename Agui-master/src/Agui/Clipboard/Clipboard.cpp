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


#include "Agui/Clipboard/Clipboard.hpp"
#if defined(_WIN32)
#include "Agui/Clipboard/WinClipboard.hpp"
// TODO This was not working for us because of some Cocoa issues.
// So far the clipboard is not needed anyway.
// #elif defined(__APPLE__)
// #include "Agui/Clipboard/OSXClipboard.hpp"
#else
#endif

namespace agui
{
	Clipboard::Clipboard(void)
	{
	}

	Clipboard::~Clipboard(void)
	{
	}

	void Clipboard::copy( const std::string& input )
	{

#if defined(_WIN32)
		WinClipboard::copy(input);
#else
		inClipboard = input;
#endif
	}

	std::string Clipboard::paste()
	{
#if defined(_WIN32)
		return _filter(WinClipboard::paste());
#else
		return inClipboard;
#endif

	}

	std::string Clipboard::_filter( const std::string& str )
	{
		std::string result;

		for(size_t i = 0; i < str.length(); ++i)
		{
			if(str[i] != '\t' && str[i] != '\r')
			{
				result += str[i];
			}
		}

		return result;

	}

	std::string Clipboard::inClipboard;

}
