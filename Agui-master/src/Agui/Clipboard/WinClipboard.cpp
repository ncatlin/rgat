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

#include "Agui/Clipboard/WinClipboard.hpp"
#include <windows.h>
namespace agui
{
	WinClipboard::WinClipboard(void)
	{
	}

	WinClipboard::~WinClipboard(void)
	{
	}

	void WinClipboard::copy( const std::string& input )
	{
		LPWSTR  lptstrCopy; 
		HGLOBAL hglbCopy; 
		std::wstring text;

		text = _winUTF8ToUTF16(input);

		// Open the clipboard, and empty it. 

		if (!OpenClipboard(NULL)) 
			return; 

		EmptyClipboard(); 

		// Allocate a global memory object for the text. 
		hglbCopy = GlobalAlloc(GMEM_MOVEABLE, 
			((text.length() + 1) * sizeof(WCHAR))); 

		if (hglbCopy == NULL) 
		{ 
			CloseClipboard(); 
			return; 
		} 

		// Lock the handle and copy the text to the buffer. 
		lptstrCopy = (LPWSTR)GlobalLock(hglbCopy); 
		memcpy(lptstrCopy, text.c_str(), 
			(text.length() + 1) * sizeof(WCHAR) ); 
		GlobalUnlock(hglbCopy); 

		// Place the handle on the clipboard. 

		SetClipboardData(CF_UNICODETEXT, hglbCopy); 


		// Close the clipboard. 

		CloseClipboard(); 
	}

	std::string WinClipboard::paste()
	{ 
		HGLOBAL   hglb; 
		LPWSTR    lptstr; 

		std::string result;
		std::wstring input;

		// get the clipboard text. 

		if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) 
			return result;

		if (!OpenClipboard(NULL)) 
			return result; 

		hglb = GetClipboardData(CF_UNICODETEXT); 
		if (hglb != NULL) 
		{ 
			lptstr = (LPWSTR)GlobalLock(hglb); 


			if (lptstr != NULL) 
			{ 
				input = lptstr;
				result = _winUTF16ToUTF8(input);
				GlobalUnlock(hglb); 
				
			} 
		}

		CloseClipboard(); 
		return result;
	}

	std::string WinClipboard::_winUTF16ToUTF8( const std::wstring& input )
	{
		// get length
		int length = WideCharToMultiByte( CP_UTF8, NULL,
			input.c_str(), int(input.size()),
			NULL, 0,
			NULL, NULL );
		if( !(length > 0) )
			return std::string();
		else
		{
			std::string result;
			result.resize( length );

			if( WideCharToMultiByte( CP_UTF8, NULL,
				input.c_str(), int(input.size()),
				&result[0], int(result.size()),
				NULL, NULL ) > 0 )
				return result;
			else
				return std::string();
		}

	}

	std::wstring WinClipboard::_winUTF8ToUTF16( const std::string& input )
	{
		// get length
		int length = MultiByteToWideChar( CP_UTF8, NULL,
			input.c_str(), int(input.size()),
			NULL, 0 );
		if( !(length > 0) )
			return std::wstring();
		else
		{
			std::wstring result;
			result.resize( length );

			if( MultiByteToWideChar(CP_UTF8, NULL,
				input.c_str(), int(input.size()),
				&result[0], int(result.size())) > 0 )
				return result;
			else
				return std::wstring();
		}

	}

}
