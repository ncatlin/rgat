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

#include "Agui/Font.hpp"
#include "Agui/FontLoader.hpp"
namespace agui
{
	FontLoader* Font::loader = NULL;

	Font::Font()
	{
	}

	Font::~Font()
	{
	}



	void Font::setFontLoader(FontLoader* manager)
	{
		loader = manager;
	}

	int Font::getStringIndexFromPosition( const std::string &str, int x ) const
	{
		UTF8 utf8;

		unsigned int i;
		int size = 0;

		for (i = 0; i <= utf8.length(str); ++i)
		{
			size = getTextWidth(utf8.subStr(str,0,i));

			if (size > x)
			{
				if( i == 0)
				{
					return i;
				}
				int cmpsize = getTextWidth(utf8.subStr(str,0,i - 1));
				int diff = size - cmpsize;
				diff /= 2;

				x -= cmpsize;

				if(x > diff)
				{
					return i;
				}
				else
				{
					return i - 1;
				}

			}
		}
		return int(utf8.length(str));

	}

	Font* Font::load( const std::string &fileName, int height, FontFlags fontFlags, float borderWidth, agui::Color borderColor )
	{
		return loader->loadFont(fileName,height,fontFlags,borderWidth,borderColor);
	}
  Font* Font::loadEmpty()
  {
    return loader->loadEmptyFont();
  }
}