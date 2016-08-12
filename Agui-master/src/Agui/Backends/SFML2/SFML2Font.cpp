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

#include "Agui/Backends/SFML2/SFML2Font.hpp"
namespace agui
{
	static std::wstring wide;
	std::wstring StringToUnicode( const std::string& strIn )
	{
		wide.clear();
		sf::Utf<8>::toWide(strIn.begin(), strIn.end(), back_inserter(wide));
		return wide;
	}

	SFML2Font::SFML2Font(void)
		: sfFont(NULL),autoFree(false),
		characterSize(0)
	{
	}

	SFML2Font::SFML2Font( const std::string &fileName, int height, FontFlags fontFlags /*= FONT_DEFAULT_FLAGS*/ )
		:autoFree(true),characterSize(height)
	{
		sfFont = new sf::Font();
		if(!sfFont->loadFromFile(fileName))
		{
			free();
			throw Exception("Agui SFML2 Font failed to load.");
		}
	}

	SFML2Font::~SFML2Font(void)
	{
		if(autoFree)
			free();
	}

	void SFML2Font::free()
	{
		delete sfFont;
		sfFont = NULL;
		characterSize = 0;
	}

	sf::Font* SFML2Font::getFont() const
	{
		return sfFont;
	}

	int SFML2Font::getLineHeight() const
	{
		if(sfFont)
			return sfFont->getLineSpacing(sfFont->getLineSpacing(characterSize));
		return 0;
	}

	int SFML2Font::getHeight() const
	{
		return characterSize;
	}

	int SFML2Font::getTextWidth( const std::string &text ) const
	{
		if(sfFont)
		{
			sf::Text sfStr;
			sfStr.setString( StringToUnicode(text) );
			sfStr.setFont( *sfFont );
			sfStr.setCharacterSize( characterSize );
			return (int)sfStr.getLocalBounds().width;
		}

		return 0;
	}

	const std::string& SFML2Font::getPath() const
	{
		return path;
	}

	void SFML2Font::setFont( sf::Font* font, const std::string &path, int characterSize, bool autoFree /*= false*/ )
	{
		if(this->autoFree)
			free();

		sfFont = font;
		this->characterSize = characterSize;
		this->autoFree = autoFree;
	}

	void SFML2Font::setHeight( int characterSize )
	{
		this->characterSize = characterSize;
	}

	void SFML2Font::reload( const std::string &fileName, int height, FontFlags fontFlags /*= FONT_DEFAULT_FLAGS */, float borderWidth /*= 0*/, agui::Color borderColor /*= agui::Color()*/ )
	{
		if(autoFree)
			free();

		this->autoFree = true;
		this->characterSize = characterSize;

		sfFont = new sf::Font();
		if(!sfFont->loadFromFile(fileName))
		{
			free();
			throw Exception("Agui SFML2 Font failed to load.");
		}
	}

}


