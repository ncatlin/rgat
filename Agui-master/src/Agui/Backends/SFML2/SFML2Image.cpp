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

#include "Agui/Backends/SFML2/SFML2Image.hpp"
namespace agui
{
	SFML2Image::SFML2Image(void)
		: sfTexture(NULL),autoFree(false)
	{
	}

	SFML2Image::SFML2Image( const std::string& fileName )
		: autoFree(true),sfTexture(NULL)
	{
		sfTexture = new sf::Texture();

		sfTexture->setSmooth(true);
		if(!sfTexture->loadFromFile(fileName))
		{
			free();
			throw Exception("SFML2 Image failed to load.");
		}
	}

	SFML2Image::~SFML2Image(void)
	{
		if(autoFree)
		free();
	}

	int SFML2Image::getWidth() const
	{
		if(sfTexture)
			return (int)sfTexture->getSize().x;

		return 0;
	}

	int SFML2Image::getHeight() const
	{
		if(sfTexture)
			return (int)sfTexture->getSize().y;

		return 0;
	}

	Color SFML2Image::getPixel( int x, int y ) const
	{
		//unimplemented
		return agui::Color();
	}

	void SFML2Image::setPixel( int x, int y, const Color& color )
	{
		//unimplemented
	}

	bool SFML2Image::isAutoFreeing() const
	{
		return autoFree;
	}

	sf::Texture* SFML2Image::getBitmap() const
	{
		return sfTexture;
	}

	void SFML2Image::free()
	{
		delete sfTexture;
		sfTexture = NULL;
	}

	void SFML2Image::setBitmap( sf::Texture* bitmap, bool autoFree /*= false*/ )
	{
		if(this->autoFree)
			free();

		sfTexture = bitmap;
		this->autoFree = autoFree;
	}

}
