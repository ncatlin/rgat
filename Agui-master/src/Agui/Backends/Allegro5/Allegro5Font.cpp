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

#include "Agui/Backends/Allegro5/Allegro5Font.hpp"

namespace agui
{

	Allegro5Font::Allegro5Font(void)
	: font(NULL),height(0),lineHeight(0),autoFree(false)
	{

	}

	Allegro5Font::~Allegro5Font(void)
	{
		if(autoFree)
		al_destroy_font(font);
	}

  Allegro5Font::Allegro5Font( const std::string &fileName, int height , FontFlags fontFlags, float borderWidth, agui::Color borderColor )
	{
    font = NULL;
    reload(fileName, height, fontFlags, borderWidth, borderColor);
	}

  void Allegro5Font::reload( const std::string &fileName, int height , FontFlags fontFlags, float borderWidth, agui::Color borderColor )
  {
    if (font)
      free();
    font = al_load_font(fileName.c_str(),height,ALLEGRO_TTF_NO_KERNING | fontFlags);
		if(!font && fileName != "")
		{
			throw Exception("Allegro5 Failed to load font");
		}
		if(font)
		{
#ifdef AGUI_TTF_BORDER_SUPPORT
			if (allegroFontFlags & ALLEGRO_TTF_RENDER_BORDER)
			{
			  al_set_ttf_border(this->font, borderWidth, al_map_rgb(borderColor.getR()*255, borderColor.getG()*255, borderColor.getB()*255));
			}
#endif
			this->height = height;
			lineHeight = al_get_font_line_height(font);
			autoFree = true;
		}
		else
		{
			this->height = 0;
			lineHeight = 0;
			autoFree = false;
		}
  }

	void Allegro5Font::free()
	{
		al_destroy_font(font);
		font = NULL;
	}

	int Allegro5Font::getLineHeight() const
	{
		return lineHeight;
	}

	void Allegro5Font::setFont( ALLEGRO_FONT* font, const std::string &path, 
		bool autoFree /*= false*/ )
	{
		if(autoFree)
		{
			free();
		}
		this->font = font;
		if(!font)
		{
			throw Exception("Allegro5 was given a NULL font");
		}
		this->autoFree = autoFree;
		this->path = path;
		height = al_get_font_line_height(font);
		lineHeight = height;
	}

	int Allegro5Font::getHeight() const
	{
		return height;
	}

	int Allegro5Font::getTextWidth( const std::string &text ) const
	{
		if(font)
		{
			return al_get_text_width(font,text.c_str());
		}

		return 0;
		
	}

	ALLEGRO_FONT* Allegro5Font::getFont() const
	{
		return font;
	}

	const std::string& Allegro5Font::getPath() const
	{
		return path;
	}

}
