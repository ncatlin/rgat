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

#ifndef AGUI_ALLEGRO5_FONT_HPP
#define AGUI_ALLEGRO5_FONT_HPP
#include "Agui/BaseTypes.hpp"

//Allegro 5 
#include <allegro5/allegro.h>
#include <allegro5/allegro5.h>
#include <allegro5/allegro_image.h>
#include <allegro5/allegro_primitives.h>
#include <allegro5/allegro_font.h>
#include <allegro5/allegro_ttf.h>

namespace agui
{
	class Allegro5Font :
		public Font
	{
		ALLEGRO_FONT* font;
		std::string path;
		int height;
		int lineHeight;
		bool autoFree;
	public:
		virtual void free();
		ALLEGRO_FONT* getFont() const;
		virtual int getLineHeight() const;
		virtual int getHeight() const;
		virtual int getTextWidth(const std::string &text) const;
		virtual const std::string& getPath() const;
		Allegro5Font(void);
    Allegro5Font(const std::string &fileName, int height, FontFlags fontFlags = FONT_DEFAULT_FLAGS, float borderWidth = 0, agui::Color borderColor = agui::Color());
    virtual void reload(const std::string &fileName, int height, FontFlags fontFlags = FONT_DEFAULT_FLAGS, float borderWidth = 0, agui::Color borderColor = agui::Color());
		virtual void setFont(ALLEGRO_FONT* font, const std::string &path, bool autoFree = false);
		virtual ~Allegro5Font(void);
	};
}
#endif