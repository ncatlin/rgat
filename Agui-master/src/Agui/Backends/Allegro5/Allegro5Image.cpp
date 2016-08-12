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

#include "Agui/Backends/Allegro5/Allegro5Image.hpp"

namespace agui
{

	Allegro5Image::Allegro5Image(void)
	: bmp(NULL), width(0), height(0), autoFree(false)
	{
	}

	Allegro5Image::~Allegro5Image(void)
	{
		if(bmp && autoFree)
		{
			al_destroy_bitmap(bmp);
			bmp = NULL;
		}
	}

	Allegro5Image::Allegro5Image( const std::string& fileName, bool convertMask /*= false*/ )
		:autoFree(true)
	{
		bmp = al_load_bitmap(fileName.c_str());
		if(!bmp)
		{
			throw Exception("Agui Allegro 5 Failed to load image " + fileName);
		}
		width = al_get_bitmap_width(bmp);
		height = al_get_bitmap_height(bmp);

		if(bmp && convertMask)
		{
			al_convert_mask_to_alpha(bmp,al_map_rgb(255,0,255));
		}
	}

	int Allegro5Image::getWidth() const
	{
		return width;
	}

	int Allegro5Image::getHeight() const
	{
		return height;
	}

	ALLEGRO_BITMAP* Allegro5Image::getBitmap() const
	{
		return bmp;
	}

	Color Allegro5Image::getPixel( int x, int y ) const
	{
		if(!bmp)
		{
			throw Exception("Cannot obtain the pixel of a NULL image");
		}
		ALLEGRO_COLOR c = al_get_pixel(bmp, x, y);

		unsigned char r,g,b,a;
		al_unmap_rgba(c, &r, &g, &b, &a);

		return Color(r, g, b, a);;
	}

	void Allegro5Image::setPixel( int x, int y, const Color& color )
	{
		if(!bmp)
		{
			throw Exception("Cannot set the pixel of a NULL image");
		}

		ALLEGRO_COLOR c = al_map_rgba_f(color.getR(),color.getG(),color.getB(),color.getA());
		ALLEGRO_BITMAP* oldBmp = al_get_target_bitmap();

		al_set_target_bitmap(bmp);
		al_put_pixel(x, y, c);
		al_set_target_bitmap(oldBmp);
	}

	bool Allegro5Image::isAutoFreeing() const
	{
		return autoFree;
	}

	void Allegro5Image::free()
	{
			al_destroy_bitmap(bmp);
			bmp = NULL;
	}

	void Allegro5Image::setBitmap( ALLEGRO_BITMAP* bitmap, bool autoFree /*= false*/ )
	{
		if(this->autoFree)
		{
			free();
		}
		bmp = bitmap;
		width = al_get_bitmap_width(bmp);
		height = al_get_bitmap_height(bmp);
		this->autoFree = autoFree;

	}


}
