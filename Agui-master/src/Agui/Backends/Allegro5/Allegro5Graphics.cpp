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

#include "Agui/Backends/Allegro5/Allegro5Graphics.hpp"
#include "Agui/BaseTypes.hpp"

namespace agui {
	void Allegro5Graphics::setClippingRectangle
	(const Rectangle &rect ) 
	{
		al_set_clipping_rectangle(rect.getX(),rect.getY(),
			rect.getWidth(),rect.getHeight());
	}


	void Allegro5Graphics::drawImage( const Image *bmp,
												const Point &position, 
												const float &opacity )
	{
		if(((Allegro5Image*)bmp)->getBitmap())
			al_draw_tinted_bitmap(((Allegro5Image*)bmp)->getBitmap(),
			al_map_rgba_f(opacity * getGlobalOpacity(),opacity  * getGlobalOpacity(),opacity  * getGlobalOpacity(),opacity  * getGlobalOpacity()),
			position.getX() + getOffset().getX(),position.getY() + getOffset().getY(),0);
	}

	void Allegro5Graphics::drawImage( const Image *bmp,
												const Point &position,
												const Point &regionStart,
												const Dimension &regionSize,
												const float &opacity /*= 1.0f*/ )
	{
		if(((Allegro5Image*)bmp)->getBitmap())
		al_draw_tinted_bitmap_region(((Allegro5Image*)bmp)->getBitmap(),
			al_map_rgba_f(opacity  * getGlobalOpacity(),opacity  * getGlobalOpacity(),opacity  * getGlobalOpacity(),opacity  * getGlobalOpacity()),
			regionStart.getX(),regionStart.getY(),
			regionSize.getWidth(),regionSize.getHeight(),
			position.getX() + getOffset().getX(),position.getY() + getOffset().getY(), 0);
	}

	Rectangle Allegro5Graphics::getClippingRectangle()
	{
		int x = 0;
		int y = 0;
		int width = 0;
		int height = 0;

		al_get_clipping_rectangle(&x,&y,&width,&height);
		return Rectangle(Point(x,y),Dimension(width,height));
	}



	void Allegro5Graphics::drawScaledImage( const Image *bmp,
													  const Point &position,
													  const Point &regionStart,
													  const Dimension &regionScale,
													  const Dimension &scale, 
													  const float &opacity /*= 1.0f*/ )
	{
		if(((Allegro5Image*)bmp)->getBitmap())
		al_draw_tinted_scaled_bitmap(((Allegro5Image*)bmp)->getBitmap(),
			al_map_rgba_f(opacity  * getGlobalOpacity(),opacity  * getGlobalOpacity(),opacity  * getGlobalOpacity(),opacity  * getGlobalOpacity()),
			regionStart.getX(),regionStart.getY(),
			regionScale.getWidth(),regionScale.getHeight(),
			position.getX() + getOffset().getX(),position.getY() + getOffset().getY(),
			scale.getWidth(),scale.getHeight(),0);
	}




	void Allegro5Graphics::drawText
	( const Point &position,const char* text,const Color &color, 
	 const Font *font, AlignmentEnum align /*= ALIGN_LEFT*/ )
	{
		if( font && ((Allegro5Font*)font)->getFont() && position.getY() <= getDisplaySize().getHeight())
		al_draw_text(((Allegro5Font*)font)->getFont(),getColor(color),
			position.getX() + getOffset().getX(),position.getY() + getOffset().getY(),align,text);
	}


	void Allegro5Graphics::drawRectangle( const Rectangle &rect, 
													const Color &color)
	{
		al_draw_rectangle(
			float(rect.getLeft() + getOffset().getX()) + 0.5f,
			float(rect.getTop() + getOffset().getY()) + 0.5f,
			float(rect.getRight() + getOffset().getX() - 1) + 0.5f,
			float(rect.getBottom() + getOffset().getY() - 1) + 0.5f,
			getColor(color),1);
	}

	void Allegro5Graphics::drawFilledRectangle
	( const Rectangle &rect, const Color &color )
	{
		al_draw_filled_rectangle(rect.getLeft() + getOffset().getX(),
			rect.getTop() + getOffset().getY(),
			rect.getRight() + getOffset().getX()
			,rect.getBottom() + getOffset().getY(),getColor(color));
	}

	void Allegro5Graphics::drawPixel( const Point &point,
												const Color &color )
	{
		al_put_blended_pixel(point.getX() + getOffset().getX() + 0.5f,
			point.getY() + getOffset().getY() + 0.5f,getColor(color));
	}

	void Allegro5Graphics::setTargetImage( const Image *target )
	{

		al_set_target_bitmap(((Allegro5Image*)target)->getBitmap());

	}

	void Allegro5Graphics::resetTargetImage()
	{
		al_set_target_bitmap(al_get_backbuffer
			(al_get_current_display()));
	}

	ALLEGRO_COLOR Allegro5Graphics::getColor( const Color &color )
	{
		return al_map_rgba_f(color.getR()  * getGlobalOpacity(),color.getG()  * getGlobalOpacity(),
			color.getB()  * getGlobalOpacity(),color.getA()  * getGlobalOpacity());
	}

	Dimension Allegro5Graphics::getDisplaySize()
	{
		if(al_get_current_display())
		return Dimension(al_get_display_width(
			al_get_current_display()),
			al_get_display_height(al_get_current_display()));
		else
			return Dimension(0,0);
	}

	void Allegro5Graphics::drawCircle( const Point &center,
												 float radius, 
												 const Color &color )
	{
		al_draw_circle(center.getX() + getOffset().getX(),center.getY() + getOffset().getY(),
			radius,getColor(color),1);
	}

	void Allegro5Graphics::drawFilledCircle( const Point &center,
													   float radius,
													   const Color &color )
	{
		al_draw_filled_circle(center.getX() + getOffset().getX(),
	center.getY() + getOffset().getY(),
			radius,getColor(color));
	}

	void Allegro5Graphics::drawLine( const Point &start,
											   const Point &end,
											   const Color &color)
	{

			al_draw_line(
				start.getX() + getOffset().getX(),
				start.getY() + getOffset().getY() - 0.5f,
				end.getX() + getOffset().getX(),
				end.getY() + getOffset().getY() - 0.5f,
				getColor(color),1.0f);

	}

	void Allegro5Graphics::_beginPaint()
	{
		//stub
	}

	void Allegro5Graphics::_endPaint()
	{
		//stub
	}
}
