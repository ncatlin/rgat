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

#include "Agui/Rectangle.hpp"

namespace agui
{

	bool Rectangle::isEmpty() const
	{
		return width == 0 && height == 0;
	}

	int Rectangle::getTop() const
	{
		return y;
	}

	int Rectangle::getLeft() const
	{
		return x;
	}

	int Rectangle::getBottom() const
	{
		return y + height;
	}

	int Rectangle::getRight() const
	{
		return x + width;
	}

	Point Rectangle::getLeftTop() const
	{
		return Point(getLeft(),getTop());
	}

	Point Rectangle::getRightBottom() const
	{
		return Point(getRight(),getBottom());
	}


	bool Rectangle::pointInside( const Point &p ) const
	{
		if(p.getX() < x) return false;
		if(p.getY() < y) return false;
		if(p.getX() >= x + width) return false;
		if(p.getY() >= y + height) return false;
		return true;
	}

	Rectangle::Rectangle()
	{
		x = 0;
		y = 0;
		width = 0;
		height = 0;
	}

	Rectangle::Rectangle( int x, int y, int width, int height )
	{
		this->x = x;
		this->y = y;
		this->width = width;
		this->height = height;
	}

	Rectangle::Rectangle( Point location,Dimension size )
	{
		x = location.getX();
		y = location.getY();
		width = size.getWidth();
		height = size.getHeight();
	}

	Rectangle Rectangle::fromTLBR( int top, int left,
		int bottom, int right )
	{

		return Rectangle(left,top,abs(right - left),abs(bottom - top));
	}

	int Rectangle::getX() const
	{
		return x;
	}

	int Rectangle::getY() const
	{
		return y;
	}

	int Rectangle::getWidth() const
	{
		return width;
	}

	int Rectangle::getHeight() const 
	{
		return height;
	}

	Point Rectangle::getTopRight() const
	{
		return Point(getRight(),getTop());
	}

	Point Rectangle::getBottomLeft() const
	{
		return Point(getLeft(),getBottom());
	}

	Dimension Rectangle::getSize() const
	{
		return Dimension(getWidth(),getHeight());
	}
}
