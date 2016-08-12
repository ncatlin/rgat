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

#include "Agui/Color.hpp"

namespace agui
{
	Color::Color( float r, float g, float b, float a )
	{
		if(premultiplyAlpha)
		{
			this->r = r * a;
			this->g = g * a;
			this->b = b * a;
			this->a = a;
		}
		else
		{
			this->r = r;
			this->g = g;
			this->b = b;
			this->a = a;
		}
		verifyColorBounds();
	}

	Color::Color()
	{
		r = 0;
		g = 0;
		b = 0;
		a = 0;
	}

	Color::Color( int r, int g, int b, int a )
	{
		double num = 1.0f / 255.0f;
		*this =	Color((float)(r * num),
			(float)(g * num), (float)(b * num), (float)(a * num));

	}

	Color::Color( float r, float g, float b )
	{
		*this = Color(r,g,b,1.0f);
	}

	Color::Color( int r, int g, int b )
	{
		*this = Color(r,g,b,255);
	}

	void Color::verifyColorBounds()
	{
		if(r > 1.0f) r = 1.0f;
		if(r < 0.0f) r = 0.0f;

		if(g > 1.0f) g = 1.0f;
		if(g < 0.0f) g = 0.0f;

		if(b > 1.0f) b = 1.0f;
		if(b < 0.0f) b = 0.0f;

		if(a > 1.0f) a = 1.0f;
		if(a < 0.0f) a = 0.0f;
	}

	float Color::getR() const
	{
		return r;
	}

	float Color::getG() const
	{
		return g;
	}

	float Color::getB() const
	{
		return b;
	}

	float Color::getA() const
	{
		return a;
	}

	bool Color::isAlphaPremultiplied()
	{
		return premultiplyAlpha;
	}

	void Color::setPremultiplyAlpha( bool premultiply )
	{
		premultiplyAlpha = premultiply;
	}

	bool Color::operator==( const Color &refCol )
	{
		return refCol.getR() == r &&
			refCol.getG() == g &&
			refCol.getB() == b &&
			refCol.getA() == a;
	}

	bool Color::operator!=( const Color &refCol )
	{
		return refCol.getR() != r ||
			refCol.getG() != g ||
			refCol.getB() != b ||
			refCol.getA() != a;
	}

	bool Color::premultiplyAlpha = false;

}