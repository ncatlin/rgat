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

#ifndef AGUI_SFML2_GRAPHICS_HPP
#define AGUI_SFML2_GRAPHICS_HPP
#include "Agui/Graphics.hpp"
#include <SFML/Graphics.hpp>
namespace agui
{
	class AGUI_BACKEND_DECLSPEC SFML2Graphics : public Graphics
	{
		sf::RenderTarget& target;
		std::wstring wide;
		sf::View originalView;
		int sfHeight;
		Rectangle clRct;
		inline std::wstring StringToUnicode( const std::string& strIn )
		{
			wide.clear();
			sf::Utf<8>::toWide(strIn.begin(), strIn.end(), back_inserter(wide));
			return wide;
		}
		sf::Color colToSf(const agui::Color& c) const;
	protected:
		void startClip();
		void endClip();
		virtual void setClippingRectangle(const Rectangle &rect);
	public:
		SFML2Graphics(sf::RenderTarget& target);
		virtual void _beginPaint();
		virtual void _endPaint();
		virtual Dimension getDisplaySize();
		virtual Rectangle getClippingRectangle();
		virtual void drawImage(const Image *bmp,
			const Point &position,const Point &regionStart,const Dimension &regionSize,
			const float &opacity = 1.0f);
		virtual void drawImage(const Image *bmp,const Point &position,
			const float &opacity = 1.0f);
		virtual void drawScaledImage(const Image *bmp,const Point &position,
			const Point &regionStart,
			const Dimension &regionScale,
			const Dimension &scale, const float &opacity = 1.0f);
		virtual void drawText(const Point &position,const char* text,
			const Color &color, const Font *font,
			AlignmentEnum align = ALIGN_LEFT);
		virtual void drawRectangle(const Rectangle &rect, 
			const Color &color);
		virtual void drawFilledRectangle(const Rectangle &rect, const Color &color);
		virtual void drawPixel(const Point &point, const Color &color);
		virtual void drawCircle(const Point &center,float radius, const Color &color);
		virtual void drawFilledCircle(const Point &center,float radius,const Color &color);
		virtual void drawLine(const Point &start, const Point &end,
			const Color &color);

		virtual void setTargetImage(const Image *target);
		virtual void resetTargetImage();
		virtual ~SFML2Graphics(void);
	};
}
#endif
