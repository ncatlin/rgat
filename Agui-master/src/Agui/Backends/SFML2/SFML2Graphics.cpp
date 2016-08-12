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

#include "Agui/Backends/SFML2/SFML2Graphics.hpp"
#include "Agui/Backends/SFML2/SFML2Font.hpp"
#include "Agui/Backends/SFML2/SFML2Image.hpp"
#include <SFML/OpenGL.hpp>
namespace agui
{
	SFML2Graphics::~SFML2Graphics(void)
	{
	}

	SFML2Graphics::SFML2Graphics( sf::RenderTarget& target )
		: target(target),sfHeight(target.getSize().y)
	{
	}

	void SFML2Graphics::_beginPaint()
	{
		originalView = target.getView();
		sfHeight = target.getSize().y;
		sf::FloatRect vrect;
		vrect.left = 0; vrect.top = 0;
		vrect.width = (float)target.getSize().x;
		vrect.height = (float)target.getSize().y;
		sf::FloatRect vprect;
		vprect.left = 0; vprect.top = 0;
		vprect.width = 1.0f; vprect.height = 1.0f;
		sf::View view( vrect );
		view.setViewport( vprect );
		target.setView( view );
		setClippingRectangle(Rectangle(0,0,target.getSize().x,target.getSize().y));
	}

	void SFML2Graphics::_endPaint()
	{
		target.setView( originalView );
		endClip();
	}

	agui::Dimension SFML2Graphics::getDisplaySize()
	{
		return agui::Dimension(target.getSize().x,target.getSize().y);
	}

	Rectangle SFML2Graphics::getClippingRectangle()
	{
		return clRct;
	}

	void SFML2Graphics::drawImage( const Image *bmp, const Point &position,
		const Point &regionStart,const Dimension &regionSize, const float &opacity /*= 1.0f*/ )
	{
		sf::Sprite sp;
		SFML2Image* img = (SFML2Image*)(bmp);
		sp.setTexture(*img->getBitmap());
		sp.setColor(sf::Color(255,255,255,(sf::Uint8)(255 * opacity)));
		sp.setPosition((float)(position.getX() + getOffset().getX()),(float)(position.getY() + getOffset().getY()));
		sp.setTextureRect(sf::IntRect(regionStart.getX(),regionStart.getY(),regionSize.getWidth(),regionSize.getHeight()));
		target.draw(sp);
	}

	void SFML2Graphics::drawImage( const Image *bmp,const Point &position, const float &opacity /*= 1.0f*/ )
	{
		sf::Sprite sp;
		SFML2Image* img = (SFML2Image*)(bmp);
		sp.setTexture(*img->getBitmap());
		sp.setColor(sf::Color(255,255,255,(sf::Uint8)(255 * opacity)));
		sp.setPosition((float)(position.getX() + getOffset().getX()),(float)(position.getY() + getOffset().getY()));
		target.draw(sp);
	}

	void SFML2Graphics::drawScaledImage( const Image *bmp,const Point &position, 
		const Point &regionStart, const Dimension &regionScale, const Dimension &scale, const float &opacity /*= 1.0f*/ )
	{
		sf::Sprite sp;
		SFML2Image* img = (SFML2Image*)(bmp);
		sp.setTexture(*img->getBitmap());
		sp.setColor(sf::Color(255,255,255,(sf::Uint8)(255 * opacity)));
		sp.setPosition((float)(position.getX()  + getOffset().getX()),(float)(position.getY()  + getOffset().getY()));
		sp.setTextureRect(sf::IntRect(regionStart.getX(),regionStart.getY(),regionScale.getWidth(),regionScale.getHeight()));
		sp.setScale((float)scale.getWidth() / (float)regionScale.getWidth(),(float)scale.getHeight() / (float)regionScale.getHeight());
		target.draw(sp);
	}

	void SFML2Graphics::drawText( 
		const Point &position,const char* text, const Color &color, const Font *font, AlignmentEnum align /*= ALIGN_LEFT*/ )
	{
		SFML2Font* sfFont = (SFML2Font*)(font);
		const sf::Font* pSFFont = sfFont->getFont();
		sf::Text sfStr;
		sfStr.setString( StringToUnicode(text) );
		sfStr.setFont( *pSFFont );
		sfStr.move( (float)(position.getX()  + getOffset().getX()), (float)(position.getY()  + getOffset().getY()) );
		sfStr.setCharacterSize( font->getHeight() );

		sf::FloatRect textRect = sfStr.getLocalBounds();
		if(align == ALIGN_CENTER)
		sfStr.setOrigin(textRect.left + textRect.width/2.0f,
			textRect.top);
		else if(align == ALIGN_RIGHT)
			sfStr.setOrigin(textRect.left + textRect.width,
			textRect.top);

		sfStr.setColor(colToSf(color));

		target.draw( sfStr );
	}

	void SFML2Graphics::drawRectangle( const Rectangle &rect, const Color &color )
	{
		sf::RectangleShape rectangle;
		rectangle.setPosition(sf::Vector2f(
			float(rect.getLeft() + getOffset().getX()) + 1.0f,
			float(rect.getTop() + getOffset().getY() + 0.5f)
			));
		rectangle.setSize(sf::Vector2f(rect.getWidth() - 1.5f, rect.getHeight() - 1.5f));
		rectangle.setFillColor(sf::Color::Transparent);
		rectangle.setOutlineThickness(1.0f);
		rectangle.setOutlineColor(colToSf(color));
		target.draw(rectangle);
	}

	void SFML2Graphics::drawFilledRectangle( const Rectangle &rect, const Color &color )
	{
		sf::RectangleShape rectangle;
		rectangle.setPosition(sf::Vector2f((float)(rect.getX()  + getOffset().getX()),(float)(rect.getY() + getOffset().getY())));
		rectangle.setSize(sf::Vector2f((float)rect.getWidth(),(float)rect.getHeight()));
		rectangle.setFillColor(colToSf(color));
		target.draw(rectangle);
	}

	void SFML2Graphics::drawPixel( const Point &point, const Color &color )
	{
		sf::RectangleShape rectangle(sf::Vector2f((float)(point.getX()  + getOffset().getX()),(float)(point.getY()  + getOffset().getY())));
		rectangle.setSize(sf::Vector2f(1,1));
		rectangle.setFillColor(sf::Color((sf::Uint8)(color.getR() * 255),
			(sf::Uint8)(color.getG() * 255),
			(sf::Uint8)(color.getB() * 255),
			(sf::Uint8)(color.getA() * 255)));
		target.draw(rectangle);
	}

	void SFML2Graphics::drawCircle( const Point &center,float radius, const Color &color )
	{
		sf::CircleShape circle(radius);
		circle.setOrigin(radius,radius);
		circle.setFillColor(sf::Color::Transparent);
		circle.setPosition((float)(center.getX()  + getOffset().getX()),(float)(center.getY()  + getOffset().getY()));
		circle.setOutlineThickness(1.0f);
		circle.setOutlineColor(colToSf(color));
		target.draw(circle);
	}

	void SFML2Graphics::drawFilledCircle( const Point &center,float radius,const Color &color )
	{
		sf::CircleShape circle(radius);
		circle.setOrigin(radius,radius);
		circle.setPosition((float)(center.getX()  + getOffset().getX()),(float)(center.getY()  + getOffset().getY()));
		circle.setFillColor(colToSf(color));
		target.draw(circle);
	}

	void SFML2Graphics::drawLine( const Point &start, const Point &end, const Color &color )
	{
		sf::Vertex line[] =
		{
			sf::Vertex(sf::Vector2f((float)(start.getX()  + getOffset().getX()), (float)(start.getY() + getOffset().getY()) - 0.5f),
		colToSf(color)),
			sf::Vertex(sf::Vector2f((float)(end.getX()  + getOffset().getX()), (float)(end.getY() + getOffset().getY()) - 0.5f),
		colToSf(color))
		};

		target.draw(line, 2, sf::Lines);
	}

	void SFML2Graphics::setTargetImage( const Image *target )
	{
		//unimplemented
	}

	void SFML2Graphics::resetTargetImage()
	{
		//unimplemented
	}

	void SFML2Graphics::setClippingRectangle( const Rectangle &rect )
	{
		clRct = rect;
	    startClip();
	}

	void SFML2Graphics::startClip()
	{
			int x = clRct.getX(), y = clRct.getY(), w = clRct.getWidth(), h = clRct.getHeight();
			// OpenGL's coords are from the bottom left
			// so we need to translate them here.
			y = sfHeight - ( y + h );

			glEnable( GL_SCISSOR_TEST );
			glScissor( x, y, w, h );
	}

	void SFML2Graphics::endClip()
	{
		glDisable( GL_SCISSOR_TEST );
	}

	sf::Color SFML2Graphics::colToSf( const agui::Color& c ) const
	{
		return sf::Color((sf::Uint8)(c.getR() * 255),
			(sf::Uint8)(c.getG() * 255),
			(sf::Uint8)(c.getB() * 255),
			(sf::Uint8)(c.getA() * 255));
	}

}
