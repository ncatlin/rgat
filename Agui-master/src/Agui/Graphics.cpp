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

#include "Agui/Graphics.hpp"
namespace agui {
	void Graphics::pushClippingRect( const Rectangle &rect )
	{
		Rectangle relRect = Rectangle(
			rect.getX() + getOffset().getX(),
			rect.getY() + getOffset().getY(),
			rect.getWidth(),rect.getHeight()
			);

		if(clipStack.empty())
		{
			clipRect = relRect;
			clipStack.push(relRect);
			setClippingRectangle(clipRect);
			return;
		}

		workingRect = clipRect; 

		if(clipRect.getLeft() > relRect.getLeft())
			L = clipRect.getLeft();
		else
			L = relRect.getLeft();

		if(clipRect.getRight() < relRect.getRight())
			R = clipRect.getRight();
		else
			R = relRect.getRight();

		if(clipRect.getBottom() < relRect.getBottom())
			B = clipRect.getBottom();
		else
			B = relRect.getBottom();

		if(clipRect.getTop() > relRect.getTop())
			T = clipRect.getTop();
		else
			T = relRect.getTop();

		if(L > R || B < T)
		{
			clipRect = Rectangle(0,0,0,0);
		}
		else
		{
			clipRect = Rectangle::fromTLBR(T,L,B,R);
		}
		clipStack.push(clipRect);
		setClippingRectangle(clipRect);



	}
	void Graphics::popClippingRect()
	{
		if(clipStack.size() > 0)
		{
			clipStack.pop();
		}

		if(!clipStack.empty())
		{
			clipRect = clipStack.top();
			setClippingRectangle(clipRect);
		}

	}

	void Graphics::clearClippingStack()
	{
		
			while (clipStack.size() > 0)
			{
				popClippingRect();
			
			}

			clipRect = Rectangle(Point(0,0),getDisplaySize());
			setClippingRectangle(clipRect);
	}

	size_t Graphics::getClippingRectCount() const
	{
		return clipStack.size();
	}

	const Point& Graphics::getOffset() const
	{
		return offset;
	}

	void Graphics::setOffset( const Point &offset )
	{
		this->offset = offset;
	}

	const std::stack<Rectangle>& Graphics::getClippingStack() const
	{
		return clipStack;
	}


	void Graphics::setClippingStack( const std::stack<Rectangle> &clippingStack, const Point &offset )
	{
		setOffset(offset);
		clipStack = clippingStack;
		if(!clipStack.empty())
		{
			clipRect = clipStack.top();
			setClippingRectangle(clipRect);
		}
	}

	void Graphics::drawNinePatchImage( const Image *bmp,
												 const Point &position,
												 const Dimension &scale, 
												 float opacity /*= 1.0f*/ )
	{
		//top left corner
		drawImage(
			bmp,
			position,
			Point(0,0),
			Dimension(bmp->getMargin(SIDE_LEFT),bmp->getMargin(SIDE_TOP)),
			opacity);

		//bottom left corner
		drawImage(bmp,
			Point(position.getX(), position.getY() + 
			scale.getHeight() - bmp->getMargin(SIDE_BOTTOM)),
			Point(0,bmp->getHeight() - bmp->getMargin(SIDE_BOTTOM)),
			Dimension(bmp->getMargin(SIDE_LEFT),bmp->getMargin(SIDE_BOTTOM)),
			opacity
			);

		//top right corner
		drawImage(bmp,
			Point(position.getX() + scale.getWidth() - bmp->getMargin(SIDE_RIGHT),
			position.getY()),
			Point(bmp->getWidth() - bmp->getMargin(SIDE_RIGHT) ,0),
			Dimension(bmp->getMargin(SIDE_RIGHT),bmp->getMargin(SIDE_TOP)),
			opacity
			);

		//bottom right
		drawImage(bmp,
			Point(position.getX() + scale.getWidth() - bmp->getMargin(SIDE_RIGHT),
			position.getY() + scale.getHeight() - bmp->getMargin(SIDE_BOTTOM)),
			Point(bmp->getWidth() - bmp->getMargin(SIDE_RIGHT) ,
			bmp->getHeight() - bmp->getMargin(SIDE_BOTTOM)),
			Dimension(bmp->getMargin(SIDE_RIGHT),bmp->getMargin(SIDE_BOTTOM)),
			opacity
			);


		//stretched center
		drawScaledImage(bmp,
			Point(position.getX() + bmp->getMargin(SIDE_LEFT),
			position.getY() + bmp->getMargin(SIDE_TOP)),
			Point(bmp->getMargin(SIDE_LEFT) , bmp->getMargin(SIDE_TOP)),
			Dimension(bmp->getWidth() - bmp->getMargin(SIDE_LEFT) - bmp->getMargin(SIDE_RIGHT) ,
			bmp->getHeight() - bmp->getMargin(SIDE_BOTTOM) - bmp->getMargin(SIDE_TOP) ),
			Dimension(scale.getWidth() - bmp->getMargin(SIDE_LEFT) - bmp->getMargin(SIDE_RIGHT),
			scale.getHeight() - bmp->getMargin(SIDE_BOTTOM) - bmp->getMargin(SIDE_TOP)),
			opacity);

		//top edge
		drawScaledImage(bmp,
			Point(position.getX() + bmp->getMargin(SIDE_LEFT), position.getY()),
			Point(bmp->getMargin(SIDE_LEFT) , 0),
			Dimension(bmp->getWidth() - bmp->getMargin(SIDE_LEFT) - bmp->getMargin(SIDE_RIGHT) ,
			bmp->getMargin(SIDE_TOP)),
			Dimension(scale.getWidth() - bmp->getMargin(SIDE_LEFT) - bmp->getMargin(SIDE_RIGHT),
			bmp->getMargin(SIDE_TOP)),
			opacity);

		//bottom edge
		drawScaledImage(bmp,Point(position.getX() + bmp->getMargin(SIDE_LEFT),
			position.getY() + scale.getHeight() - bmp->getMargin(SIDE_BOTTOM)),
			Point(bmp->getMargin(SIDE_LEFT),
			bmp->getHeight() - bmp->getMargin(SIDE_BOTTOM)),
			Dimension(bmp->getWidth() - bmp->getMargin(SIDE_LEFT) - bmp->getMargin(SIDE_RIGHT) ,
			bmp->getMargin(SIDE_BOTTOM)),
			Dimension(scale.getWidth() - bmp->getMargin(SIDE_LEFT) - bmp->getMargin(SIDE_RIGHT),
			bmp->getMargin(SIDE_BOTTOM)),
			opacity);

		//left edge
		drawScaledImage(bmp,
			Point(position.getX(),
			position.getY() + bmp->getMargin(SIDE_TOP)),
			Point(0,bmp->getMargin(SIDE_TOP) ),
			Dimension(bmp->getMargin(SIDE_LEFT),
			bmp->getHeight() - bmp->getMargin(SIDE_BOTTOM) - bmp->getMargin(SIDE_TOP) ),
			Dimension(bmp->getMargin(SIDE_LEFT),
			scale.getHeight() - bmp->getMargin(SIDE_BOTTOM) - bmp->getMargin(SIDE_TOP)),
			opacity);

		//right edge
		drawScaledImage(bmp,
			Point(position.getX() + scale.getWidth() - bmp->getMargin(SIDE_RIGHT),
			position.getY() + bmp->getMargin(SIDE_TOP)),
			Point(bmp->getWidth() - bmp->getMargin(SIDE_RIGHT) ,
			bmp->getMargin(SIDE_TOP)),
			Dimension(bmp->getMargin(SIDE_RIGHT),
			bmp->getHeight() - bmp->getMargin(SIDE_BOTTOM) - bmp->getMargin(SIDE_TOP)),
			Dimension(bmp->getMargin(SIDE_RIGHT),
			scale.getHeight() - bmp->getMargin(SIDE_BOTTOM) - bmp->getMargin(SIDE_TOP)),
			opacity);

	}

	void Graphics::setGlobalOpacity( float o )
	{
		globalOpacity = o;
	}

	float Graphics::getGlobalOpacity() const
	{
		return globalOpacity;
	}

}


