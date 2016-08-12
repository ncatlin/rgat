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

#include "Agui/Image.hpp"
#include "Agui/ImageLoader.hpp"

namespace agui
{

	void Image::setMargins( int top, int left, int bottom, int right )
	{
		leftTop = Point(left,top);
		rightBottom = Point(right,bottom);
	}


	void Image::setMargins( int top, int left )
	{
		leftTop = Point(left,top);
		rightBottom = Point(left - 1,
			top - 1);

	}

	Image::~Image()
	{
	}

	Image::Image()
	{
	}

	ImageLoader* Image::loader = NULL;


	void Image::setImageLoader( ImageLoader* manager )
	{
		loader = manager;
	}

	const Point& Image::getLeftTopMargin() const
	{
		return leftTop;
	}

	int Image::getMargin( SideEnum side ) const
	{
		switch(side)
		{
		case SIDE_TOP:
			return leftTop.getY();
			break;
		case SIDE_LEFT:
			return leftTop.getX();
			break;
		case SIDE_BOTTOM:
			return rightBottom.getY();
			break;
		case SIDE_RIGHT:
			return rightBottom.getX();
			break;
		default:
			return 0;
		}
	}

	const Point& Image::getRightBottomMargin() const
	{
		return rightBottom;
	}

	Image* Image::load( const std::string& fileName, bool convertMask /*= false*/,
		bool convertToDisplayFormat )
	{
		if(!loader)
		{
			throw Exception("Image Loader not set!");
		}
		Image* img = loader->loadImage(fileName,convertMask,convertToDisplayFormat);
		img->setMargins(img->getWidth() / 2, img->getHeight() / 2);
		return img;
	}

}