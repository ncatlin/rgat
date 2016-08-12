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
#include "Agui/Widgets/ImageWidget/ImageWidget.hpp"

namespace agui {
	ImageWidget::~ImageWidget(void)
	{
    delete this->image;
	}

	ImageWidget::ImageWidget( Image *image )
	: image(image), topMargin(4), leftMargin(4),rightMargin(4),bottomMargin(4)
  {
    if (this->image != NULL)
    {
      this->setSize(image->getWidth(), image->getHeight());
      this->setMargins(topMargin, leftMargin, rightMargin, bottomMargin);
    }
  }

  void ImageWidget::load(Image *image)
  {
    delete this->image;
    this->image = image;
    if (this->image != NULL)
    {
      this->setSize(image->getWidth(), image->getHeight());
      this->setMargins(topMargin, leftMargin, rightMargin, bottomMargin);
    }
  }

	int ImageWidget::getTopMargin() const
	{
		return topMargin;
	}

	int ImageWidget::getLeftMargin() const
	{
		return leftMargin;
	}

	int ImageWidget::getBottomMargin() const
	{
		return bottomMargin;
	}

	int ImageWidget::getRightMargin() const
	{
		return rightMargin;
	}

	void ImageWidget::paintComponent( const PaintEvent &paintEvent )
	{
    if (this->image != NULL)
      paintEvent.graphics()->drawImage(this->image, agui::Point(this->getLeftMargin(), this->getTopMargin()));
	}

	void ImageWidget::setSize( const Dimension &size )
	{
		Widget::setSize(size);
	}

	void ImageWidget::setSize( int width, int height )
	{
		Widget::setSize(width,height);
	}

	void ImageWidget::setTopMargin( int margin )
	{
		if(margin >= 0)
			topMargin = margin;
	}

	void ImageWidget::setLeftMargin( int margin )
	{
		if(margin >= 0)
			leftMargin = margin;
	}

	void ImageWidget::setBottomMargin( int margin )
	{
		if(margin >= 0)
			bottomMargin = margin;
	}

	void ImageWidget::setRightMargin( int margin )
	{
		if(margin >= 0)
			rightMargin = margin;
	}

	void ImageWidget::setMargins( int t, int l, int b, int r )
	{
		if(t > 0)
			topMargin = t;
		if(l > 0)
			leftMargin = l;
		if(b > 0)
			bottomMargin = b;
		if(r > 0)
			rightMargin = r;
    this->setSize(this->image->getWidth() + leftMargin + rightMargin,
                  this->image->getHeight() + topMargin + bottomMargin);
	}

	void ImageWidget::setClientSize( const Dimension &size )
	{
		int x = size.getWidth() + getLeftMargin() + 
			getRightMargin() + getMargin(SIDE_LEFT) + getMargin(SIDE_RIGHT);
		int y = size.getHeight() + getTopMargin() + 
			getBottomMargin() + getMargin(SIDE_TOP) + getMargin(SIDE_BOTTOM);

		setSize(x,y);
	}

}
