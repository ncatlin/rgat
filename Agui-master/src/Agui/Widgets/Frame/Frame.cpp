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

#include "Agui/Widgets/Frame/Frame.hpp"

namespace agui {
	Frame::~Frame(void)
	{
		for(std::vector<FrameListener*>::iterator it = 
			frameListeners.begin();
			it != frameListeners.end(); ++it)
		{
			if((*it))
				(*it)->death(this);
		}
		if(isMaintainingContainer)
		{
			delete pChildContainer;
		}
	}

	Frame::Frame( Widget *container /*= NULL*/ )
	: topMargin(16),titleFontMargin(6),leftMargin(4),rightMargin(4),bottomMargin(4),
      movable(true),resizable(true),dragX(0),dragY(0),moving(false)
	{
		if(container)
		{
			isMaintainingContainer = false;
			pChildContainer = container;
		}
		else
		{
			isMaintainingContainer = true;
			pChildContainer = new EmptyWidget();
		}
		addPrivateChild(pChildContainer);
		setFocusable(true);

        setFrontColor(Color(240,240,240));
        setBackColor(Color(196,210,224));


		setTopMargin(getFont()->getLineHeight() + titleFontMargin);
		setMargins(1,1,1,1);
        
        setCausesLocationChange(true);
	
	}

	void Frame::add( Widget *widget )
	{
		pChildContainer->add(widget);
		if(pChildContainer->containsChildWidget(widget))
		for(std::vector<FrameListener*>::iterator it = 
			frameListeners.begin();
			it != frameListeners.end(); ++it)
		{
			if((*it))
				(*it)->contentChildAdded(this,widget);
		}
	}

	void Frame::remove( Widget *widget )
	{
		bool containerHasChild = pChildContainer->containsChildWidget(widget);
		pChildContainer->remove(widget);

		if(containerHasChild)
			for(std::vector<FrameListener*>::iterator it = 
				frameListeners.begin();
				it != frameListeners.end(); ++it)
			{
				if((*it))
					(*it)->contentChildRemoved(this,widget);
			}

		removeFromFrame(widget);
	}

	int Frame::getTopMargin() const
	{
		return topMargin;
	}

	int Frame::getLeftMargin() const
	{
		return leftMargin;
	}

	int Frame::getBottomMargin() const
	{
		return bottomMargin;
	}

	int Frame::getRightMargin() const
	{
		return rightMargin;
	}

	void Frame::paintComponent( const PaintEvent &paintEvent )
	{
	
		paintEvent.graphics()->drawFilledRectangle(Rectangle(
			getLeftMargin() - 1,getTopMargin() - 1,
			getInnerSize().getWidth() - getLeftMargin() - getRightMargin() + 2,
      getInnerSize().getHeight() - getTopMargin() - getBottomMargin() + 2), this->frontColor);

		paintEvent.graphics()->drawRectangle(Rectangle(
			getLeftMargin() - 1,getTopMargin() - 1,
			getInnerSize().getWidth() - getLeftMargin() - getRightMargin() + 2,
			getInnerSize().getHeight() - getTopMargin() - getBottomMargin() + 2),Color(70,60,60));

		paintEvent.graphics()->pushClippingRect(Rectangle(getLeftMargin(),0,
			getSize().getWidth() - getLeftMargin() - getRightMargin(),getTopMargin()));

		paintEvent.graphics()->drawText(Point(getLeftMargin() + 1,
			(getTopMargin() - getFont()->getLineHeight()) / 2),getText().c_str(),
			getFontColor(),getFont());

		paintEvent.graphics()->popClippingRect();
	}

	void Frame::resizeContainer()
	{
		pChildContainer->setLocation(getLeftMargin(),getTopMargin());
		pChildContainer->setSize(
			getInnerSize().getWidth() - getRightMargin() - getLeftMargin(),
			getInnerSize().getHeight() - getBottomMargin() - getTopMargin());
	}

	void Frame::setSize( const Dimension &size )
	{
		Widget::setSize(size);
		resizeContainer();
	}

	void Frame::setSize( int width, int height )
	{
		Widget::setSize(width,height);
	}

	void Frame::setTopMargin( int margin )
	{
		if(margin >= 0)
		{
			topMargin = margin;
			resizeContainer();

			for(std::vector<FrameListener*>::iterator it = 
				frameListeners.begin();
				it != frameListeners.end(); ++it)
			{
				if((*it))
					(*it)->topMarginChanged(this,margin);
			}
		}
	}

	void Frame::setLeftMargin( int margin )
	{
		if(margin >= 0)
		{
			leftMargin = margin;
			resizeContainer();
			for(std::vector<FrameListener*>::iterator it = 
				frameListeners.begin();
				it != frameListeners.end(); ++it)
			{
				if((*it))
					(*it)->leftMarginChanged(this,margin);
			}
		}
	}

	void Frame::setBottomMargin( int margin )
	{
		if(margin >= 0)
		{
			bottomMargin = margin;
			resizeContainer();
			for(std::vector<FrameListener*>::iterator it = 
				frameListeners.begin();
				it != frameListeners.end(); ++it)
			{
				if((*it))
					(*it)->bottomMarginChanged(this,margin);
			}
		}
	}

	void Frame::setRightMargin( int margin )
	{
		if(margin >= 0)
		{
			rightMargin = margin;
			resizeContainer();
			for(std::vector<FrameListener*>::iterator it = 
				frameListeners.begin();
				it != frameListeners.end(); ++it)
			{
				if((*it))
					(*it)->rightMarginChanged(this,margin);
			}
		}
	}

	void Frame::setMovable( bool move )
	{
		if(movable != move)
		{
			for(std::vector<FrameListener*>::iterator it = 
				frameListeners.begin();
				it != frameListeners.end(); ++it)
			{
				if((*it))
					(*it)->movableChanged(this,move);
			}

			movable = move;
		}
		
	}

	bool Frame::isMovable() const
	{
		return movable;
	}

	void Frame::mouseDown( MouseEvent &mouseEvent )
	{
		bringToFront();
		Point relativeMouse = Point(
			mouseEvent.getX(),
			mouseEvent.getY());

		mouseEvent.consume();

		Rectangle topRect = Rectangle(getMargin(SIDE_LEFT),getMargin(SIDE_TOP),
			getInnerSize().getWidth(), getTopMargin());

		if(isResizable())
		{
			if(getBRResizeRect().pointInside(relativeMouse))
			{
				moving = false;
				resizing = true;
				dragX = mouseEvent.getX();
				dragY = mouseEvent.getY();
				initialSize = getSize();
				return;
			}
		}
		if(isMovable())
		{
			if(topRect.pointInside(relativeMouse))
			{
				resizing = false;
				moving = true;
				dragX = mouseEvent.getX();
				dragY = mouseEvent.getY();

				return;
			}
		}

		resizing = false;
		moving = false;


	}

	void Frame::mouseDrag( MouseEvent &mouseEvent )
	{
		if(moving)
		{
			int deltaX = mouseEvent.getX() - dragX + getLocation().getX();
			int deltaY = mouseEvent.getY() - dragY + getLocation().getY();

			setLocation(deltaX,deltaY);
			mouseEvent.consume();
		}
		else if(resizing)
		{
			int deltaX = mouseEvent.getX() - dragX + initialSize.getWidth();
			int deltaY = mouseEvent.getY() - dragY + initialSize.getHeight();
			setSize(Dimension(deltaX,deltaY));
			mouseEvent.consume();
		}
	}

	void Frame::mouseUp( MouseEvent &mouseEvent )
	{
		if(moving)
		{
			mouseEvent.consume();
		}
		moving = false;
	}

	void Frame::paintBackground( const PaintEvent &paintEvent )
	{
		int borderSize = 1;
		int innerBorderTLX = getMargin(SIDE_LEFT) - borderSize;
		int innerBorderTLY = getMargin(SIDE_TOP) - borderSize;
		int innerBorderBRX = getWidth() - getMargin(SIDE_RIGHT) + borderSize;
		int innerBorderBRY = getHeight() - getMargin(SIDE_BOTTOM) + borderSize;

		Rectangle fillRect = Rectangle(innerBorderTLX,
			innerBorderTLY,
			innerBorderBRX,
			innerBorderBRY);

		if(moving)
		{
			paintEvent.graphics()->drawFilledRectangle(fillRect,Color(
				getBackColor().getR(),getBackColor().getG(),getBackColor().getB(), 0.9f));
		}
		else
		{
			paintEvent.graphics()->drawFilledRectangle(fillRect,Color(
				getBackColor().getR(),getBackColor().getG(),getBackColor().getB(), 0.85f));
		}


		Color  all = Color(20,20,20);

		paintEvent.graphics()->drawRectangle(fillRect,all);
	}

	const Dimension& Frame::getContentSize() const
	{
		return pChildContainer->getInnerSize();
	}

	void Frame::addToFrame( Widget *widget )
	{
		Widget::add(widget);
	}

	void Frame::removeFromFrame( Widget *widget )
	{
		Widget::remove(widget);
	}

	Widget* Frame::getContentPane()
	{
		return pChildContainer;
	}

	void Frame::setFont( const Font *font )
	{
		Widget::setFont(font);
		if(getTopMargin() < getFont()->getLineHeight())
		{
			setTopMargin(getFont()->getLineHeight());
		}
	}

	void Frame::setResizable( bool resize )
	{
		if(resize != resizable)
		{
			resizable = resize;

			for(std::vector<FrameListener*>::iterator it = 
				frameListeners.begin();
				it != frameListeners.end(); ++it)
			{
				if((*it))
					(*it)->resizableChanged(this,resize);
			}
		}
	
	}

	bool Frame::isResizable() const
	{
		return resizable;
	}

	void Frame::flagAllChildrenForDestruction()
	{
		Widget::flagAllChildrenForDestruction();
		getContentPane()->flagAllChildrenForDestruction();
	}

	void Frame::addFrameListener( FrameListener* listener )
	{
		if(!listener)
		{
			return;
		}
		for(std::vector<FrameListener*>::iterator it = 
			frameListeners.begin();
			it != frameListeners.end(); ++it)
		{
			if((*it) == listener)
				return;
		}

		frameListeners.push_back(listener);
	}

	void Frame::removeFrameListener( FrameListener* listener )
	{
		frameListeners.erase(
			std::remove(frameListeners.begin(),
			frameListeners.end(), listener),
			frameListeners.end());
	}

	Rectangle Frame::getBRResizeRect() const
	{
		return Rectangle(
			getMargin(SIDE_LEFT) + getLeftMargin() + getInnerWidth() - getRightMargin() - getLeftMargin() - (getRightMargin() ),
			getMargin(SIDE_TOP) + getTopMargin() + getInnerHeight() - getBottomMargin() - getTopMargin() - (getBottomMargin()),
			(int)(getRightMargin() + (getRightMargin() )),
			(int)(getBottomMargin()) + getBottomMargin());
	}

	void Frame::setFrameMargins( int t, int l, int b, int r )
	{
		if(t > 0)
		{
			topMargin = t;
		}
		if(l > 0)
		{
			leftMargin = l;
		}
		if(b > 0)
		{
			bottomMargin = b;
		}
		if(r > 0)
		{
			rightMargin = r;
		}

			for(std::vector<FrameListener*>::iterator it = 
				frameListeners.begin();
				it != frameListeners.end(); ++it)
			{
				if((*it))
				{
					(*it)->topMarginChanged(this,t);
					(*it)->leftMarginChanged(this,l);
					(*it)->bottomMarginChanged(this,b);
					(*it)->rightMarginChanged(this,r);
				}
			}

			resizeContainer();

	}

	void Frame::setClientSize( const Dimension &size )
	{
		int x = size.getWidth() + getLeftMargin() + 
			getRightMargin() + getMargin(SIDE_LEFT) + getMargin(SIDE_RIGHT);
		int y = size.getHeight() + getTopMargin() + 
			getBottomMargin() + getMargin(SIDE_TOP) + getMargin(SIDE_BOTTOM);

		setSize(x,y);
	}

	void Frame::setClientSize( int width, int height )
	{
		setClientSize(Dimension(width,height));
	}

  void Frame::setFrontColor(const Color& color)
  {
    this->frontColor = color;
  }

  void Frame::resizeToContents()
  {
    topMargin = getFont()->getLineHeight() + titleFontMargin;
  }
  void Frame::setTitleFontMargin(int margin)
  {
    titleFontMargin = margin;
  }
}
