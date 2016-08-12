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

#include "Agui/Widgets/ScrollPane/ScrollPane.hpp"
namespace agui {

	ScrollPane::ScrollPane( HScrollBar *hScroll /*= NULL*/,
		VScrollBar* vScroll /*= NULL*/, Widget* scrollBarInset /*= NULL*/,
		Widget* contentContainer /*= NULL*/ )
	{
		pChildHScroll = NULL;
		pChildVScroll = NULL;
		pChildInset = NULL;
		pChildContent = NULL;

		if(contentContainer)
		{
			isMaintainingContent = false;
			pChildContent = contentContainer;
		}
		else
		{
			isMaintainingContent = true;
			pChildContent = new EmptyWidget();
		}


		if(hScroll)
		{
			isMaintainingHScroll = false;
			pChildHScroll = hScroll;
		}
		else
		{
			isMaintainingHScroll = true;
			pChildHScroll = new HScrollBar();
		}

		if(vScroll)
		{
			isMaintainingVScroll = false;
			pChildVScroll = vScroll;
		}
		else
		{
			isMaintainingVScroll = true;
			pChildVScroll = new VScrollBar();
		}


		if(scrollBarInset)
		{
			isMaintainingInset = false;
			pChildInset = scrollBarInset;
		}
		else
		{
			isMaintainingInset = true;
			pChildInset = new EmptyWidget();
		}

		addPrivateChild(pChildContent);
		addPrivateChild(pChildInset);
		pChildContent->addWidgetListener(this);
		addPrivateChild(pChildHScroll);
		addPrivateChild(pChildVScroll);
		pChildContent->addMouseListener(this);

		pChildHScroll->addHScrollBarListener(this);
		pChildVScroll->addVScrollBarListener(this);

		setHScrollPolicy(SHOW_AUTO);
		setVScrollPolicy(SHOW_AUTO);

		setBackColor(Color(150,150,150));
		pChildInset->setBackColor(Color(120,120,120));

		setWheelScrollRate(2);
		setHKeyScrollRate(6);
		setVKeyScrollRate(6);
	}

	ScrollPane::~ScrollPane(void)
	{
		for(WidgetArray::iterator it = pChildContent->getChildBegin();
			it != pChildContent->getChildEnd(); ++it)
		{
			(*it)->removeWidgetListener(this);
			(*it)->removeMouseListener(this);
			(*it)->removeKeyboardListener(this);
		}

		pChildHScroll->removeHScrollBarListener(this);
		pChildVScroll->removeVScrollBarListener(this);

		if(isMaintainingHScroll)
		delete pChildHScroll;

		if(isMaintainingVScroll)
		delete pChildVScroll;

		if(isMaintainingInset)
		delete pChildInset;

		if(isMaintainingContent)
		delete pChildContent;
		
		
	}

	void ScrollPane::add( Widget *widget )
	{
		pChildContent->add(widget);
		pChildContent->setSize(Dimension(getContentWidth(),getContentHeight()));
		updateScrollBars();

	}

	void ScrollPane::remove( Widget *widget )
	{
		if(widget)
		{
			widget->removeMouseListener(this);
			widget->removeKeyboardListener(this);
			widget->removeWidgetListener(this);
		}
		pChildContent->remove(widget);
		pChildContent->setSize(Dimension(getContentWidth(),getContentHeight()));
		updateScrollBars();
	}

	void ScrollPane::setHScrollPolicy( ScrollPolicy policy )
	{
		hScrollPolicy = policy;
		updateScrollBars();
	}

	void ScrollPane::setVScrollPolicy( ScrollPolicy policy )
	{
		vScrollPolicy = policy;
		updateScrollBars();
	}

	ScrollPolicy ScrollPane::getHScrollPolicy() const
	{
		return hScrollPolicy;
	}

	ScrollPolicy ScrollPane::getVScrollPolicy() const
	{
		return vScrollPolicy;
	}

	void ScrollPane::checkScrollPolicy()
	{
		switch (getHScrollPolicy())
		{
		case SHOW_ALWAYS:
			pChildHScroll->setVisibility(true);
			break;
		case SHOW_NEVER:
			pChildHScroll->setVisibility(false);
			break;
		case SHOW_AUTO:
			pChildHScroll->setVisibility(isHScrollNeeded());
			break;
		default:
			break;
		}

		switch (getVScrollPolicy())
		{
		case SHOW_ALWAYS:
			pChildVScroll->setVisibility(true);
			break;
		case SHOW_NEVER:
			pChildVScroll->setVisibility(false);
			break;
		case SHOW_AUTO:
			pChildVScroll->setVisibility(isVScrollNeeded());
			break;
		default:
			break;
		}

	}

	void ScrollPane::resizeSBsToPolicy()
	{
		pChildHScroll->setLocation(0,getInnerSize().getHeight()
			- pChildHScroll->getHeight());

		pChildVScroll->setLocation(getInnerSize().getWidth()
			- pChildVScroll->getWidth(),0);

		if(pChildHScroll->isVisible() && 
			pChildVScroll->isVisible())
		{
			pChildHScroll->setSize(getInnerSize().getWidth() - pChildVScroll->getWidth()
				,pChildHScroll->getHeight());
			pChildVScroll->setSize(pChildVScroll->getWidth(),
				getInnerSize().getHeight() - pChildHScroll->getHeight());
		}
		else if(pChildHScroll->isVisible())
		{
			pChildHScroll->setSize(getInnerSize().getWidth(),pChildHScroll->getHeight());
		}
		else if(pChildVScroll->isVisible())
		{
			pChildVScroll->setSize(pChildVScroll->getWidth(),getInnerSize().getHeight());
		}

		pChildInset->setVisibility(
			pChildVScroll->isVisible() && 
			pChildHScroll->isVisible());

		pChildInset->setLocation(pChildVScroll->getLocation().getX(),
			pChildHScroll->getLocation().getY());

		pChildInset->setSize(pChildVScroll->getSize().getWidth(),
			pChildHScroll->getSize().getHeight());

	}

	int ScrollPane::getContentWidth() const
	{
		int w = 0;
		for(WidgetArray::const_iterator it = pChildContent->getChildBegin();
			it != pChildContent->getChildEnd(); ++it)
		{
			if((*it)->getRelativeRectangle().getRight() > w)
			{
				w = (*it)->getRelativeRectangle().getRight();
			}
		}

		return w;
	}

	int ScrollPane::getContentHeight() const
	{
		int h = 0;
		for(WidgetArray::const_iterator it = pChildContent->getChildBegin();
			it != pChildContent->getChildEnd(); ++it)
		{
			if((*it)->getRelativeRectangle().getBottom() > h)
			{
				h = (*it)->getRelativeRectangle().getBottom();
			}
		}

		return h;
	}

	bool ScrollPane::isHScrollNeeded() const
	{
		if(getHScrollPolicy() == SHOW_NEVER)
		{
			return false;
		}
		if(getContentWidth() > getSize().getWidth())
		{
			return true;
		}
		else if(getVScrollPolicy() != SHOW_NEVER &&
			(getContentHeight() >  getSize().getHeight()  &&
			getContentWidth() > (getSize().getWidth() - pChildVScroll->getWidth() )))
		{
			return true;
		}
		return false;
	}

	bool ScrollPane::isVScrollNeeded() const
	{
		if(getVScrollPolicy() == SHOW_NEVER)
		{
			return false;
		}

		if(getContentHeight() > getSize().getHeight())
		{
			return true;
		}
		else if(getHScrollPolicy() != SHOW_NEVER &&
			(getContentWidth() >  getSize().getWidth()  &&
			getContentHeight() > (getSize().getHeight() - pChildHScroll->getHeight() )))
		{
			return true;
		}
		return false;
	}


	void ScrollPane::updateScrollBars()
	{
		checkScrollPolicy();
		resizeSBsToPolicy();
		adjustSBRanges();
	}


	void ScrollPane::textChanged( Widget* source, const std::string &text )
	{
		(void)source; (void)text;
	}

	void ScrollPane::valueChanged( HScrollBar* source, int val )
	{
		(void)source;
		pChildContent->setLocation(-val,
			pChildContent->getLocation().getY());
	}

	void ScrollPane::valueChanged( VScrollBar* source,int val )
	{
		(void)source;
		pChildContent->setLocation(pChildContent->getLocation().getX(),
			-val);
	}

	void ScrollPane::sizeChanged( Widget* source, const Dimension &size )
	{
		(void)source; (void)size; 
		updateScrollBars();

		if(source != pChildContent)
		pChildContent->setSize(Dimension(getContentWidth(),getContentHeight()));
	}

	void ScrollPane::locationChanged( Widget* source, const Point &location )
	{
		(void)source; (void)location;

		if(source != pChildContent)
		updateScrollBars();

		if(source != pChildContent)
		pChildContent->setSize(Dimension(getContentWidth(),getContentHeight()));
	}

	void ScrollPane::setSize( const Dimension &size )
	{
		Widget::setSize(size);
		updateScrollBars();
		pChildContent->setSize(Dimension(getContentWidth(),getContentHeight()));

	}

	void ScrollPane::setSize( int width, int height )
	{
		Widget::setSize(width,height);
	}

	void ScrollPane::paintComponent( const PaintEvent &paintEvent )
	{

	}

	void ScrollPane::mouseWheelDownCB( MouseEvent &mouseEvent )
	{
		if(!mouseEvent.isConsumed())
		{
			pChildVScroll->wheelScrollDown(mouseEvent.getMouseWheelChange());
		}
	}

	void ScrollPane::mouseWheelUpCB( MouseEvent &mouseEvent )
	{
		if(!mouseEvent.isConsumed())
		{
			pChildVScroll->wheelScrollUp(mouseEvent.getMouseWheelChange());
		}
	}

	void ScrollPane::mouseWheelDown( MouseEvent &mouseEvent )
	{
		pChildVScroll->setValue(pChildVScroll->getValue() + getWheelScrollRate() 
			- mouseEvent.getMouseWheelChange());
		mouseEvent.consume();
	}

	void ScrollPane::mouseWheelUp( MouseEvent &mouseEvent )
	{

		pChildVScroll->setValue(pChildVScroll->getValue() - getWheelScrollRate() 
			- mouseEvent.getMouseWheelChange());
		mouseEvent.consume();
	}

	void ScrollPane::adjustSBRanges()
	{
		int extraH = 0;
		int extraV = 0;

		if(pChildHScroll->isVisible())
		{
			extraH += pChildHScroll->getHeight();
		}

		if(pChildVScroll->isVisible())
		{
			extraV += pChildVScroll->getWidth();
		}

		//set vertical value
		pChildVScroll->setRangeFromPage(getInnerSize().getHeight() - extraH,getContentHeight());


		//set horizontal value
		pChildHScroll->setRangeFromPage(getInnerSize().getWidth() - extraV,getContentWidth());
	}

	void ScrollPane::setWheelScrollRate( int rate )
	{
		pChildVScroll->setMouseWheelAmount(rate);
	}

	int ScrollPane::getWheelScrollRate() const
	{
		return pChildVScroll->getMouseWheelAmount();
	}


	void ScrollPane::keyDownCB( KeyEvent &keyEvent )
	{
		keyAction(keyEvent.getExtendedKey());
	}

	void ScrollPane::setHKeyScrollRate( int rate )
	{
		hKeyScrollRate = rate;
	}

	int ScrollPane::getHKeyScrollRate() const
	{
		return hKeyScrollRate;
	}

	void ScrollPane::setVKeyScrollRate( int rate )
	{
		vKeyScrollRate = rate;
	}

	int ScrollPane::getVKeyScrollRate() const
	{
		return vKeyScrollRate;
	}

	void ScrollPane::keyAction( ExtendedKeyEnum key )
	{
		switch (key)
		{
		case EXT_KEY_UP:
			pChildVScroll->setValue(pChildVScroll->getValue()
				- getVKeyScrollRate());
			break;
		case EXT_KEY_DOWN:
			pChildVScroll->setValue(pChildVScroll->getValue()
				+ getVKeyScrollRate());
			break;
		case EXT_KEY_LEFT:
			pChildHScroll->setValue(pChildHScroll->getValue()
				- getHKeyScrollRate());
			break;
		case EXT_KEY_RIGHT:
			pChildHScroll->setValue(pChildHScroll->getValue()
				+ getHKeyScrollRate());
			break;
		case EXT_KEY_PAGE_DOWN:
			pChildVScroll->setValue(pChildVScroll->getValue() +
				pChildVScroll->getLargeAmount());
			break;
		case EXT_KEY_PAGE_UP:
			pChildVScroll->setValue(pChildVScroll->getValue() -
				pChildVScroll->getLargeAmount());
				break;
        default: break;
		}

	}

	void ScrollPane::keyRepeatCB( KeyEvent &keyEvent )
	{
			keyAction(keyEvent.getExtendedKey());
	}

	void ScrollPane::keyUpCB( KeyEvent &keyEvent )
	{
		(void)keyEvent;
	}

	int ScrollPane::getTopArrowAmount() const
	{
		return pChildVScroll->getTopArrowAmount();
	}

	int ScrollPane::getBottomArrowAmount() const
	{
		return pChildVScroll->getBottomArrowAmount();
	}

	int ScrollPane::getLeftArrowAmount() const
	{
		return pChildHScroll->getLeftArrowAmount();
	}

	int ScrollPane::getRightArrowAmount() const
	{
		return pChildHScroll->getRightArrowAmount();
	}

	void ScrollPane::setTopArrowAmount( int amount )
	{
		pChildVScroll->setTopArrowAmount(amount);
	}

	void ScrollPane::setBottomArrowAmount( int amount )
	{
		pChildVScroll->setBottomArrowAmount(amount);
	}

	void ScrollPane::setLeftArrowAmount( int amount )
	{
		pChildHScroll->setLeftArrowAmount(amount);
	}

	void ScrollPane::setHMinThumbSize( int size )
	{
		pChildHScroll->setMinThumbWidth(size);
	}

	int ScrollPane::getHMinThumbSize() const
	{
		return pChildHScroll->getMinThumbWidth();
	}

	void ScrollPane::setVMinThumbSize( int size )
	{
		pChildVScroll->setMinThumbHeight(size);
	}

	int ScrollPane::getVMinThumbSize() const
	{
		return pChildVScroll->getMinThumbHeight();
	}

	void ScrollPane::childAdded( Widget* source, Widget* widget )
	{
		if(source == pChildContent)
		{
			widget->addWidgetListener(this);
			widget->addMouseListener(this);
			widget->addKeyboardListener(this);

			updateScrollBars();
		}
	}

	void ScrollPane::childRemoved( Widget* source, Widget* widget )
	{
		if(source == pChildContent)
		{
			widget->removeWidgetListener(this);
			widget->removeMouseListener(this);
			widget->removeKeyboardListener(this);


		}
	}

	void ScrollPane::setRightArrowAmount( int amount )
	{
		pChildHScroll->setRightArrowAmount(amount);
	}

	void ScrollPane::paintBackground( const PaintEvent &paintEvent )
	{
		//draw background
		paintEvent.graphics()->drawFilledRectangle(getSizeRectangle(),getBackColor());

		Color  Top = Color(110,110,110);
		Color  Left = Color(110,110,110);
		Color  Bottom = Color(110,110,110);
		Color  Right = Color(110,110,110);


		//top
		paintEvent.graphics()->drawLine(Point(0,1),
			Point(getSize().getWidth(),1),Top);
		//left
		paintEvent.graphics()->drawLine(Point(1,1),
			Point(1,getSize().getHeight()),Left);

		//right
		paintEvent.graphics()->drawLine(Point(getSize().getWidth() ,1),
			Point(getSize().getWidth() ,getSize().getHeight()),Right);

		//bottom
		paintEvent.graphics()->drawLine(Point(0,getSize().getHeight()),
			Point(getSize().getWidth(),getSize().getHeight()),Bottom);
	}

	bool ScrollPane::intersectionWithPoint( const Point &p ) const
	{
		return Rectangle(getMargin(SIDE_LEFT),
			getMargin(SIDE_TOP),getInnerWidth(),getInnerHeight()).pointInside(p);
	}

	void ScrollPane::flagAllChildrenForDestruction()
	{
		Widget::flagAllChildrenForDestruction();
		pChildContent->flagAllChildrenForDestruction();
	}

	void ScrollPane::resizeWidthToContents()
	{
		int vscroll = 0;
		if(getVScrollPolicy() == SHOW_ALWAYS)
		{
			vscroll = pChildVScroll->getWidth();
		}

		setSize(getMargin(SIDE_LEFT) +
			getMargin(SIDE_RIGHT) +
			getContentWidth() +
			vscroll,
			getHeight());
	}

	void ScrollPane::resizeHeightToContents()
	{
		int hscroll = 0;
		if(getHScrollPolicy() == SHOW_ALWAYS)
		{
			hscroll = pChildHScroll->getWidth();
		}

		setSize(getWidth(),
			getMargin(SIDE_TOP) +
			getMargin(SIDE_BOTTOM) +
			getContentHeight() +
			hscroll
			);
	}

	void ScrollPane::resizeToContents()
	{
		resizeWidthToContents();
		resizeHeightToContents();
	}



}
