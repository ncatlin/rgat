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

#include "Agui/Widgets/ScrollBar/HScrollBar.hpp"
namespace agui {
	HScrollBar::HScrollBar( Widget *thumb /*= NULL*/,
		Widget *leftArrow /*= NULL*/, 
		Widget *rightArrow /*= NULL*/ )
        : lastArrowTick(0.0),largeAmount(10), minValue(0), maxValue(100),
        currentValue(0), downThumbPos(0), downMousePos(0),
        leftArrowDown(false),rightArrowDown(false),
        autoScrollStartInterval(0.35f),minThumbSize(10)
	{

		if(thumb)
		{
			isMaintainingThumb = false;
			pChildThumb = thumb;
		}
		else
		{
			isMaintainingThumb = true;
			pChildThumb = new Button();
			((Button*)pChildThumb)->setMouseLeaveState(Button::CLICKED);
		}

		if(leftArrow)
		{
			isMaintainingLeftArrow = false;
			pChildLeftArrow = leftArrow;
			((Button*)pChildLeftArrow)->setMouseLeaveState(Button::CLICKED);
		}
		else
		{
			isMaintainingLeftArrow = true;
			pChildLeftArrow = new Button();
		}

		if(rightArrow)
		{
			isMaintainingRightArrow = false;
			pChildRightArrow = rightArrow;
		}
		else
		{
			isMaintainingRightArrow = true;
			pChildRightArrow = new Button();
			((Button*)pChildRightArrow)->setMouseLeaveState(Button::CLICKED);
		}

		pChildThumb->setFocusable(false);
		pChildLeftArrow->setFocusable(false);
		pChildRightArrow->setFocusable(false);

		pChildThumb->addMouseListener(this);
		pChildLeftArrow->addMouseListener(this);
		pChildRightArrow->addMouseListener(this);

		pChildRightArrow->setBackColor(Color(80,160,200));
		pChildLeftArrow->setBackColor(Color(80,160,200));
		pChildThumb->setBackColor(Color(60,140,180));
        
        pChildLeftArrow->setCausesLocationChange(true);
        pChildThumb->setCausesLocationChange(true);
        pChildRightArrow->setCausesLocationChange(true);

		addPrivateChild(pChildThumb);
		addPrivateChild(pChildLeftArrow);
		addPrivateChild(pChildRightArrow);

		setLeftArrowAmount(5);
		setRightArrowAmount(5);
		setArrowWidth(16);
		setSize(400,16);
		setMargins(0,0,0,0);
        
        setCausesLocationChange(true);

		setBackColor(Color(200,200,201));
	}

	HScrollBar::~HScrollBar(void)
	{
		for(std::vector<HScrollBarListener*>::iterator it = 
			hScrollListeners.begin();
			it != hScrollListeners.end(); ++it)
		{
			if((*it))
				(*it)->death(this);
		}

		for(WidgetArray::iterator it = getPrivateChildBegin(); it != 
			getPrivateChildEnd(); ++it)
		{
			(*it)->removeMouseListener(this);
		}
		for(WidgetArray::iterator it = getChildBegin(); it != 
			getChildEnd(); ++it)
		{
			(*it)->removeMouseListener(this);
		}

		if(isMaintainingThumb)
			delete pChildThumb;

		if(isMaintainingLeftArrow)
			delete pChildLeftArrow;

		if(isMaintainingRightArrow)
			delete pChildRightArrow;
	}

	void HScrollBar::resizeThumb()
	{
		//the width if 1 pixel = 1 value
		int width = getLargeAmount();

		int maxValSupport = getMaxValue() - getMinValue();
		//get the ratio
		float change = (float)getMaxThumbSize() / (float)maxValSupport;

		//make height proportional to ratio
		width = (int)((float)width * change);

		//make sure the thumb never gets too small
		if(width < getMinThumbWidth())
		{
			width = getMinThumbWidth();
		}

		if(width > getMaxThumbSize())
		{

			pChildThumb->setVisibility(false);
		}
		else if(pChildThumb->isVisible() == false)
		{
			pChildThumb->setVisibility(true);
		}

		pChildThumb->setSize(width,getInnerSize().getHeight());
	}

	void HScrollBar::positionThumb()
	{
		float val = getAdjustedMaxThumbSize() * getRelativeValue();
		val += pChildLeftArrow->getSize().getWidth();


		if(getValue() == getMaxValue() - getLargeAmount())
		{
			val = (float)(pChildRightArrow->getLocation().getX() -
				pChildThumb->getSize().getWidth());
		}

		if(val + pChildThumb->getSize().getWidth() >
			pChildRightArrow->getLocation().getX())
		{
			val = (float)(pChildRightArrow->getLocation().getX() - 
				pChildThumb->getSize().getWidth());
		}
		pChildThumb->setLocation((int)val,0);
	}

	void HScrollBar::positionArrows()
	{
		pChildLeftArrow->setLocation(0,0);
		pChildRightArrow->setLocation(getInnerSize().getWidth() - 
			pChildRightArrow->getSize().getWidth(),0);

	}

	void HScrollBar::arrowMoveRight()
	{
		setValue(getValue() + getRightArrowAmount());
	}

	void HScrollBar::arrowMoveLeft()
	{
		setValue(getValue() - getLeftArrowAmount());
	}

	void HScrollBar::paintComponent( const PaintEvent &paintEvent )
	{
	}

	void HScrollBar::mouseDownCB( MouseEvent &mouseArgs )
	{
		if(mouseArgs.getSourceWidget() == pChildThumb)
		{
			downThumbPos = pChildThumb->getLocation().getX();
			downMousePos = mouseArgs.getX() + pChildThumb->getLocation().getX();
		}

		if (mouseArgs.getSourceWidget() == pChildLeftArrow)
		{
			arrowMoveLeft();
			lastArrowTick = -1;
			leftArrowDown = true;
		}

		if (mouseArgs.getSourceWidget() == pChildRightArrow)
		{
			arrowMoveRight();
			lastArrowTick = -1;
			rightArrowDown = true;
		}
		mouseArgs.consume();
	}

	void HScrollBar::mouseUpCB( MouseEvent &mouseArgs )
	{
		if (mouseArgs.getSourceWidget() == pChildLeftArrow)
		{
			leftArrowDown = false;
			mouseArgs.consume();

		}

		if (mouseArgs.getSourceWidget() == pChildRightArrow)
		{
			rightArrowDown = false;
			mouseArgs.consume();
		}
	}

	void HScrollBar::mouseDragCB( MouseEvent &mouseArgs )
	{
		if(mouseArgs.getSourceWidget() == pChildThumb)
		{
			int mouseChange = mouseArgs.getX() + pChildThumb->getLocation().getX() - downMousePos;
			int thumbChange = downThumbPos + mouseChange;
			setValue(getValueFromPosition(thumbChange));
			mouseArgs.consume();
		}
	}


	void HScrollBar::setSize( const Dimension &size )
	{
		Widget::setSize(size);


		resizeArrows();
		positionArrows();
		resizeThumb();
		positionThumb();
	}

	void HScrollBar::setSize( int width, int height )
	{
		Widget::setSize(width,height);
	}

	void HScrollBar::setLargeAmount( int amount )
	{
		int maxVal = getMaxValue() - getMinValue();
		if(amount >  maxVal)
		{
			amount = maxVal;
		}
		if(amount < 0)
		{
			amount = 0;
		}

		largeAmount = amount;
		for(std::vector<HScrollBarListener*>::iterator it = 
			hScrollListeners.begin();
			it != hScrollListeners.end(); ++it)
		{
			if((*it))
				(*it)->largeAmountChanged(this,amount);
		}

		resizeThumb();
		positionThumb();
	}

	void HScrollBar::setValue( int val )
	{
		//store current value to compare later
		int targetVal = val;

		//perform bounds checking
		if (val <= getMinValue())
		{
			targetVal = getMinValue();
		}
		else if(val >= getMaxValue() - getLargeAmount())
		{

			targetVal = getMaxValue() - getLargeAmount();
		}


		//only reposition if there is a change
		if(targetVal != currentValue)
		{
			currentValue = targetVal;
			positionThumb();

			for(std::vector<HScrollBarListener*>::iterator it = 
				hScrollListeners.begin();
				it != hScrollListeners.end(); ++it)
			{
				if((*it))
					(*it)->valueChanged(this,currentValue);
			}

			dispatchActionEvent(ActionEvent(this));
		}
	}

	void HScrollBar::setMinValue( int val )
	{
		if(val <= getMaxValue())
		{
			for(std::vector<HScrollBarListener*>::iterator it = 
				hScrollListeners.begin();
				it != hScrollListeners.end(); ++it)
			{
				if((*it))
					(*it)->minValueChanged(this,val);
			}

			minValue = val;

			if(getValue() < minValue)
			{
				setValue(minValue);
			}
			positionThumb();
			resizeThumb();
		}
	}

	void HScrollBar::setMaxValue( int val )
	{
		if(val >= getMinValue())
		{
			for(std::vector<HScrollBarListener*>::iterator it = 
				hScrollListeners.begin();
				it != hScrollListeners.end(); ++it)
			{
				if((*it))
					(*it)->maxValueChanged(this,val);
			}
			maxValue = val;

			if(getLargeAmount() >= maxValue)
			{
				setLargeAmount(maxValue);
			}


			if(getValue() >= maxValue - largeAmount)
			{
				setValue(maxValue - largeAmount);
			}

			positionThumb();
			resizeThumb();
		}
	}

	void HScrollBar::setLeftArrowAmount( int amount )
	{
		for(std::vector<HScrollBarListener*>::iterator it = 
			hScrollListeners.begin();
			it != hScrollListeners.end(); ++it)
		{
			if((*it))
				(*it)->leftAmountChanged(this,amount);
		}

		leftArrowAmount = amount;
	}

	void HScrollBar::setRightArrowAmount( int amount )
	{
		for(std::vector<HScrollBarListener*>::iterator it = 
			hScrollListeners.begin();
			it != hScrollListeners.end(); ++it)
		{
			if((*it))
				(*it)->rightAmountChanged(this,amount);
		}
		rightArrowAmount = amount;
	}

	int HScrollBar::getValueFromPosition( int position ) const
	{
		//subtract the left arrow's width
		position -= pChildLeftArrow->getSize().getWidth();

		//what percent of the thumb size we have traveled
		float retVal =  ((float)position / (float)getAdjustedMaxThumbSize());

		//total possible number of values
		int numValues = getMaxValue() - getMinValue();

		//how many values we have passed
		retVal = retVal * numValues;

		//add the minimum to get the value
		retVal += (float)getMinValue();

		//bounds checking
		if (retVal > getMaxValue() - getLargeAmount())
		{
			retVal = (float)(getMaxValue() - getLargeAmount());
		}
		if(retVal < getMinValue())
		{
			retVal = (float)getMinValue();
		}

		return (int)retVal;
	}

	float HScrollBar::getRelativeValue() const
	{
		float relVal = (float)(getValue() - getMinValue());
		float relMax =(float) (getMaxValue() - getMinValue());

		return relVal / relMax;
	}

	int HScrollBar::getLargeAmount() const
	{
		return largeAmount;
	}

	int HScrollBar::getValue() const
	{
		return currentValue;
	}

	int HScrollBar::getMinValue() const
	{
		return minValue;
	}

	int HScrollBar::getMaxValue() const
	{
		return maxValue;
	}

	int HScrollBar::getLeftArrowAmount() const
	{
		return leftArrowAmount;
	}

	int HScrollBar::getRightArrowAmount() const
	{
		return rightArrowAmount;
	}

	bool HScrollBar::isLeftArrowDown() const
	{
		return leftArrowDown;
	}

	bool HScrollBar::isRightArrowDown() const
	{
		return rightArrowDown;
	}

	int HScrollBar::getMaxThumbSize() const
	{
		return getSize().getWidth() -
			pChildLeftArrow->getSize().getWidth()
			- pChildRightArrow->getSize().getWidth();
	}



	void HScrollBar::setArrowWidth( int width )
	{
		if(width >= 0)
		{
			for(std::vector<HScrollBarListener*>::iterator it = 
				hScrollListeners.begin();
				it != hScrollListeners.end(); ++it)
			{
				if((*it))
					(*it)->arrowWidthChanged(this,width);
			}

			pChildLeftArrow->setSize(width,getHeight());
			pChildRightArrow->setSize(width,getHeight());
		}
	}

	int HScrollBar::getArrowWidth() const
	{
		return pChildLeftArrow->getSize().getWidth();
	}

	void HScrollBar::scrollRight()
	{
		setValue(getValue() + 1);
	}

	void HScrollBar::scrollLeft()
	{
		setValue(getValue() - 1);
	}

	bool HScrollBar::isThumbAtLeft() const
	{
		int tPos = pChildThumb->getLocation().getX()
			+ pChildThumb->getSize().getWidth();

		tPos -= pChildLeftArrow->getSize().getWidth();

		return tPos == 0;
	}

	bool HScrollBar::isThumbAtRight() const
	{
		int tPos = pChildThumb->getLocation().getX()
			+ pChildThumb->getSize().getWidth();

		tPos -= pChildRightArrow->getSize().getWidth();

		return tPos == getMaxThumbSize();
	}

	void HScrollBar::addHScrollBarListener( HScrollBarListener* listener )
	{
		if(!listener)
		{
			return;
		}
		for(std::vector<HScrollBarListener*>::iterator it = 
			hScrollListeners.begin();
			it != hScrollListeners.end(); ++it)
		{
			if((*it) == listener)
				return;
		}

		hScrollListeners.push_back(listener);
	}

	void HScrollBar::removeHScrollBarListener( HScrollBarListener* listener )
	{
		hScrollListeners.erase(
			std::remove(hScrollListeners.begin(),
			hScrollListeners.end(), listener),
			hScrollListeners.end());
	}


	void HScrollBar::setAutoscrollStartInterval( float interval )
	{
		if(interval > 0.0f)
		{
			autoScrollStartInterval = interval;
		}
		else
		{
			autoScrollStartInterval = 0.0f;
		}
	}

	float HScrollBar::getAutoscrollStartInterval() const
	{
		return autoScrollStartInterval;
	}

	int HScrollBar::getMinThumbWidth() const
	{
		return minThumbSize;
	}

	void HScrollBar::setMinThumbWidth( int size )
	{
		if(size >= 0)
		{
			for(std::vector<HScrollBarListener*>::iterator it = 
				hScrollListeners.begin();
				it != hScrollListeners.end(); ++it)
			{
				if((*it))
					(*it)->minThumbWidthChanged(this,size);
			}
			minThumbSize = size;
		}

	}

	int HScrollBar::getAdjustedMaxThumbSize() const
	{
		//the width if 1 pixel = 1 value
		int width = getLargeAmount();

		int maxValSupport = getMaxValue() - getMinValue();
		//get the ratio
		float change = (float)(getSize().getWidth() -
			pChildLeftArrow->getSize().getWidth()
			- pChildRightArrow->getSize().getWidth()) / (float)maxValSupport;

		//make height proportional to ratio
		width = (int)((float)width * change);

		int difference = width - pChildThumb->getSize().getWidth();


		return getSize().getWidth() -
			pChildLeftArrow->getSize().getWidth()
			- pChildRightArrow->getSize().getWidth() + difference;
	}


	void HScrollBar::mouseWheelDownCB( MouseEvent &mouseArgs )
	{

	}

	void HScrollBar::mouseWheelUpCB( MouseEvent &mouseArgs )
	{
	}

	void HScrollBar::mouseDown( MouseEvent &mouseArgs )
	{
		//when you click, it scrolls
		int mousePos = mouseArgs.getX();
		int newVal = getValue();
		if(mousePos > pChildThumb->getLocation().getX())
		{
			newVal += getLargeAmount();
		}
		else
		{
			newVal -= getLargeAmount();
		}
		setValue(newVal);
		mouseArgs.consume();
	}

	void HScrollBar::resizeArrows()
	{
		pChildLeftArrow->setSize(getArrowWidth(),getInnerSize().getHeight());
		pChildRightArrow->setSize(getArrowWidth(),getInnerSize().getHeight());
	}

	void HScrollBar::setRangeFromPage( int pageWidth, int contentWidth )
	{
		float percentage = (float)(pageWidth) / (float)(contentWidth);

		int y = (int)((contentWidth - pageWidth)
			/ (1.0f - percentage));
		int x = (int)((float)y * percentage);

		//should the thumb be brought to the bottom?
		bool isAtMax = getValue() > y - x;

		setMaxValue(y);
		setLargeAmount(x);

		y = getMaxValue();
		x = getLargeAmount();

		if(isAtMax)
		{
			setValue(getMaxValue() - getLargeAmount());
		}

		if(x <= 0 || y <= 0 || x >= y)
		{
			setMaxValue(1);
			setLargeAmount(1);

		}
	}

	void HScrollBar::paintBackground( const PaintEvent &paintEvent )
	{
		paintEvent.graphics()->drawFilledRectangle(getSizeRectangle(),
			getBackColor());

	}

	void HScrollBar::handleAutoscroll( double timeElapsed )
	{
		if(lastArrowTick == -1)
		{
			lastArrowTick = timeElapsed + autoScrollStartInterval;
		}
		else if(timeElapsed > lastArrowTick)
		{
			if(leftArrowDown)
			{
				scrollLeft();
			}

			if(rightArrowDown)
			{
				scrollRight();
			}
		}
	}

	void HScrollBar::logic( double timeElapsed )
	{
		handleAutoscroll(timeElapsed);
	}

}

