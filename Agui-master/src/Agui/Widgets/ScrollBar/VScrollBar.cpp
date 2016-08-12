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

#include "Agui/Widgets/ScrollBar/VScrollBar.hpp"
namespace agui {
	VScrollBar::VScrollBar( Widget *thumb /*= NULL*/, 
								   Widget *topArrow /*= NULL*/,
								   Widget *bottomArrow /*= NULL*/ )
    : largeAmount(10), lastArrowTick(0.0), minValue(0), maxValue(100),
      wheelSpeed(1),currentValue(0), downThumbPos(0), downMousePos(0),
      topArrowDown(false), bottomArrowDown(false),
      autoScrollStartInterval(0.35f),
      minThumbSize(10),stickToBottom(false)
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

		if(topArrow)
		{
			isMaintainingTopArrow = false;
			pChildTopArrow = topArrow;
		}
		else
		{
			isMaintainingTopArrow = true;
			pChildTopArrow = new Button();
			((Button*)pChildTopArrow)->setMouseLeaveState(Button::CLICKED);
		}

		if(bottomArrow)
		{
			isMaintainingBottomArrow = false;
			pChildBottomArrow = bottomArrow;
		}
		else
		{
			isMaintainingBottomArrow = true;
			pChildBottomArrow = new Button();
			((Button*)pChildBottomArrow)->setMouseLeaveState(Button::CLICKED);
		}


		pChildThumb->setFocusable(false);
		pChildTopArrow->setFocusable(false);
		pChildBottomArrow->setFocusable(false);

		pChildThumb->addMouseListener(this);
		pChildTopArrow->addMouseListener(this);
		pChildBottomArrow->addMouseListener(this);

		pChildBottomArrow->setBackColor(Color(80,160,200));
		pChildTopArrow->setBackColor(Color(80,160,200));
		pChildThumb->setBackColor(Color(60,140,180));
        
        pChildBottomArrow->setCausesLocationChange(true);
        pChildThumb->setCausesLocationChange(true);
        pChildTopArrow->setCausesLocationChange(true);

		addPrivateChild(pChildThumb);
		addPrivateChild(pChildTopArrow);
		addPrivateChild(pChildBottomArrow);
        
        setCausesLocationChange(true);

		setTopArrowAmount(5);
		setBottomArrowAmount(5);
		setArrowHeight(16);
		setSize(16,400);
		setMargins(0,0,0,0);
		setBackColor(Color(200,200,201));
	}

	VScrollBar::~VScrollBar(void)
	{		
		for(std::vector<VScrollBarListener*>::iterator it = 
			vScrollListeners.begin();
			it != vScrollListeners.end(); ++it)
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
		if(isMaintainingTopArrow)
		delete pChildTopArrow;
		if(isMaintainingBottomArrow)
		delete pChildBottomArrow;
	}


	void VScrollBar::setArrowHeight( int height )
	{
		if(height >= 0)
		{
			for(std::vector<VScrollBarListener*>::iterator it = 
				vScrollListeners.begin();
				it != vScrollListeners.end(); ++it)
			{
				if((*it))
					(*it)->arrowHeightChanged(this,height);
			}

			pChildTopArrow->setSize(getInnerSize().getWidth(),height);
			pChildBottomArrow->setSize(getInnerSize().getWidth(),height);
		}
		
	}

	void VScrollBar::positionArrows()
	{
		pChildTopArrow->setLocation(0,0);
		pChildBottomArrow->setLocation(0,getInnerSize().getHeight()
			- pChildBottomArrow->getSize().getHeight());
	}

	int VScrollBar::getMaxThumbSize() const
	{ 

		return getInnerSize().getHeight() -
			pChildTopArrow->getSize().getHeight()
			- pChildBottomArrow->getSize().getHeight();
	}


	int VScrollBar::getLargeAmount() const
	{
		return largeAmount;
	}

	int VScrollBar::getValue() const
	{
		return currentValue;
	}

	int VScrollBar::getMinValue() const
	{
		return minValue;
	}

	int VScrollBar::getMaxValue() const
	{
		return maxValue;
	}

	int VScrollBar::getArrowHeight() const
	{
		return pChildTopArrow->getSize().getHeight();
	}

	void VScrollBar::positionThumb()
	{
		float val = getAdjustedMaxThumbSize() * getRelativeValue();
		val += pChildTopArrow->getSize().getHeight();


		if(getValue() == getMaxValue() - getLargeAmount())
		{
			val = (float)(pChildBottomArrow->getLocation().getY() -
				pChildThumb->getSize().getHeight());
		}

		if(val + pChildThumb->getSize().getHeight() >
			pChildBottomArrow->getLocation().getY())
		{
			val = (float)(pChildBottomArrow->getLocation().getY() - 
				pChildThumb->getSize().getHeight());
		}
		pChildThumb->setLocation(0,(int)val);
	}

	void VScrollBar::resizeThumb()
	{
		//the height if 1 pixel = 1 value
		int height = getLargeAmount();

		int maxValSupport = getMaxValue() - getMinValue();
		//get the ratio
		float change = (float)getMaxThumbSize() / (float)maxValSupport;

		//make height proportional to ratio
		height = (int)((float)height * change);

		//make sure the thumb never gets too small
		if(height < getMinThumbHeight())
		{
			height = getMinThumbHeight();
		}

		if(height > getMaxThumbSize())
		{
			
			pChildThumb->setVisibility(false);
		}
		else if(pChildThumb->isVisible() == false)
		{
			pChildThumb->setVisibility(true);
		}

		pChildThumb->setSize(getInnerSize().getWidth(),height);
	}

	void VScrollBar::setLargeAmount( int amount)
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
		for(std::vector<VScrollBarListener*>::iterator it = 
			vScrollListeners.begin();
			it != vScrollListeners.end(); ++it)
		{
			if((*it))
				(*it)->largeAmountChanged(this,amount);
		}

		resizeThumb();
		positionThumb();
	}

	void VScrollBar::setValue( int val )
	{
		//store current value to compare later
		int targetVal = val;

		//perform bounds checking
		if (val <= getMinValue())
		{
			targetVal = getMinValue();
		}
		else if(val >= getMaxValue() - largeAmount)
		{

			targetVal = getMaxValue() - largeAmount;
		}

		
		
		//only reposition if there is a change
		if(targetVal != currentValue)
		{
			currentValue = targetVal;
			positionThumb();
			for(std::vector<VScrollBarListener*>::iterator it = 
				vScrollListeners.begin();
				it != vScrollListeners.end(); ++it)
			{
				if((*it))
					(*it)->valueChanged(this,currentValue);
			}

			dispatchActionEvent(ActionEvent(this));
		}

	}

	void VScrollBar::paintComponent( const PaintEvent &paintEvent )
	{
	}

	void VScrollBar::setMinValue( int val )
	{
		if(val <= getMaxValue())
		{
			for(std::vector<VScrollBarListener*>::iterator it = 
				vScrollListeners.begin();
				it != vScrollListeners.end(); ++it)
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

	void VScrollBar::setMaxValue( int val )
	{
		if(val >= getMinValue())
		{
			for(std::vector<VScrollBarListener*>::iterator it = 
				vScrollListeners.begin();
				it != vScrollListeners.end(); ++it)
			{
				if((*it))
					(*it)->maxValueChanged(this,val);
			}
			maxValue = val;

			if(getLargeAmount() >= maxValue)
			{
				setLargeAmount(maxValue);
			}

			if(getValue() >= maxValue - largeAmount && maxValue - largeAmount > 1)
			{
				setValue(maxValue - largeAmount);
			}

			positionThumb();
			resizeThumb();

		}
	}

	void VScrollBar::setTopArrowAmount( int amount )
	{
		for(std::vector<VScrollBarListener*>::iterator it = 
			vScrollListeners.begin();
			it != vScrollListeners.end(); ++it)
		{
			if((*it))
				(*it)->topAmountChanged(this,amount);
		}

		topArrowAmount = amount;
	}

	void VScrollBar::setBottomArrowAmount( int amount )
	{
		for(std::vector<VScrollBarListener*>::iterator it = 
			vScrollListeners.begin();
			it != vScrollListeners.end(); ++it)
		{
			if((*it))
				(*it)->bottomAmountChanged(this,amount);
		}
		bottomArrowAmount = amount;
	}

	float VScrollBar::getRelativeValue() const
	{
		float relVal = (float)(getValue() - getMinValue());
		float relMax =(float) (getMaxValue() - getMinValue());

		return relVal / relMax;
	}

	int VScrollBar::getValueFromPosition( int position ) const
	{
		//subtract the top arrow's height
		position -= pChildTopArrow->getSize().getHeight();

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

	void VScrollBar::mouseDownCB( MouseEvent &mouseEvent )
	{
		if(mouseEvent.getSourceWidget() == pChildThumb)
		{
			downThumbPos = pChildThumb->getLocation().getY();
			downMousePos = mouseEvent.getY() + pChildThumb->getLocation().getY();
		}

		if (mouseEvent.getSourceWidget() == pChildTopArrow)
		{
			arrowMoveUp();
			lastArrowTick = -1.0;
			topArrowDown = true;
		}

		if (mouseEvent.getSourceWidget() == pChildBottomArrow)
		{
			arrowMoveDown();
			lastArrowTick = -1.0;
			bottomArrowDown = true;
		}
		mouseEvent.consume();

	}

	void VScrollBar::mouseDragCB( MouseEvent &mouseEvent )
	{

		if(mouseEvent.getSourceWidget() == pChildThumb)
		{
			int mouseChange = mouseEvent.getY() +
				pChildThumb->getLocation().getY() - downMousePos;
			int thumbChange = downThumbPos + mouseChange;
			setValue(getValueFromPosition(thumbChange));
			mouseEvent.consume();
		}
	}

	bool VScrollBar::isTopArrowDown() const
	{
		return topArrowDown;
	}

	bool VScrollBar::isBottomArrowDown() const
	{
		return bottomArrowDown;
	}

	void VScrollBar::mouseUpCB( MouseEvent &mouseEvent )
	{

		if (mouseEvent.getSourceWidget() == pChildTopArrow)
		{
			topArrowDown = false;
			mouseEvent.consume();
		}

		if (mouseEvent.getSourceWidget() == pChildBottomArrow)
		{
			bottomArrowDown = false;
			mouseEvent.consume();
		}
	}

	int VScrollBar::getTopArrowAmount() const
	{
		return topArrowAmount;
	}

	int VScrollBar::getBottomArrowAmount() const
	{
		return topArrowAmount;
	}

	bool VScrollBar::isThumbAtBottom() const
	{
		int tPos = pChildThumb->getLocation().getY()
			+ pChildThumb->getSize().getHeight();

		tPos -= pChildTopArrow->getSize().getHeight();

		return tPos == getMaxThumbSize();
	}

	bool VScrollBar::isThumbAtTop() const
	{
		int tPos = pChildThumb->getLocation().getY()
			+ pChildThumb->getSize().getHeight();

		tPos -= pChildTopArrow->getSize().getHeight();

		return tPos == 0;
	}

	void VScrollBar::scrollDown()
	{
		setValue(getValue() + 1);
	}

	void VScrollBar::scrollUp()
	{
		setValue(getValue() - 1);
	}


	float VScrollBar::getAutoscrollStartInterval() const
	{
		return autoScrollStartInterval;
	}

	void VScrollBar::setAutoscrollStartInterval( float interval )
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

	int VScrollBar::getMinThumbHeight() const
	{
		return minThumbSize;
	}

	void VScrollBar::setMinThumbHeight( int size )
	{
		if(size >= 0)
		{
			for(std::vector<VScrollBarListener*>::iterator it = 
				vScrollListeners.begin();
				it != vScrollListeners.end(); ++it)
			{
				if((*it))
					(*it)->minThumbHeightChanged(this,size);
			}
			minThumbSize = size;
		}
		
	}

	void VScrollBar::setSize( const Dimension &size )
	{
		Widget::setSize(size);

		resizeArrows();
		positionArrows();
		resizeThumb();
		positionThumb();

	}

	void VScrollBar::setSize( int width, int height )
	{
		Widget::setSize(width,height);
	}


	void VScrollBar::arrowMoveDown()
	{
		setValue(getValue() + getBottomArrowAmount());

	}

	void VScrollBar::arrowMoveUp()
	{
		setValue(getValue() - getTopArrowAmount());
	}


	void VScrollBar::addVScrollBarListener( VScrollBarListener* listener )
	{
		if(!listener)
		{
			return;
		}
		for(std::vector<VScrollBarListener*>::iterator it = 
			vScrollListeners.begin();
			it != vScrollListeners.end(); ++it)
		{
			if((*it) == listener)
				return;
		}

		vScrollListeners.push_back(listener);
	}

	void VScrollBar::removeVScrollBarListener( VScrollBarListener* listener )
	{
		vScrollListeners.erase(
			std::remove(vScrollListeners.begin(),
			vScrollListeners.end(), listener),
			vScrollListeners.end());
	}

	int VScrollBar::getAdjustedMaxThumbSize() const
	{
		//the height if 1 pixel = 1 value
		int height = getLargeAmount();

		int maxValSupport = getMaxValue() - getMinValue();
		//get the ratio
		float change = (float)(getSize().getHeight() -
			pChildTopArrow->getSize().getHeight()
			- pChildBottomArrow->getSize().getHeight()) / (float)maxValSupport;

		//make height proportional to ratio
		height = (int)((float)height * change);

		int difference = height - pChildThumb->getSize().getHeight();
		

		return getSize().getHeight() -
			pChildTopArrow->getSize().getHeight()
			- pChildBottomArrow->getSize().getHeight() + difference;

	}

	
	void VScrollBar::mouseWheelDownCB( MouseEvent &mouseEvent )
	{

		if(mouseEvent.getSourceWidget() == pChildBottomArrow ||
			mouseEvent.getSourceWidget() == pChildThumb ||
			mouseEvent.getSourceWidget() == pChildTopArrow)
		{
			wheelScrollDown(mouseEvent.getMouseWheelChange());
		}
	}

	void VScrollBar::mouseWheelUpCB( MouseEvent &mouseEvent )
	{
		if(mouseEvent.getSourceWidget() == pChildBottomArrow ||
			mouseEvent.getSourceWidget() == pChildThumb ||
			mouseEvent.getSourceWidget() == pChildTopArrow)
		{
			wheelScrollUp(mouseEvent.getMouseWheelChange());
		}
	}

	void VScrollBar::mouseDown( MouseEvent &mouseEvent )
	{
		//when you click, it scrolls
		int mousePos = mouseEvent.getY();
		int newVal = getValue();
		if(mousePos > pChildThumb->getLocation().getY())
		{
			newVal += getLargeAmount();
		}
		else
		{
			newVal -= getLargeAmount();
		}
		setValue(newVal);
		mouseEvent.consume();
	}

	void VScrollBar::resizeArrows()
	{
		pChildTopArrow->setSize(getInnerSize().getWidth(),getArrowHeight());
		pChildBottomArrow->setSize(getInnerSize().getWidth(),getArrowHeight());

	}

	void VScrollBar::setRangeFromPage( int pageHeight, int contentHeight )
	{

		float percentage = (float)(pageHeight) / (float)(contentHeight);

		int y = (int)((contentHeight - pageHeight)
			 / (1.0f - percentage));
		int x = (int)((float)y * percentage);

		//should the thumb be brought to the bottom?
		bool isAtMax = getValue() > y - x;
		bool atBottom = getValue() == getMaxValue() - getLargeAmount();

		setMaxValue(y);
		setLargeAmount(x);

		y = getMaxValue();
		x = getLargeAmount();

		if(isAtMax || (atBottom && isStickingToBottom()))
		{
			setValue(getMaxValue() - getLargeAmount());
		}

		if(x <= 0 || y <= 0 || x >= y)
		{
			setMaxValue(1);
			setLargeAmount(1);

		}

	}

	bool VScrollBar::isStickingToBottom() const
	{
		return stickToBottom;
	}

	void VScrollBar::setStickToBottom()
	{
		stickToBottom = true;
	}

	void VScrollBar::paintBackground( const PaintEvent &paintEvent )
	{
		paintEvent.graphics()->drawFilledRectangle(getSizeRectangle(),
			getBackColor());
	}

	void VScrollBar::setMouseWheelAmount( int amount )
	{
		wheelSpeed = amount;
	}

	void VScrollBar::wheelScrollDown( int deltaWheel )
	{
		setValue(getValue() + getMouseWheelAmount() - deltaWheel);
	}

	void VScrollBar::wheelScrollUp( int deltaWheel )
	{
		setValue(getValue() - getMouseWheelAmount() - deltaWheel);
	}

	int VScrollBar::getMouseWheelAmount() const
	{
		return wheelSpeed;
	}

	void VScrollBar::mouseWheelDown( MouseEvent &mouseEvent )
	{
		wheelScrollDown(mouseEvent.getMouseWheelChange());
		mouseEvent.consume();
	}

	void VScrollBar::mouseWheelUp( MouseEvent &mouseEvent )
	{
		wheelScrollUp(mouseEvent.getMouseWheelChange());
		mouseEvent.consume();
	}

	void VScrollBar::logic( double timeElapsed )
	{
		handleAutoscroll(timeElapsed);
	
	}

	void VScrollBar::handleAutoscroll( double timeElapsed )
	{
		if(lastArrowTick == -1)
		{
			lastArrowTick = timeElapsed + autoScrollStartInterval;
		}
		else if(timeElapsed > lastArrowTick)
		{
			if(topArrowDown)
			{
				scrollUp();
			}

			if(bottomArrowDown)
			{
				scrollDown();
			}
		}
	}

}
