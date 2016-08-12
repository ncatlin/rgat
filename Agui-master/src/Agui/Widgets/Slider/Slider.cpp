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

#include "Agui/Widgets/Slider/Slider.hpp"
namespace agui {
	Slider::Slider( Widget *marker /*= NULL*/ )
    : orientation(HORIZONTAL),centerRatio(0.5f),
      value(0),min(0),max(30),change(1),
      isMaintainingMarker(false)
	{
		isMaintainingMarker = marker == NULL;

		if(isMaintainingMarker)
		{
			pChildMarker = new Button();
			((Button*)pChildMarker)->setMouseLeaveState(Button::CLICKED);
		}
		else
		{
			pChildMarker = marker;
		}

		setOrientation(HORIZONTAL);
		addPrivateChild(pChildMarker);
		pChildMarker->setFocusable(false);
		pChildMarker->setTabable(false);
		setFocusable(true);
		setTabable(true);
		pChildMarker->addMouseListener(this);
		pChildMarker->setSize(16,16);
		setSize(16,16);
		pChildMarker->setBackColor(Color(60,140,180));
        pChildMarker->setCausesLocationChange(true);
		setValue(getMinValue());

		setBackColor(Color(200,200,200));
        pChildMarker->setCausesLocationChange(true);
        setCausesLocationChange(true);
	}

	Slider::~Slider(void)
	{
		for(std::vector<SliderListener*>::iterator it = sliderListeners.begin();
			it != sliderListeners.end(); ++it)
		{
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

		if(isMaintainingMarker)
		{
			delete pChildMarker;
		}
	}

	int Slider::getRange() const
	{
		return getMaxValue() - getMinValue();
	}

	int Slider::getValue() const
	{
		return value;
	}

	void Slider::setValue( int val )
	{
		if(val < getMinValue())
		{
			val = getMinValue();
		}
		
		if(val > getMaxValue())
		{
			val = getMaxValue();
		}

		if(value != val)
		{
			for(std::vector<SliderListener*>::iterator it = sliderListeners.begin();
				it != sliderListeners.end(); ++it)
			{
				(*it)->valueChanged(this,val);
			}
		}
		value = val;

		positionMarker(getValue());
	}

	int Slider::getMinValue() const
	{
		return min;
	}

	int Slider::getMaxValue() const
	{
		return max;
	}

	void Slider::setMinValue( int val )
	{
		if(val > max)
		{
			val = max;
		}

		if(min != val)
		{
			
			for(std::vector<SliderListener*>::iterator it = sliderListeners.begin();
				it != sliderListeners.end(); ++it)
			{
				(*it)->minValueChanged(this,val);
			}
			
		}
		min = val;
	}

	void Slider::setMaxValue( int val )
	{
		if(val < min)
		{
			val = min;
		}

		if(val != max)
		{

			for(std::vector<SliderListener*>::iterator it = sliderListeners.begin();
				it != sliderListeners.end(); ++it)
			{
				(*it)->maxValueChanged(this,val);
			}
		}

		max = val;
	}

	void Slider::setOrientation( OrientationEnum orientation )
	{

		if(this->orientation != orientation)
		{
			pChildMarker->setSize(pChildMarker->getSize().getHeight(),
				pChildMarker->getSize().getWidth());

			setSize(getSize().getHeight(),getSize().getWidth());

			for(std::vector<SliderListener*>::iterator it = sliderListeners.begin();
				it != sliderListeners.end(); ++it)
			{
				(*it)->orientationChanged(this,orientation);
			}
		}
		this->orientation = orientation;
		setValue(getValue());
	}

	OrientationEnum Slider::getOrientation() const
	{
		return orientation;
	}

	int Slider::valueToPosition( int value ) const
	{
		
		float sz = getOrientation() == 
			HORIZONTAL ? (float)getInnerSize().getWidth() : (float)getInnerSize().getHeight();

		if(value > getMaxValue())
		{
			return _round(sz);
		}

		if(value < getMinValue())
		{
			return 0;
		}

		float val = (float)(value - getMinValue());
		float percent = val / (float)getRange();

		if(getOrientation() == HORIZONTAL)
		return _round(sz * percent);
		else
		return _round(sz - (sz * percent));
	}

	int Slider::positionToValue( int position ) const
	{
		position -= getOrientation() == HORIZONTAL ?
			pChildMarker->getWidth() / 2 : pChildMarker->getHeight() / 2;
		float sz = getOrientation() == 
			HORIZONTAL ? (float)getInnerSize().getWidth() - pChildMarker->getWidth()
			: (float)getInnerSize().getHeight() - pChildMarker->getHeight();

		if(getOrientation() == VERTICAL)
		{
			position = _round(sz - (float)position);
		}
		if(position > sz)
		{
			return getMaxValue();
		}

		if(position < 0)
		{
			return getMinValue();
		}

		float val = (float)position;
		float percent = val / sz;

		int result = _round((float)getRange() * percent);
		int otherPos = _round((sz / getRange()) * (result + 1));

		position -= otherPos;
		int curPos = _round((sz / getRange()) * result);
		curPos -= otherPos;
		result += getMinValue();
		
		return result;

	}

	void Slider::positionMarker( int value)
	{

			float sz = getOrientation() == 
				HORIZONTAL ? (float)getInnerSize().getWidth() -
				pChildMarker->getSize().getWidth() :
				(float)getInnerSize().getHeight()  - pChildMarker->getSize().getHeight();

			int pos = 0;
			if(value > getMaxValue())
			{
				pos = _round(sz);
			}
			else if(value < getMinValue())
			{
				pos = 0;
			}
			else
			{
				float val = (float)(value - getMinValue());
				float percent = val / (float)getRange();


				pos = _round(sz * percent);
			}

			if(getOrientation() == VERTICAL)
			{
				pos = _round(sz - pos);
			}

			if(getOrientation() == HORIZONTAL)
			{


				float center = (getInnerSize().getHeight() * getCenterRatio()) -
					(pChildMarker->getSize().getHeight() * getCenterRatio());
			
				pChildMarker->setLocation(pos,_round(center));
			}

			else
			{
				float center = (getInnerSize().getWidth() * getCenterRatio()) -
					(pChildMarker->getSize().getWidth()  * getCenterRatio());
			
				pChildMarker->setLocation(_round(center),pos);
			}


		
	}

	void Slider::paintComponent( const PaintEvent &paintEvent )
	{
		if(getOrientation() == HORIZONTAL)
		{
			paintEvent.graphics()->drawFilledRectangle(Rectangle(
				0,
				int(getInnerSize().getHeight() * 0.25),
				getInnerSize().getWidth(),
				int(getInnerSize().getHeight() * 0.5)),
				getBackColor());

			paintEvent.graphics()->drawRectangle(Rectangle(
				0,
				int(getInnerSize().getHeight() * 0.25),
				getInnerSize().getWidth(),
				int(getInnerSize().getHeight() * 0.5)),
				Color(0,0,0));
		}
		else
		{
			paintEvent.graphics()->drawFilledRectangle(Rectangle(
				int(getInnerSize().getWidth() * 0.25),
				0,
				int(getInnerSize().getWidth() * 0.5),
				getInnerSize().getHeight()),
				getBackColor());

			paintEvent.graphics()->drawRectangle(Rectangle(
				int(getInnerSize().getWidth() * 0.25),
				0,
				int(getInnerSize().getWidth() * 0.5),
				getInnerSize().getHeight()),
				Color(0,0,0));
		}
	}

	void Slider::setSize( int width, int height )
	{
		Widget::setSize(width,height);
	}

	void Slider::setSize( const Dimension &size )
	{
		Widget::setSize(size);
		setValue(getValue());
	}

	void Slider::mouseDragCB( MouseEvent &mouseEvent )
	{
		if(mouseEvent.getSourceWidget() != pChildMarker)
		{
			return;
		}

		if(mouseEvent.getButton() != MOUSE_BUTTON_LEFT)
		{
			return;
		}

		int mousePos = getOrientation() == HORIZONTAL ? 
		mouseEvent.getPosition().getX() + mouseEvent.getSourceWidget()->getLocation().getX() :
		mouseEvent.getPosition().getY() + mouseEvent.getSourceWidget()->getLocation().getY();

		int val = getValue();
		setValue(positionToValue(mousePos));
		if(val != getValue())
		{
			dispatchActionEvent(ActionEvent(
				this));
		}
		mouseEvent.consume();
	}

	void Slider::mouseDown( MouseEvent &mouseEvent )
	{
		if(mouseEvent.getButton() != MOUSE_BUTTON_LEFT)
		{
			return;
		}

		int mousePos = getOrientation() == HORIZONTAL ? 
			mouseEvent.getPosition().getX():
		mouseEvent.getPosition().getY();

		int val = getValue();
		setValue(positionToValue(mousePos));
		if(getValue() != val)
		{
			dispatchActionEvent(ActionEvent(
				this));
		}
		mouseEvent.consume();

	}


	void Slider::mouseDownCB( MouseEvent &mouseEvent )
	{
		if(mouseEvent.getSourceWidget() != pChildMarker)
		{
			return;
		}

		if(mouseEvent.getButton() != MOUSE_BUTTON_LEFT)
		{
			return;
		}

		focus();

		int mousePos = getOrientation() == HORIZONTAL ? 
			mouseEvent.getPosition().getX() + mouseEvent.getSourceWidget()->getLocation().getX() :
		mouseEvent.getPosition().getY() + mouseEvent.getSourceWidget()->getLocation().getY();

		int val = getValue();
		setValue(positionToValue(mousePos));
		if(val != getValue())
		{
			dispatchActionEvent(ActionEvent(
				this));
		}

		mouseEvent.consume();
		mouseEvent.consume();
	}

	void Slider::keyDown( KeyEvent &keyEvent )
	{
		int val = getValue();
		handleKeyboard(keyEvent);
		if(val != getValue())
		{
			dispatchActionEvent(ActionEvent(
				this));
		}
	}

	void Slider::setStepLength( int length )
	{
		if(change != length)
		{
			for(std::vector<SliderListener*>::iterator it = sliderListeners.begin();
				it != sliderListeners.end(); ++it)
			{
				(*it)->stepLengthChanged(this,length);
			}
		}
		change = length;
	}

	int Slider::getStepLength() const
	{
		return change;
	}

	void Slider::handleKeyboard( KeyEvent &keyEvent )
	{
		if(getOrientation() == HORIZONTAL)
		{
			if(keyEvent.getExtendedKey() == EXT_KEY_LEFT)
			{
				setValue(getValue() - getStepLength());
			}

			else if(keyEvent.getExtendedKey() == EXT_KEY_RIGHT)
			{
				setValue(getValue() + getStepLength());
			}
		}
		else
		{
			if(keyEvent.getExtendedKey() == EXT_KEY_UP)
			{
				setValue(getValue() + getStepLength());
			}

			else if(keyEvent.getExtendedKey() == EXT_KEY_DOWN)
			{
				setValue(getValue() - getStepLength());
			}
		}
	}

	void Slider::keyRepeat( KeyEvent &keyEvent )
	{
		int val = getValue();
		handleKeyboard(keyEvent);

		if(val != getValue())
		{
			dispatchActionEvent(ActionEvent(
				this));
		}

	}

	void Slider::mouseWheelDown( MouseEvent &mouseEvent )
	{
		int val = getValue();
		setValue(getValue() - getStepLength());
		if(val != getValue())
		{
			dispatchActionEvent(ActionEvent(
				this));
		}
		mouseEvent.consume();
	}

	void Slider::mouseWheelDownCB( MouseEvent &mouseEvent )
	{

		if(mouseEvent.getSourceWidget() == pChildMarker)
		{
			int val = getValue();
			setValue(getValue() - getStepLength());

			if(val != getValue())
			{
				dispatchActionEvent(ActionEvent(
					this));
			}

			mouseEvent.consume();
		}
	}

	void Slider::mouseWheelUp( MouseEvent &mouseEvent )
	{

		mouseEvent.consume();
		int val = getValue();
		setValue(getValue() + getStepLength());
		if(val != getValue())
		{
			dispatchActionEvent(ActionEvent(
				this));
		}
	}

	void Slider::mouseWheelUpCB( MouseEvent &mouseEvent )
	{

		if(mouseEvent.getSourceWidget() == pChildMarker)
		{
			int val = getValue();
			setValue(getValue() + getStepLength());

			if(val != getValue())
			{
				dispatchActionEvent(ActionEvent(
					this));
			}

			mouseEvent.consume();
		}
	}

	void Slider::addSliderListener( SliderListener *listener )
	{
		if(!listener)
		{
			return;
		}
		for(std::vector<SliderListener*>::iterator it = 
			sliderListeners.begin();
			it != sliderListeners.end(); ++it)
		{
			if((*it) == listener)
				return;
		}

		sliderListeners.push_back(listener);
	}

	void Slider::removeSliderListener( SliderListener *listener )
	{
		sliderListeners.erase(
			std::remove(sliderListeners.begin(),
			sliderListeners.end(), listener),
			sliderListeners.end());
	}

	const Dimension& Slider::getMarkerSize() const
	{
		return pChildMarker->getSize();
	}

	void Slider::setMarkerSize( const Dimension &size )
	{
		pChildMarker->setSize(size);
		setValue(getValue());
	}

	void Slider::paintBackground( const PaintEvent &paintEvent )
	{
	}

	float Slider::getPercentage() const
	{
		if(getRange() == 0)
		{
			return 1.0f;
		}

		float val = (float)(value - getMinValue());
		float percent = val / (float)getRange();

		return percent;
	}

	void Slider::setCenterRatio( float ratio )
	{
		if(ratio < 0.0f)
		{
			ratio = 0.0f;
		}
		if(ratio > 1.0f)
		{
			ratio = 1.0f;
		}

		centerRatio = ratio;
		positionMarker(getValue());

	}

	float Slider::getCenterRatio() const
	{
		return centerRatio;
	}

}
