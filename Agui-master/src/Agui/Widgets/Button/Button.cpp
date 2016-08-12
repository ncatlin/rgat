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

#include "Agui/Widgets/Button/Button.hpp"
#include "Agui/Widgets/Button/ButtonListener.hpp"

namespace agui {
	Button::Button()
    : buttonState(DEFAULT), mouseIsInside(false),mouseIsDown(false),
      isDoingKeyAction(false), isButtonToggleButton(false),toggled(false),
      autoUntoggle(true), mouseLeaveState(HOVERED)
	{
		setFocusable(true);
		setTabable(true);

		setTextAlignment(ALIGN_MIDDLE_CENTER);

		setBackColor(Color(115,183,226));
		setMargins(1,1,2,2);

	}


	Button::~Button(void)
	{
		for(std::vector<ButtonListener*>::iterator it = 
			buttonListeners.begin();
			it != buttonListeners.end(); ++it)
		{
			if((*it))
				(*it)->death(this);
		}
	}


	void Button::setTextAlignment( AreaAlignmentEnum alignment )
	{
		for(std::vector<ButtonListener*>::iterator it = 
			buttonListeners.begin();
			it != buttonListeners.end(); ++it)
		{
			if((*it))
				(*it)->textAlignmentChanged(this,alignment);
		}
		this->textAlignment = alignment;
	}

	AreaAlignmentEnum Button::getTextAlignment() const
	{
		return textAlignment;
	}



	void Button::changeButtonState( ButtonStateEnum state )
	{
		for(std::vector<ButtonListener*>::iterator it = 
			buttonListeners.begin();
			it != buttonListeners.end(); ++it)
		{
			if((*it))
				(*it)->buttonStateChanged(this,state);
		}
		buttonState = state;
	}

	Button::ButtonStateEnum Button::getButtonState() const
	{
		return buttonState;
	}

	void Button::paintComponent( const PaintEvent &paintEvent )
	{

		resizableText.drawTextArea(paintEvent.graphics(),getFont(),
			getInnerRectangle(),getFontColor(),wrappedText,getTextAlignment());
	}

	void Button::modifyButtonState()
	{
		if(isDoingKeyAction)
		{
			return;
		}
		if(isToggleButton() && toggled)
		{
			
			if(getButtonState() != CLICKED)
			{
				changeButtonState(CLICKED);
			}
			return;
		}
		if(mouseIsDown && mouseIsInside)
		{
			changeButtonState(CLICKED);
		}
		else if(mouseIsDown && !mouseIsInside)
		{
			changeButtonState(getMouseLeaveState());
		}
		else if(!mouseIsDown && mouseIsInside)
		{
			changeButtonState(HOVERED);
		}
		else
		{
			changeButtonState(DEFAULT);
		}
	}



	bool Button::isToggleButton() const
	{
		return isButtonToggleButton;
	}

	bool Button::isToggled() const
	{
		return isToggleButton() && toggled; 
	}

	void Button::setToggleButton( bool toggleButton )
	{
		isButtonToggleButton = toggleButton;
		for(std::vector<ButtonListener*>::iterator it = 
			buttonListeners.begin();
			it != buttonListeners.end(); ++it)
		{
			if((*it))
				(*it)->isToggleButtonChanged(this,toggleButton);
		}
		if(!toggleButton)
		{
			modifyIsToggled(false);
			modifyButtonState();
		}
	}


	void Button::handleToggleClick()
	{

		if(toggled && !isAutoUntoggling())
		{
			return;
		}

		modifyIsToggled(!toggled);
		modifyButtonState();
	}


	void Button::removeButtonListener(
		ButtonListener* listener )
	{
		buttonListeners.erase(
			std::remove(buttonListeners.begin(),
			buttonListeners.end(), listener),
			buttonListeners.end());
	}

	void Button::addButtonListener( 
		ButtonListener* listener )
	{
		if(!listener)
		{
			return;
		}
		for(std::vector<ButtonListener*>::iterator it = 
			buttonListeners.begin();
			it != buttonListeners.end(); ++it)
		{
			if((*it) == listener)
				return;
		}

		buttonListeners.push_back(listener);
	}


	void Button::modifyIsToggled( bool toggled )
	{
		if( toggled == this->toggled)
		{
			return;
		}
		this->toggled = toggled;

		for(std::vector<ButtonListener*>::iterator it = 
			buttonListeners.begin();
			it != buttonListeners.end(); ++it)
		{
			if((*it))
				(*it)->toggleStateChanged(this,toggled);
		}
	}


	void Button::setText( const std::string &text )
	{
		Widget::setText(text);
		resizableText.makeTextLines(getFont(),getText(),wrappedText,getInnerWidth());
	}

	void Button::setSize( const Dimension &size )
	{
		Widget::setSize(size);
		resizableText.makeTextLines(getFont(),getText(),wrappedText,getInnerWidth());

	}

	void Button::setSize( int width, int height )
	{
		Widget::setSize(width,height);
	}

	void Button::setFont( const Font *font )
	{
		Widget::setFont(font);
		resizableText.makeTextLines(getFont(),getText(),wrappedText,getInnerWidth());
	}

	void Button::focusGained()
	{
		Widget::focusGained();
		isDoingKeyAction = false;
		modifyButtonState();
	}

	void Button::focusLost()
	{
		Widget::focusLost();
		isDoingKeyAction = false;
		modifyButtonState();
	}

	void Button::mouseEnter( MouseEvent &mouseEvent )
	{
		mouseIsInside = true;
		modifyButtonState();
		mouseEvent.consume();
	}

	void Button::mouseLeave( MouseEvent &mouseEvent )
	{

		mouseIsInside = false;
		modifyButtonState();
		mouseEvent.consume();
	}

	void Button::mouseDown( MouseEvent &mouseEvent )
	{
		if(mouseEvent.getButton() == MOUSE_BUTTON_LEFT)
		{
			mouseIsDown = true;
			mouseEvent.consume();
		}

		modifyButtonState();
	}

	void Button::mouseUp( MouseEvent &mouseEvent )
	{

		if(mouseEvent.getButton() == MOUSE_BUTTON_LEFT)
		{
			mouseIsDown = false;
			mouseEvent.consume();
		}

		modifyButtonState();
	}

	void Button::mouseClick( MouseEvent &mouseEvent )
	{
		if(isToggleButton() && mouseEvent.getButton() == MOUSE_BUTTON_LEFT)
		{
			handleToggleClick();
			mouseEvent.consume();
		}

		if(mouseEvent.getButton() == MOUSE_BUTTON_LEFT)
		dispatchActionEvent(ActionEvent(this));
	}

	void Button::keyUp( KeyEvent &keyEvent )
	{
		if(!isDoingKeyAction)
		{
			return;
		}
		isDoingKeyAction = false;
		if(keyEvent.getKey() == KEY_SPACE || keyEvent.getKey() == KEY_ENTER)
		{
			dispatchActionEvent(ActionEvent(
				this));
			handleToggleClick();
			modifyButtonState();

			keyEvent.consume();
		}
	}

	void Button::keyDown( KeyEvent &keyEvent )
	{
		
		if(keyEvent.getKey() == KEY_SPACE || keyEvent.getKey() == KEY_ENTER)
		{
			isDoingKeyAction = true;
			changeButtonState(CLICKED);
			keyEvent.consume();
		}
	}

	void Button::setMouseLeaveState(Button::ButtonStateEnum state)
	{
		mouseLeaveState = state;
	}

	Button::ButtonStateEnum Button::getMouseLeaveState() const
	{
		return mouseLeaveState;
	}

	void Button::paintBackground( const PaintEvent &paintEvent )
	{
		Color color = getBackColor();

		switch (getButtonState())
		{
		case HOVERED:
			color = Color((float)(color.getR() + 0.075f), 
				(float)(color.getG() + 0.075f),
				(float)(color.getB() + 0.075f), 
				(float)(color.getA() ));
			break;
		case CLICKED:
			color = Color((float)(color.getR() - 0.075f), 
				(float)(color.getG() - 0.075f),
				(float)(color.getB() - 0.075f), (float)(color.getA() ));
			break;
		default:
			break;
		}

		paintEvent.graphics()->drawFilledRectangle(getSizeRectangle(),color);

		Color shadow = Color(
			color.getR() - 0.2f,
			color.getG() - 0.2f,
			color.getB() - 0.2f);

		Color highlight = Color(
			color.getR() + 0.2f,
			color.getG() + 0.2f,
			color.getB() + 0.2f);

		//top
		paintEvent.graphics()->drawLine(Point(0,1),
			Point(getSize().getWidth(),1),highlight);
		//left
		paintEvent.graphics()->drawLine(Point(1,1),
			Point(1,getSize().getHeight()),highlight);

		//bottom
		paintEvent.graphics()->drawLine(Point(0,getSize().getHeight() ),
			Point(getSize().getWidth(),getSize().getHeight() ),shadow);

		//right
		paintEvent.graphics()->drawLine(Point(getSize().getWidth() ,1),
			Point(getSize().getWidth() ,getSize().getHeight()),shadow);

		//bottom
		paintEvent.graphics()->drawLine(Point(0,getSize().getHeight() - 1 ),
			Point(getSize().getWidth(),getSize().getHeight() - 1 ),shadow);

		//right
		paintEvent.graphics()->drawLine(Point(getSize().getWidth()  - 1,0),
			Point(getSize().getWidth() - 1 ,getSize().getHeight()),shadow);

	}

	const std::vector<std::string>& Button::getAreaText() const
	{
		return wrappedText;
	}

	void Button::setToggleState(bool toggled)
	{
		if(isToggleButton())
		{
			modifyIsToggled(toggled);
			modifyButtonState();
		}
	}

	void Button::resizeToContents()
	{
		int w = getFont()->getTextWidth(getText()) +
			getMargin(SIDE_LEFT) + getMargin(SIDE_RIGHT);
		int h = getFont()->getLineHeight() +
			getMargin(SIDE_TOP) + getMargin(SIDE_BOTTOM);

		setSize(w,h);
		
	}

	void Button::setButtonState( ButtonStateEnum state )
	{
		changeButtonState(state);
	}

	void Button::setAutoUntoggle( bool untoggle )
	{
		autoUntoggle = untoggle;
	}

	bool Button::isAutoUntoggling() const
	{
		return autoUntoggle;
	}

	bool Button::isMouseInside() const
	{
		return mouseIsInside;
	}

}



