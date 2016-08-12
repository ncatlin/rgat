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

#include "Agui/Widgets/RadioButton/RadioButton.hpp"
#include "Agui/Widgets/RadioButton/RadioButtonListener.hpp"
namespace agui {
	RadioButton::RadioButton()
    :	sidePadding(6), radioButtonState(DEFAULT),
        mouseIsInside(false), mouseIsDown(false), isDoingKeyAction(false)
	{

		setMargins(1,1,1,1);
		setBackColor(Color(240,240,240));
		setFocusable(true);
		setTabable(true);
		setRadioButtonAlignment(ALIGN_TOP_LEFT);
		setTextAlignment(ALIGN_MIDDLE_LEFT);

		positionRadioButton();
		resizeCaption();
		setChecked(false);
		setAutosizing(false);
		setRadioButtonRadius(6);
	}

	RadioButton::~RadioButton(void)
	{
		for(std::vector<RadioButtonListener*>::iterator it = 
			radioButtonListeners.begin();
			it != radioButtonListeners.end(); ++it)
		{
			if((*it))
				(*it)->death(this);
		}
	}

	void RadioButton::setRadioButtonRadius( int size )
	{
		if(size < 0)
		{
			size = 0;
		}
		radioButtonRadius = size;
		positionRadioButton();
		if(isAutosizing())
		{
			resizeToContents();
		}
	}





	void RadioButton::changeRadioButtonState( RadioButtonStateEnum state )
	{
		radioButtonState = state;

		for(std::vector<RadioButtonListener*>::iterator it = 
			radioButtonListeners.begin();
			it != radioButtonListeners.end(); ++it)
		{
			if((*it))
				(*it)->radioButtonStateChanged(this,state);
		}
	}

	void RadioButton::modifyRadioButtonState()
	{
		if(isDoingKeyAction)
		{
			return;
		}
		if(mouseIsDown && mouseIsInside)
		{
			changeRadioButtonState(CLICKED);
		}
		else if(mouseIsDown && !mouseIsInside)
		{
			changeRadioButtonState(HOVERED);
		}
		else if(!mouseIsDown && mouseIsInside)
		{
			changeRadioButtonState(HOVERED);
		}
		else
		{
			changeRadioButtonState(DEFAULT);
		}
	}

	void RadioButton::nextCheckState()
	{
		switch (getCheckedState())
		{
		case UNCHECKED:
			changeCheckedState(CHECKED);
			break;
		case CHECKED:
			break;
		default:
			changeCheckedState(CHECKED);
			break;
		}
	}

	RadioButton::RadioButtonStateEnum RadioButton::getRadioButtonState() const
	{
		return radioButtonState;
	}

	RadioButton::RadioButtonCheckedEnum RadioButton::getCheckedState() const
	{
		return checkedState;
	}

	void RadioButton::changeCheckedState( RadioButtonCheckedEnum state )
	{
		if(state == checkedState)
		{
			return;
		}
		checkedState = state;

		for(std::vector<RadioButtonListener*>::iterator it = 
			radioButtonListeners.begin();
			it != radioButtonListeners.end(); ++it)
		{
			if((*it))
				(*it)->checkedStateChanged(this,state);
		}

		if(checkedState == CHECKED)
		dispatchActionEvent(ActionEvent(this));
	}


	void RadioButton::resizeCaption()
	{

		int x = 0;
		int y = 0;
		int sizeX = 0;
		int sizeY = 0;

		switch (getRadioButtonAlignment())
		{
		case ALIGN_TOP_LEFT:
		case ALIGN_MIDDLE_LEFT:
		case ALIGN_BOTTOM_LEFT:
			x += getRadioButtonRadius() * 2;
			x += getSidePadding();
			break;
		case ALIGN_TOP_CENTER:
			y += getRadioButtonRadius() * 2;
		
			break;
		case ALIGN_BOTTOM_CENTER:
			sizeY -= getRadioButtonRadius() * 2;
			break;
		case ALIGN_TOP_RIGHT:
		case ALIGN_MIDDLE_RIGHT:
		case ALIGN_BOTTOM_RIGHT:
			sizeX -= getRadioButtonRadius() * 2;
			sizeX += getSidePadding();
			x += getSidePadding();
			break;
        default: break; // ALIGN_MIDDLE_CENTER?
		}

		sizeX -= x;
		sizeY -= y;

		Rectangle areaRect = getInnerRectangle();

		sizeX += areaRect.getWidth();
		sizeY += areaRect.getHeight();


		wordWrapRect = Rectangle(x,y,sizeX,sizeY);
	}

	void RadioButton::setRadioButtonAlignment( AreaAlignmentEnum alignment )
	{
		radioButtonAlignment = alignment;
		resizeCaption();
		positionRadioButton();
		if(isAutosizing())
		{
			resizeToContents();
		}
		textAreaMan.makeTextLines(getFont(),getText(),
			wordWrappedLines,wordWrapRect.getWidth());

		for(std::vector<RadioButtonListener*>::iterator it = 
			radioButtonListeners.begin();
			it != radioButtonListeners.end(); ++it)
		{
			if((*it))
				(*it)->radioButtonAlignmentChanged(this,alignment);
		}
	}

	AreaAlignmentEnum RadioButton::getRadioButtonAlignment() const
	{
		return radioButtonAlignment;
	}

	void RadioButton::setTextAlignment( AreaAlignmentEnum alignment )
	{
		textAlignment = alignment;
		positionRadioButton();
		if(isAutosizing())
		{
			resizeToContents();
		}
		textAreaMan.makeTextLines(getFont(),getText(),
			wordWrappedLines,wordWrapRect.getWidth());

		for(std::vector<RadioButtonListener*>::iterator it = 
			radioButtonListeners.begin();
			it != radioButtonListeners.end(); ++it)
		{
			if((*it))
				(*it)->textAlignmentChanged(this,alignment);
		}

	}

	AreaAlignmentEnum RadioButton::getTextAlignment() const
	{
		return textAlignment;
	}

	void RadioButton::positionRadioButton()
	{
		radioButtonPosition = createAlignedPosition(
			getRadioButtonAlignment(),getInnerRectangle(),
			Dimension(getRadioButtonRadius() * 2, getRadioButtonRadius() * 2));

		radioButtonPosition = Point(
			radioButtonPosition.getX() + (getRadioButtonRadius() ),
			radioButtonPosition.getY() + (getRadioButtonRadius() ));

		radioButtonRect = Rectangle(Point(
			radioButtonPosition.getX() - getRadioButtonRadius(),
			radioButtonPosition.getY() - getRadioButtonRadius()),
			Dimension(getRadioButtonRadius() * 2, getRadioButtonRadius() * 2));
	}


	void RadioButton::paintComponent( const PaintEvent &paintEvent )
	{
		//draw the radio button
		Color checkFillColor = Color(255,255,255);
		if(getRadioButtonState() == CLICKED)
		{
			checkFillColor = Color(50,95,128);
		}
		else if(getRadioButtonState() == HOVERED)
		{
			checkFillColor = Color(200,220,230);
		}

		paintEvent.graphics()->drawFilledCircle(getRadioButtonPosition(),
			(float)getRadioButtonRadius(),checkFillColor);

		//draw the check mark if needed

		switch(getCheckedState())
		{
		case CHECKED:
			for(int i = 2; i < 8; ++i)
			paintEvent.graphics()->drawFilledCircle(getRadioButtonPosition(),
				(float)(getRadioButtonRadius() / i),Color(20,40 * i,200 * i));
		

			break;
		default:
			break;
		}

		if(isFocused())
		{
			paintEvent.graphics()->drawCircle(getRadioButtonPosition(),(float)getRadioButtonRadius(),
				Color(170,170,170));
		}
		else
		{
			paintEvent.graphics()->drawCircle(getRadioButtonPosition(),(float)getRadioButtonRadius(),
				Color(100,100,100));
		}


		//draw text
		textAreaMan.drawTextArea(paintEvent.graphics(),getFont(),getWordWrapRect(),getFontColor(),
			getTextLines(),getTextAlignment());
	}



	void RadioButton::resizeToContents()
	{
		positionRadioButton();

		if(getText().length() == 0)
		{
			_setSizeInternal(Dimension(getRadioButtonRadius() * 2, getRadioButtonRadius() * 2));
			return;
		}

		int sizeX = getFont()->getTextWidth(getText());
		int sizeY = getFont()->getLineHeight();


		if((int)getRadioButtonRadius() * 2 > sizeY)
		{
			sizeY = getRadioButtonRadius() * 2;
		}


		switch (getRadioButtonAlignment())
		{
		case ALIGN_TOP_CENTER:
		case ALIGN_BOTTOM_CENTER:
			sizeY += getRadioButtonRadius() * 2;
			sizeY += getSidePadding() * 2;
			break;
		case ALIGN_MIDDLE_CENTER:
			break;
		default:
			sizeX += getRadioButtonRadius() * 2;
			sizeX += getSidePadding() * 2;
			break;
		}

		_setSizeInternal(Dimension(sizeX + 
			getMargin(SIDE_LEFT) + 
			getMargin(SIDE_RIGHT),
			sizeY + 
			getMargin(SIDE_TOP) +
			getMargin(SIDE_BOTTOM))
			);
		resizeCaption();


	}


	bool RadioButton::isAutosizing()
	{
		return autosizingCheckbox;
	}

	void RadioButton::setAutosizing( bool autosizing )
	{
		autosizingCheckbox = autosizing;
		if(isAutosizing())
		{
			resizeToContents();
		}

		for(std::vector<RadioButtonListener*>::iterator it = 
			radioButtonListeners.begin();
			it != radioButtonListeners.end(); ++it)
		{
			if((*it))
				(*it)->isAutosizingChanged(this,autosizing);
		}
	}

	void RadioButton::setFontColor( const Color &color )
	{
		Widget::setFontColor(color);
	}

	void RadioButton::_setSizeInternal( const Dimension &size )
	{
		Widget::setSize(size);
		resizeCaption();
		positionRadioButton();
		textAreaMan.makeTextLines(getFont(),getText(),
			wordWrappedLines,wordWrapRect.getWidth());

	}


	void RadioButton::setChecked( bool checked )
	{
		if(checked)
		{
			changeCheckedState(CHECKED);
		}
		else
		{
			changeCheckedState(UNCHECKED);
		}
	}

	bool RadioButton::checked() const
	{
		if(getCheckedState() == CHECKED)
		{
			return true;
		}
		return false;
	}

	void RadioButton::addRadioButtonListener( RadioButtonListener* listener )
	{
		if(!listener)
		{
			return;
		}
		for(std::vector<RadioButtonListener*>::iterator it = 
			radioButtonListeners.begin();
			it != radioButtonListeners.end(); ++it)
		{
			if((*it) == listener)
				return;
		}

		radioButtonListeners.push_back(listener);
	}

	void RadioButton::removeRadioButtonListener( RadioButtonListener* listener )
	{
		radioButtonListeners.erase(
			std::remove(radioButtonListeners.begin(),
			radioButtonListeners.end(), listener),
			radioButtonListeners.end());
	}


	void RadioButton::mouseEnter( MouseEvent &mouseEvent )
	{
		mouseIsInside = true;
		modifyRadioButtonState();
		mouseEvent.consume();
	}

	void RadioButton::setLocation( const Point &location )
	{
		Widget::setLocation(location);
	}

	void RadioButton::setLocation( int x, int y )
	{
		Widget::setLocation(x,y);
	}

	void RadioButton::setFont( const Font *font )
	{
		Widget::setFont(font);
		if(isAutosizing())
		{
			resizeToContents();
		}
		textAreaMan.makeTextLines(getFont(),getText(),
			wordWrappedLines,wordWrapRect.getWidth());
	}

	void RadioButton::setSize( const Dimension &size )
	{
		if(!isAutosizing())
		{
			_setSizeInternal(size);
		}
	}

	void RadioButton::setSize( int width, int height )
	{
		Widget::setSize(width,height);
	}

	void RadioButton::setText( const std::string &text )
	{
		Widget::setText(text);
		resizeCaption();
		if(isAutosizing())
		{
			resizeToContents();
		}
		textAreaMan.makeTextLines(getFont(),getText(),wordWrappedLines,wordWrapRect.getWidth());
	}

	void RadioButton::focusGained()
	{
		Widget::focusGained();
		isDoingKeyAction = false;
		modifyRadioButtonState();
	}

	void RadioButton::focusLost()
	{
		Widget::focusLost();
		isDoingKeyAction = false;
		modifyRadioButtonState();
	}

	void RadioButton::mouseLeave( MouseEvent &mouseEvent )
	{
		mouseIsInside = false;
		modifyRadioButtonState();
		mouseEvent.consume();
	}

	void RadioButton::mouseDown( MouseEvent &mouseEvent )
	{
		if(mouseEvent.getButton() == MOUSE_BUTTON_LEFT)
		{
			mouseIsDown = true;
			mouseEvent.consume();
		}

		modifyRadioButtonState();
	}

	void RadioButton::mouseUp( MouseEvent &mouseEvent )
	{
		if(mouseEvent.getButton() == MOUSE_BUTTON_LEFT)
		{
			mouseIsDown = false;
			mouseEvent.consume();
		}

		modifyRadioButtonState();
	}

	void RadioButton::mouseClick( MouseEvent &mouseEvent )
	{
		if(mouseEvent.getButton() == MOUSE_BUTTON_LEFT)
		{
			nextCheckState();
			mouseEvent.consume();
		}
	}

	void RadioButton::keyDown( KeyEvent &keyEvent )
	{
		
		if(keyEvent.getKey() == KEY_SPACE || keyEvent.getKey() == KEY_ENTER)
		{
			isDoingKeyAction = true;
			changeRadioButtonState(CLICKED);
			keyEvent.consume();
		}
	}

	void RadioButton::keyUp( KeyEvent &keyEvent )
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
			modifyRadioButtonState();
			nextCheckState();
			keyEvent.consume();
		}
	}

	void RadioButton::paintBackground( const PaintEvent &paintEvent )
	{
	}

	const Point& RadioButton::getRadioButtonPosition() const
	{
		return radioButtonPosition;
	}


	int RadioButton::getSidePadding() const
	{
		return sidePadding;
	}

	void RadioButton::setSidePadding(int padding) 
	{
		sidePadding = padding;

		positionRadioButton();
		if(isAutosizing())
		{
			resizeToContents();
		}
		textAreaMan.makeTextLines(getFont(),getText(),
			wordWrappedLines,wordWrapRect.getWidth());

	}

	int RadioButton::getRadioButtonRadius() const
	{
		return radioButtonRadius;
	}

	const Rectangle& RadioButton::getRadioButtonRectangle() const
	{
		return radioButtonRect;
	}

	const std::vector<std::string>& RadioButton::getTextLines() const
	{
		return wordWrappedLines;
	}

	const Rectangle& RadioButton::getWordWrapRect() const
	{
		return wordWrapRect;
	}

}
