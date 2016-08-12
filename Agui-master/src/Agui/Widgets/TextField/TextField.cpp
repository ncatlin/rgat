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

#include "Agui/Widgets/TextField/TextField.hpp"
namespace agui {
	TextField::TextField(void)
    :maxCharacterSkip(8),maxLength(100),caretPosition(0),caretLocation(0),
    textOffset(0),leftPadding(5),rightPadding(5),showCaret(false),
    selfSetText(false), internalSelStart(0), dragged(false),
    selectable(true),readOnly(false),wantDecimal(false),wantNegetive(false),
    numeric(false),hideSelection(true),selectionBackColor(Color(169,193,214)),
    password(false), alignOffset(0),textAlign(ALIGN_LEFT),tOffset(0),
    hotkeys(true), frameColor(Color(180,180,180)),selStart(0),selEnd(0),
    selWidth(0),selLength(0)
	{
		setFocusable(true);
		setTabable(true);
		setPasswordCharacter('*'); 

		positionCaret(0);
	}

	TextField::~TextField(void)
	{
		for(std::vector<TextFieldListener*>::iterator it = tFieldListeners.begin();
			it != tFieldListeners.end(); ++it)
		{
			(*it)->death(this);
		}
	}

	int TextField::getAdjustedWidth() const
	{
		int w = getInnerSize().getWidth()
			- getLeftPadding() - getRightPadding();
		if(w > 0)
		{
			return w;
		}

		return 0;
	}

	void TextField::setLeftPadding( int padding )
	{
		leftPadding = padding;
		scrollToCaret(false,true);
		relocateCaret();
	}

	void TextField::setRightPadding( int padding )
	{
		rightPadding = padding;
		scrollToCaret(false,true);
		relocateCaret();
	}

	int TextField::getRightPadding() const
	{
		return rightPadding;
	}

	int TextField::getLeftPadding() const
	{
		return leftPadding;
	}

	int TextField::getTextOffset() const
	{
		return textOffset;
	}

	int TextField::getCaretLocation() const
	{
		return caretLocation;
	}

	int TextField::getCaretPosition() const
	{
		return caretPosition;
	}

	void TextField::setMaxCharacterSkip( int val )
	{
		if(val < 0)
		{
			val = 0;
		}
		maxCharacterSkip = val;
	}

	int TextField::getMaxCharacterSkip() const
	{
		return maxCharacterSkip;
	}

	void TextField::positionCaret( int position, bool surpressNegChange)
	{
		bool negChange = false;
		if(position > getTextLength())
		{
			position = getTextLength();
		}
		if(position < 0)
		{
			position = 0;
		}
		if(position < caretPosition && !surpressNegChange)
		{
			negChange = true;
		}
		caretPosition = position;

		scrollToCaret(negChange,true);
		relocateCaret();

		//because circular dependencies
		//are the new recursion!
		scrollToCaret(negChange,true);
		relocateCaret();
	}

	void TextField::positionCaret( int position )
	{
		positionCaret(position,true);
	}

	void TextField::scrollToCaret(bool negetiveChange, bool reposition)
	{
		int retOffset = getLeftPadding();
		
		int textWidth = getFont()->getTextWidth(getText());
		if(textWidth < getAdjustedWidth())
		{
			switch(getTextAlignment())
			{
			case ALIGN_LEFT:
				alignOffset = 0;
				break;
			case ALIGN_CENTER:
				alignOffset = (getAdjustedWidth() - textWidth) / 2;
				break;
			case ALIGN_RIGHT:
				alignOffset = getAdjustedWidth() - textWidth;
				break;
			default:
				break;
			}
			
		}
		else
		{
			alignOffset = 0;
		}

		if(getTextLength() == 0 || getCaretPosition() == 0)
		{
			tOffset = retOffset;
			setTextOffset(retOffset + alignOffset);
			return;
		}

		if(reposition)
		{
			//do we need to move?
			if(getFont()->getTextWidth(unicodeFunctions.subStr(getText(),
				0,getCaretPosition())) > -tOffset + getAdjustedWidth() + getLeftPadding()
				
				)
			{

				//scroll to end
				if(getTextLength() < getCaretPosition() + getMaxCharacterSkip())
				{

					retOffset -= solveCaretRetPos(getFont()->getTextWidth(getText())
						- getAdjustedWidth(),
						retOffset);
				}
				else
				{
					int initialPlace = getFont()->getTextWidth(unicodeFunctions.subStr(getText(),
						0, getCaretPosition() + getMaxCharacterSkip() )) - getAdjustedWidth();
					retOffset -= solveCaretRetPos(initialPlace,retOffset);
					
				}



				tOffset = retOffset;
				setTextOffset(retOffset + alignOffset);
				return;

			}
			else if(tOffset + getFont()->getTextWidth(unicodeFunctions.subStr(getText(),
				0,getCaretPosition())) <= leftPadding)
			{

				if(getCaretPosition() - getMaxCharacterSkip() > 0)
				{
					int initialPlace = getFont()->getTextWidth(unicodeFunctions.subStr(getText(),
						0, getCaretPosition() - getMaxCharacterSkip() ));
					retOffset -= solveCaretRetPos(initialPlace,retOffset);

				}

				tOffset = retOffset;
				setTextOffset(retOffset + alignOffset);
				return;
			}
			else if(negetiveChange )
			{

				int change = getCaretLocation() - getFont()->getTextWidth(unicodeFunctions.subStr(getText(),
					0, getCaretPosition() )) ;
				if(change <= getLeftPadding())
				{
					
					tOffset = change;
					setTextOffset(change);
				}
				else
				{
					tOffset = leftPadding;
					setTextOffset(leftPadding + alignOffset);
				}
				return;
			}
		}

		//if there is more text than width
		//but theres not enough to fill the width
		//then fill the width


			int a = getAdjustedWidth() + getLeftPadding();
			int b = getTextOffset() + textWidth;

			if(a > b && getTextOffset() < getLeftPadding())
			{
				retOffset = -textWidth + getInnerSize().getWidth() - getRightPadding(); 

				tOffset = retOffset;

			}
			else if(getTextOffset() >= getLeftPadding() )
			{

				tOffset = leftPadding;
				setTextOffset(leftPadding + alignOffset);
				return;
			}

		setTextOffset(tOffset + alignOffset);

	}

	void TextField::setTextOffset( int offset )
	{
		textOffset = offset;
	}

	void TextField::relocateCaret()
	{
		caretLocation = getFont()->getTextWidth(unicodeFunctions.subStr(getText(),
			0,getCaretPosition())) + getTextOffset();
	}

	void TextField::removeLastCharacter()
	{
		//don't try to remove past the beginning 
		if(getCaretPosition() - 1 < 0)
		{
			return;
		}

		std::string text;
			if(!isPassword())
			text = getText();
			else
			text = getPassword();

		unicodeFunctions.erase(text,getCaretPosition() - 1,1);
		setThisText(text);
		positionCaret(getCaretPosition() - 1,false);

	}

	void TextField::removeNextCharacter()
	{
		//don't try to remove past the end
		if(getCaretPosition() + 1 > getTextLength())
		{
			return;
		}
		std::string text;
		if(!isPassword())
			text = getText();
		else
			text = getPassword();

		unicodeFunctions.erase(text,getCaretPosition(),1);

		setThisText(text);
		positionCaret(getCaretPosition());
	}

	void TextField::setThisText( const std::string &text )
	{
		selfSetText = true;
		setText(text);
		selfSetText = false;
	}

	void TextField::addToNextCharacter( int unichar )
	{
		if(getTextLength() + 1 > getMaxLength())
		{
			return;
		}

		char buffer[8];
		for(int i = 0; i < 8; ++i)
		{
			buffer[i] = 0;
		}

		unicodeFunctions.encodeUtf8(buffer,unichar);
		std::string appendStr = buffer;
		
		std::string text;
		if(!isPassword())
			text = getText();
		else
			text = getPassword();

		unicodeFunctions.insert(text,getCaretPosition(),buffer);

		setThisText(text);
		positionCaret(getCaretPosition() + 1);

	}

	void TextField::setMaxLength( int length )
	{
		maxLength = length;
	}

	int TextField::getMaxLength() const
	{
		return maxLength;
	}

	void TextField::setText( const std::string &text )
	{
		//truncate string if it is too long
		if(isPassword())
		{
			
			int len = int(unicodeFunctions.length(text));
			int subLen = len;
			if( len > getMaxLength())
			{
				subLen = maxLength;
			}
			passText = "";
			for(int i = 0; i < subLen ; ++i)
			{
				passText += passwordChar;
			}
		

			if(getMaxLength() < len)
			{
				passwordText = unicodeFunctions.subStr(text,0,getMaxLength());
			}
			else
			{
				passwordText = text;
			}

				Widget::setText(passText);
		}
		else
		{
			if(getMaxLength() < (int) unicodeFunctions.length(text))
			{
				Widget::setText(unicodeFunctions.subStr(text,0,getMaxLength()));
			}
			else
			{
				Widget::setText(text);
			}
		}
	
		

		
		if(!selfSetText)
		{
			positionCaret(getTextLength());
			
		}

		setSelection(0,0);
	}

	void TextField::keyDown( KeyEvent &keyEvent )
	{
		handleKeyboard(keyEvent);
		if(keyEvent.getKey() == KEY_ENTER)
		{
			dispatchActionEvent(ActionEvent(this));
		}
			keyEvent.consume();
	}

	void TextField::handleKeyboard( KeyEvent &keyEvent )
	{
		if(handleHotkeys(keyEvent))
		{
			return;
		}

		//delete the next character
		if(keyEvent.getKey() == KEY_DELETE)
		{
			if(getCaretPosition() == getTextLength()
				&& getSelectionStart() == getSelectionEnd())
			{
				return;
			}

			if(isReadOnly())
			{
				return;
			}

			if(getSelectionStart() == getSelectionEnd())
			{
				removeNextCharacter();
			}
			else
			{
				deleteSelection();
			}
			setBlinking(true);
			invalidateBlink();
			return;
		}

		//delete the previous character
		if(keyEvent.getKey() == KEY_BACKSPACE)
		{
			if(getCaretPosition() == 0 && getSelectionStart() == getSelectionEnd())
			{
				return;
			}

			if(isReadOnly())
			{
				return;
			}

			if(getSelectionStart() == getSelectionEnd())
			{
				removeLastCharacter();
			}
			else
			{
				deleteSelection();
			}
			setBlinking(true);
			invalidateBlink();
			return;
		}

		if(keyEvent.getUnichar() >= ' ')
		{
			if(isReadOnly())
			{
				setBlinking(true);
				invalidateBlink();
				return;
			}

			if( isNumeric())
			{
				if(keyEvent.getUnichar() >= 0x30  && keyEvent.getUnichar() <= 0x39 )
				{
					deleteSelection();
					addToNextCharacter(keyEvent.getUnichar());
					setBlinking(true);
					invalidateBlink();
				}
				else if(wantedDecimal() && keyEvent.getUnichar() == 0x2e )
				{
					//check if there is already a decimal
					const char *text = getText().c_str();
					for (int i = 0; i < getTextLength(); ++i)
					{
						if(text[i] == 0x2e)
						{
							return;
						}
					}

					deleteSelection();
					addToNextCharacter(keyEvent.getUnichar());
					setBlinking(true);
					invalidateBlink();
				}
				else if(wantedMinus() && keyEvent.getUnichar() == 0x2d )
				{
					//check if we are in the first position
					if(getCaretPosition() != 0)
					{
						return;
					}

					//check if there is already a minus
					const char *text = getText().c_str();
					for (int i = 0; i < getTextLength(); ++i)
					{
						if(text[i] == 0x2d)
						{
							return;
						}
					}

					deleteSelection();
					addToNextCharacter(keyEvent.getUnichar());
					setBlinking(true);
					invalidateBlink();
				}
				

				return;
			}
			deleteSelection();
			addToNextCharacter(keyEvent.getUnichar());

			setBlinking(true);
			invalidateBlink();
			return;
		}

		switch (keyEvent.getExtendedKey())
		{
		case EXT_KEY_RIGHT:

			if(getCaretPosition() == getTextLength() 
				&& getSelectionStart() != getSelectionEnd() &&
				keyEvent.shift())
			{
				return;
			}
			else if(getCaretPosition() == getTextLength() 
				&& getSelectionStart() == getSelectionEnd())
			{
				return;
			}

			positionCaret(getCaretPosition() + 1);

			if(keyEvent.shift())
			{
				if(getSelectionStart() == getSelectionEnd())
				{
					setSelection(getCaretPosition() - 1, getCaretPosition());
				}
				else
				{
					if(getCaretPosition() - 1 < getSelectionEnd())
						setSelection(getSelectionEnd(), getCaretPosition());
					else
						setSelection(getSelectionStart(), getCaretPosition());
				}
			}
			else if(getSelectionStart() != getSelectionEnd())
			{
				int caretPos = getSelectionEnd();
				setSelection(0,0);
				positionCaret(caretPos);
			}

			setBlinking(true);
			invalidateBlink();
			break;
		case EXT_KEY_LEFT:
			printf("xxext_keyleft\n");
			if(getCaretPosition() == 0 
				&& getSelectionStart() != getSelectionEnd() &&
				keyEvent.shift())
			{
				return;
			}
			else if(getCaretPosition() == 0
				&& getSelectionStart() == getSelectionEnd())
			{
				return;
			}

			positionCaret(getCaretPosition() - 1);

			if(keyEvent.shift())
			{
				if(getSelectionStart() == getSelectionEnd())
				{
					setSelection(getCaretPosition() + 1, getCaretPosition());
				}
				else
				{
					if(getCaretPosition() + 1 < getSelectionEnd())
						setSelection(getSelectionEnd(), getCaretPosition());
					else
						setSelection(getSelectionStart(), getCaretPosition());
				}
			}

			else if(getSelectionStart() != getSelectionEnd())
			{
				int caretPos = getSelectionStart();
				setSelection(0,0);
				positionCaret(caretPos);
			}

			setBlinking(true);
			invalidateBlink();
			break;
        default: break;
		}

	}

	void TextField::paintComponent( const PaintEvent &paintEvent )
	{
		int caretLoc = getCaretLocation();
		int textLoc = getTextOffset();

		Rectangle sideclip = getInnerRectangle();
		sideclip = Rectangle(sideclip.getX() + getLeftPadding() ,
			sideclip.getY() + 2,sideclip.getSize().getWidth() - getLeftPadding()
			- getRightPadding() + 1, sideclip.getHeight() - 4);

		

		if(isReadOnly())
		{
			paintEvent.graphics()->drawFilledRectangle(
				getSizeRectangle(),frameColor);
		}
		else
		{
			paintEvent.graphics()->drawFilledRectangle(
				getSizeRectangle(),getBackColor());
		}
		

		paintEvent.graphics()->pushClippingRect(sideclip);

		if(getSelectionStart() != getSelectionEnd() && (isFocused() || !isHidingSelection()) )
		{
			Rectangle selRect = Rectangle(
				getSelectionLocation(),
				(getInnerHeight() / 2) - 
				(getFont()->getLineHeight() / 2),
				getSelectionWidth(),
				getFont()->getLineHeight());

			paintEvent.graphics()->drawFilledRectangle(
				selRect,getSelectionBackColor());
		}


			paintEvent.graphics()->drawText(Point(textLoc, +
				((getInnerSize().getHeight() - getFont()->getLineHeight()) / 2)),getText().c_str(),
				getFontColor(),getFont());
		

			if(isFocused())
			{
				if(isBlinking())
					paintEvent.graphics()->drawLine(Point(caretLoc + 1,
					((getInnerSize().getHeight() / 2) + (getFont()->getLineHeight() / 2))),
					Point(caretLoc + 1, ((getInnerSize().getHeight() / 2) - 
					(getFont()->getLineHeight() / 2))),
					Color(0,0,0));
			}


		paintEvent.graphics()->popClippingRect();

		
	}

	void TextField::keyRepeat( KeyEvent &keyEvent )
	{
		handleKeyboard(keyEvent);
			keyEvent.consume();
	}

	void TextField::mouseDown( MouseEvent &mouseEvent )
	{

		if(mouseEvent.getButton() != MOUSE_BUTTON_LEFT)
		{
			return;
		}
		dragged = false;
		int x = mouseEvent.getX() - getTextOffset() - getMargin(SIDE_LEFT);
		positionCaret(getFont()->getStringIndexFromPosition(getText(),x));

		internalSelStart = getCaretPosition();
		setSelection(0,0);
		mouseEvent.consume();
	}


	void TextField::focusGained()
	{
		Widget::focusGained();

		setBlinking(true);
		invalidateBlink();
	}

	void TextField::setFont( const Font *font )
	{
		Widget::setFont(font);
		if(getInnerSize().getHeight() < getFont()->getLineHeight())
		{
			setSize(getSize().getWidth(),getFont()->getLineHeight()
				+ getMargin(SIDE_TOP) + getMargin(SIDE_BOTTOM));
		}
		positionCaret(getCaretPosition());
	}

	void TextField::resizeHeightToContents()
	{
		setSize(getSize().getWidth(), getFont()->getLineHeight()
			+ getMargin(SIDE_TOP) + getMargin(SIDE_BOTTOM)
			+ 4); //added 4 to ensure everything shows up comfortably
	}

	void TextField::resizeWidthToContents()
	{
		setSize(getFont()->getTextWidth(getText()) + getLeftPadding() + getRightPadding()
			+ getMargin(SIDE_LEFT) + getMargin(SIDE_RIGHT),
			getSize().getHeight());
		positionCaret(0);
	}

	void TextField::resizeToContents()
	{
		resizeWidthToContents();
		resizeHeightToContents();
	}

	void TextField::mouseDrag( MouseEvent &mouseEvent )
	{
		if(mouseEvent.getButton() != MOUSE_BUTTON_LEFT)
		{
			return;
		}
		if(!isSelectable())
		{
			return;
		}
		dragged = true;

		int maxcharSkip = getMaxCharacterSkip();
		maxCharacterSkip = 1;
		int x = mouseEvent.getX() - getTextOffset() - getMargin(SIDE_LEFT);
		positionCaret(getFont()->getStringIndexFromPosition(getText(),x));

		setSelection(internalSelStart,getCaretPosition());
		maxCharacterSkip = maxcharSkip;
		mouseEvent.consume();
	}

	int TextField::getSelectionStart() const
	{
		return selStart;
	}

	int TextField::getSelectionEnd() const
	{
		return selEnd;
	}

	void TextField::setSelection( int start, int end )
	{
		if(!isSelectable())
		{
			if(getSelectionStart() != getSelectionEnd())
			{
				start = 0;
				end = 0;
			}
			else
			{
				return;
			}
		}
		if(start == end)
		{
			selStart = 0;
			selEnd = 0;
			selWidth = 0;
		}

		if(start == -1 && end == -1)
		{
			start = 0;
			end = getTextLength();
		}
		else if( end == -1)
		{
			end = getTextLength();
		}
		if( start > end)
		{
			int temp = start;
			start = end;
			end = temp;
		}

		if(start < 0)
		{
			start = 0;
		}
		if( end > getTextLength() )
		{
			end = getTextLength();
		}

		for(std::vector<TextFieldListener*>::iterator it = tFieldListeners.begin();
			it != tFieldListeners.end(); ++it)
		{
			(*it)->selectionChanged(this,start,end);
		}

		selStart = start;
		selEnd = end;
		selLength = end - start;
		selPos = getFont()->getTextWidth(unicodeFunctions.subStr(getText(),
			0,start)) + getTextOffset();

		selWidth = getFont()->getTextWidth(unicodeFunctions.subStr(getText(),
			start,selLength));

	}

	int TextField::getSelectionWidth() const
	{
		return selWidth;
	}

	int TextField::getSelectionLength() const
	{
		return selLength;
	}

	void TextField::deleteSelection()
	{
		if(getSelectionStart() == getSelectionEnd())
		{
			return;
		}
		positionCaret(getSelectionEnd());
		int e = getSelectionEnd();
		int s = getSelectionStart();
		for (int i = e; i > s; i--)
		{
			removeLastCharacter();
		}
		setSelection(0,0);
	}

	int TextField::getSelectionLocation() const
	{
		return selPos;
	}

	void TextField::focusLost()
	{
		Widget::focusLost();
	}

	void TextField::mouseUp( MouseEvent &mouseEvent )
	{
		dragged = false;
		mouseEvent.consume();
	}

	void TextField::setSelectable( bool selectable )
	{
		this->selectable = selectable;
		if(!isSelectable())
		{
			setSelection(0,0);
		}

		for(std::vector<TextFieldListener*>::iterator it = tFieldListeners.begin();
			it != tFieldListeners.end(); ++it)
		{
			(*it)->selectableChanged(this,selectable);
		}
	}

	bool TextField::isSelectable() const
	{
		return selectable;
	}

	void TextField::selectAll()
	{
		
		setSelection(-1,-1);
		caretPosition = getTextLength();
		relocateCaret();
	}

	void TextField::setReadOnly( bool readOny )
	{
		this->readOnly = readOny;
		for(std::vector<TextFieldListener*>::iterator it = tFieldListeners.begin();
			it != tFieldListeners.end(); ++it)
		{
			(*it)->readOnlyChanged(this,readOnly);
		}
	}

	bool TextField::isReadOnly() const
	{
		return readOnly;
	}

	bool TextField::wantedDecimal() const
	{
		if(isNumeric())
		return wantDecimal;
		else
			return false;
	}

	void TextField::setNumeric( bool numeric, bool wantDecimal, bool wantMinus )
	{
		this->numeric = numeric;
		this->wantDecimal = wantDecimal;
		this->wantNegetive = wantMinus;

		for(std::vector<TextFieldListener*>::iterator it = tFieldListeners.begin();
			it != tFieldListeners.end(); ++it)
		{
			(*it)->numericChanged(this,numeric,wantDecimal,wantMinus);
		}
	}

	bool TextField::isNumeric() const
	{
		return numeric;
	}

	int TextField::parseInteger() const
	{
		std::stringstream sstr;
		sstr << getText();
		int retVal = 0;
		sstr >> retVal;
		return retVal;
	}

	bool TextField::wantedMinus() const
	{
		if(isNumeric())
		{
			return wantNegetive;
		}
		else
		{
			return false;
		}
	}

	float TextField::parseFloat() const
	{
		std::stringstream sstr;
		sstr << getText();
		float retVal = 0;
		sstr >> retVal;
		return retVal;
	}

	double TextField::parseDouble() const
	{
		std::stringstream sstr;
		sstr << getText();
		double retVal = 0;
		sstr >> retVal;
		return retVal;
	}

	bool TextField::isHidingSelection() const
	{
		return hideSelection;
	}

	void TextField::setHideSelection( bool hidden )
	{
		hideSelection = hidden;
		for(std::vector<TextFieldListener*>::iterator it = tFieldListeners.begin();
			it != tFieldListeners.end(); ++it)
		{
			(*it)->hideSelectionChanged(this,hidden);
		}
	}

	const std::string TextField::getSelectedText() const
	{
		if(getSelectionStart() == getSelectionEnd())
		{
			return std::string("");
		}
		else
		{
			return unicodeFunctions.subStr(getText(),
				getSelectionStart(),getSelectionLength());
		}
	}

	void TextField::addTextFieldListener( TextFieldListener* listener )
	{
		if(!listener)
		{
			return;
		}
		for(std::vector<TextFieldListener*>::iterator it = 
			tFieldListeners.begin();
			it != tFieldListeners.end(); ++it)
		{
			if((*it) == listener)
				return;
		}

		tFieldListeners.push_back(listener);
	}

	void TextField::removeTextFieldListener( TextFieldListener* listener )
	{
		tFieldListeners.erase(
			std::remove(tFieldListeners.begin(),
			tFieldListeners.end(), listener),
			tFieldListeners.end());
	}

	AlignmentEnum TextField::getTextAlignment() const
	{
		return textAlign;
	}

	void TextField::setTextAlignment( AlignmentEnum alignment )
	{
		textAlign = alignment;
		scrollToCaret(false,true);
		relocateCaret();
	}

	void TextField::paintBackground( const PaintEvent &paintEvent )
	{
		paintEvent.graphics()->drawFilledRectangle(getSizeRectangle(),getBackColor());

		Color  Top = Color(171,171,171);
		Color  Left = Color(227,227,227);
		Color  Bottom = Color(231,231,231);
		Color  Right = Color(222,222,222);


		if(isFocused())
		{
			Top = Color(63,123,173);
			Left = Color(181,207,231);
			Bottom = Color(183,217,237);
			Right = Color(164,201,227);
		}



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

	void TextField::logic( double timeElapsed )
	{
		processBlinkEvent(timeElapsed);
	}

	void TextField::setSelectionBackColor( const Color &color )
	{
		selectionBackColor = color;
	}

	bool TextField::isPassword() const
	{
		return password;
	}

	const Color& TextField::getSelectionBackColor() const
	{
		return selectionBackColor;
	}

	void TextField::setIsPassword( bool password )
	{
		bool wasPassword = this->password;
		this->password = password;
		if(wasPassword && !password)
		{
			setThisText(getPassword());
			passwordText = "";
		}
		else
		setThisText(getText());
	}

	void TextField::setPasswordCharacter( int unichar )
	{
		char buffer[8];
		for(int i = 0; i < 8; ++i)
		{
			buffer[i] = 0;
		}

		unicodeFunctions.encodeUtf8(buffer,unichar);
		passwordChar = buffer;
		if(isPassword())
		setThisText(getPassword());
		else
		setThisText(getText());
	}

	const std::string& TextField::getPasswordCharacter() const
	{
		return passwordChar;
	}

	const std::string& TextField::getPassword() const
	{
		return passwordText;
	}

	void TextField::setSize( const Dimension& size )
	{
		Widget::setSize(size);

		scrollToCaret(false,false);
		relocateCaret();
		setSelection(getSelectionStart(),getSelectionEnd());
	}

	void TextField::setSize( int width, int height )
	{
		Widget::setSize(width,height);
	}

	int TextField::solveCaretRetPos( int initialAmount, int retOffset )
	{
		int tempResult = retOffset + alignOffset - initialAmount;

		int tempCaret = getFont()->getTextWidth(unicodeFunctions.subStr(getText(),
			0,getCaretPosition())) + tempResult;

		if(tempCaret > getAdjustedWidth() + getLeftPadding() ||
			tempCaret < getLeftPadding())
		{
			return getFont()->getTextWidth(unicodeFunctions.subStr(getText(),
				0, getCaretPosition() + 1 )) - getAdjustedWidth();
		}
		else
		{
			return initialAmount;
		}
	}

	void TextField::setWantHotkeys( bool hotkeysEnabled )
	{
		hotkeys = hotkeysEnabled;
	}

	bool TextField::wantsHotkeys() const
	{
		return hotkeys;
	}

	bool TextField::handleHotkeys(const KeyEvent &keyEvent )
	{
		if(!wantsHotkeys())
		{
			return false;
		}
		bool  isKeyDown = false;
		#ifdef __APPLE__
				isKeyDown = keyEvent.meta();
		#else
				isKeyDown = keyEvent.control();
		#endif


		if(isKeyDown && keyEvent.getKey() == KEY_A )
		{
			selectAll();
		}
		else if(isKeyDown && keyEvent.getKey() == KEY_C )
		{
			copy();
		}
		else if(isKeyDown && keyEvent.getKey() == KEY_X )
		{
			cut();
		}
		else if(isKeyDown && keyEvent.getKey() == KEY_V )
		{
			paste();
		}
		else
		{
			return false;
		}

		return true;


	}

	void TextField::cut()
	{
		if(getSelectionLength() > 0)
		{
			Clipboard::copy(getSelectedText());
			deleteSelection();
		}
		
	}

	void TextField::copy()
	{
		if(getSelectionLength() > 0)
		{
			Clipboard::copy(getSelectedText());
		}
	}

	void TextField::paste()
	{
		if(isReadOnly())
		{
			return;
		}


		std::string pasteResult = Clipboard::paste();

		if(pasteResult.length() == 0 || getTextLength() - getSelectionLength() == getMaxLength())
		{
			return;
		}

		deleteSelection();
		int start = getCaretPosition();
		
		std::string noNewLine;

		for(size_t i = 0; i < pasteResult.size(); ++i)
		{
			if(pasteResult[i] != '\n')
			{
				noNewLine += pasteResult[i];
			}
		}

		int length = int(unicodeFunctions.length(noNewLine));
		int numRemainingChar = getMaxLength() - getTextLength();
		if(numRemainingChar < length)
		{
			noNewLine = unicodeFunctions.subStr(noNewLine,0,numRemainingChar);
			length = numRemainingChar;
		}
		if(length > 0)
		{
			std::string* cText = (std::string*)&getText();
			unicodeFunctions.insert(*cText,start,noNewLine);
			setThisText(*cText);
			positionCaret(caretPosition + length);
		}
	}
    
    bool TextField::canAcceptKeyInput() const
    {
        return !isReadOnly();
    }
    
    bool TextField::isTextField() const
    {
        return true;
    }

	void TextField::appendText( const std::string& text, bool atCurrentPosition /*= true*/ )
	{
		if(text.length() == 0 || getTextLength() - getSelectionLength() == getMaxLength())
		{
			return;
		}

		deleteSelection();
		if(!atCurrentPosition)
		{
			positionCaret(getTextLength());
		}
		int start = getCaretPosition();

		std::string noNewLine;

		for(size_t i = 0; i < text.size(); ++i)
		{
			if(text[i] != '\n')
			{
				noNewLine += text[i];
			}
		}

		int length = int(unicodeFunctions.length(noNewLine));
		int numRemainingChar = getMaxLength() - getTextLength();
		if(numRemainingChar < length)
		{
			noNewLine = unicodeFunctions.subStr(noNewLine,0,numRemainingChar);
			length = numRemainingChar;
		}
		if(length > 0)
		{
			std::string* cText = (std::string*)&getText();
			unicodeFunctions.insert(*cText,start,noNewLine);
			setThisText(*cText);
			positionCaret(caretPosition + length);
		}
	}

	CursorProvider::CursorEnum TextField::getEnterCursor() const
	{
		return CursorProvider::EDIT_CURSOR;
	}

}
