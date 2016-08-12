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

#include "Agui/Widgets/TextBox/TextBox.hpp"
#include "Agui/EmptyWidget.hpp"

namespace agui {
	TextBox::TextBox( HScrollBar *hScroll /*= NULL*/,
							 VScrollBar *vScroll /*= NULL*/,
							 Widget *scrollInset /*= NULL*/)
	: topPadding(2), leftPadding(5), bottomPadding(0), rightPadding(5),
	  hScrollPolicy(SHOW_AUTO), vScrollPolicy(SHOW_AUTO),
	  horizontalOffset(0),verticalOffset(0), caretRow(0),caretColumn(0),
	  caretRowLocation(0), caretColumnLocation(0),widestLine(0),
	  wordWrap(false),readOnly(false),drawBorder(true),maxSkip(10),numSelLines(0), mouseDownIndex(0),
	  dragged(false),splittingWords(true),standardArrowKeyRules(true),
	  textAlignment(ALIGN_LEFT),selectionBackColor(Color(169,193,214)),
	  hideSelection(true),selfSetText(false),maxLength(100000),selectable(true),
	  hotkeys(true)
	{
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

		if(scrollInset)
		{
			isMaintainingScrollInset = false;
			pChildInset = scrollInset;
		}
		else
		{
			isMaintainingScrollInset = true;
			pChildInset = new EmptyWidget();
		}
		addPrivateChild(pChildVScroll);
		addPrivateChild(pChildHScroll);
		addPrivateChild(pChildInset);

		pChildHScroll->addHScrollBarListener(this);
		pChildVScroll->addVScrollBarListener(this);
		pChildInset->setBackColor(Color(120,120,120));

		setFocusable(true);
		setTabable(true);

		setWheelScrollRate(2);

		changeTextOffset();

		positionCaret(0,0);

		setText("");
	}


	int TextBox::getAdjustedWidth() const
	{
		int w = getInnerSize().getWidth()
			- getLeftPadding() - getRightPadding();
		if(w > 0)
		{
			return w;
		}

		return 0;
	}

	int TextBox::getLeftPadding() const
	{
		return leftPadding;
	}

	int TextBox::getRightPadding() const
	{
		return rightPadding;
	}

	int TextBox::getTopPadding() const
	{
		return topPadding;
	}

	int TextBox::getBottomPadding() const
	{
		return bottomPadding;
	}

	int TextBox::getAdjustedHeight() const
	{
		int h = getInnerSize().getHeight()
			- getTopPadding() - getBottomPadding();
		if(h > 0)
		{
			return h;
		}

		return 0;
	}


	bool TextBox::isHScrollNeeded() const
	{
		if(getHScrollPolicy() == SHOW_NEVER)
		{
			return false;
		}

		if(getContentWidth() > getAdjustedWidth())
		{

			return true;
		}
		else if(widestLine > 0 && getVScrollPolicy() != SHOW_NEVER &&
			(getContentHeight() >  getAdjustedHeight()  &&
			getContentWidth() > (getAdjustedWidth() - pChildVScroll->getWidth() )))
		{

			return true;
		}
		return false;
	}

	bool TextBox::isVScrollNeeded() const
	{
		if(getVScrollPolicy() == SHOW_NEVER)
		{
			return false;
		}
		if(getContentHeight() > getAdjustedHeight())
		{
			return true;
		}
		else if(getHScrollPolicy() != SHOW_NEVER &&
			(getContentWidth() >  getAdjustedWidth()  &&
			getContentHeight() > (getAdjustedHeight() - pChildHScroll->getHeight() )))
		{
			return true;
		}
		return false;
	}


	void TextBox::checkScrollPolicy()
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

	void TextBox::resizeSBsToPolicy()
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

	void TextBox::adjustSBRanges()
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
		pChildVScroll->setRangeFromPage(getAdjustedHeight() - extraH,getContentHeight());
		

		//set horizontal value
		pChildHScroll->setRangeFromPage(getAdjustedWidth() - extraV,getContentWidth());

	}

	void TextBox::updateScrollBars()
	{
		checkScrollPolicy();
		resizeSBsToPolicy();
		adjustSBRanges();
	}

	int TextBox::getContentHeight() const
	{
		return int(textRows.size() * getLineHeight());
	}

	int TextBox::getContentWidth() const
	{
		return widestLine;
		
	}

	int TextBox::getVerticalOffset() const
	{
		return verticalOffset;
	}

	int TextBox::getHorizontalOffset() const
	{
		return horizontalOffset;
	}

	ScrollPolicy TextBox::getHScrollPolicy() const
	{
		return hScrollPolicy;
	}

	ScrollPolicy TextBox::getVScrollPolicy() const
	{
		return vScrollPolicy;
	}

	TextBox::~TextBox( void )
	{
		for(std::vector<TextBoxListener*>::iterator it = 
			textBoxListeners.begin();
			it != textBoxListeners.end(); ++it)
		{
			if((*it))
				(*it)->death(this);
		}

		pChildHScroll->removeHScrollBarListener(this);
		pChildVScroll->removeVScrollBarListener(this);

		if(isMaintainingHScroll)
		{
			delete pChildHScroll;
		}

		if(isMaintainingVScroll)
		{
			delete pChildVScroll;
		}

		if(isMaintainingScrollInset)
		{
			delete pChildInset;
		}
	}

	void TextBox::setHScrollPolicy( ScrollPolicy policy )
	{
		hScrollPolicy = policy;
		updateScrollBars();
	}

	void TextBox::setVScrollPolicy( ScrollPolicy policy )
	{
		vScrollPolicy = policy;
		updateScrollBars();
	}

	void TextBox::setTopPadding( int padding )
	{
		topPadding = padding;
		changeTextOffset();
	}

	void TextBox::setLeftPadding( int padding )
	{
		leftPadding = padding;
		changeTextOffset();
	}

	void TextBox::setBottomPadding( int padding )
	{
		bottomPadding = padding;
	}

	void TextBox::setRightPadding( int padding )
	{
		rightPadding = padding;
	}

	void TextBox::valueChanged( HScrollBar* source, int val )
	{
		(void)source;
		horizontalOffset = -val + getLeftPadding();
		relocateCaret();
	}

	void TextBox::valueChanged( VScrollBar* source, int val )
	{
		(void)source;
		verticalOffset = -val + getTopPadding();
		relocateCaret();
		setSelection(getSelectionStart(),getSelectionEnd());
	}

	void TextBox::paintComponent( const PaintEvent &paintEvent )
	{

		int textX = horizontalOffset;
		int textY = verticalOffset;
		int voffset = 0;
		int hoffset = 0;
		if(pChildHScroll->isVisible())
		{
			hoffset = pChildHScroll->getHeight();
		}
		if(pChildVScroll->isVisible())
		{

			voffset = pChildVScroll->getWidth();
		}

		int linesSkipped = getVisibleLineStart();
		int maxitems = getVisibleLineCount();


		paintEvent.graphics()->pushClippingRect(Rectangle(getLeftPadding(),
			topPadding, getAdjustedWidth() - voffset + 1, getAdjustedHeight() - hoffset));


		//only show selection if it is not hidden
		if(!isHidingSelection() || (isHidingSelection() && isFocused()))
		for(int i = 0; i < getSelLineCount(); ++i)
		{
			paintEvent.graphics()->drawFilledRectangle(Rectangle(
				getSelLineAt(i).first.getX() + textX,
				getSelLineAt(i).first.getY() + textY,
				getSelLineAt(i).second.getX(),
				getSelLineAt(i).second.getY()),getSelectionBackColor());
		}

		for(int i = linesSkipped; i <= maxitems + linesSkipped; ++i)
		{
			if(i >= (int)textRows.size())
			{
				break;
			}

			paintEvent.graphics()->drawText(Point(textX + getLineOffset(i),
				textY + (i * getLineHeight())),
				textRows[i].c_str(),getFontColor(),getFont());

		}
		

		if(isFocused() && isBlinking())
			paintEvent.graphics()->drawLine(Point(getCaretColumnLocation() + 1 , getCaretRowLocation() ),
			Point(getCaretColumnLocation() + 1, getCaretRowLocation() + getLineHeight()),
			Color(0,0,0));

		paintEvent.graphics()->popClippingRect();
		
	}

	void TextBox::setSize( const Dimension &size )
	{
		int oldX = getSize().getWidth();

		int pos = 0;

		if(isWordWrap())
		pos = indexFromColumnRow(getCaretColumn(),getCaretRow());

		Widget::setSize(size);

		if(isWordWrap())
		{
			if(oldX != getSize().getWidth())
				updateText();

			Point p = columnRowFromIndex(pos);

			sizePositionCaret(p);
		}

		setSelection(getSelectionStart(),getSelectionEnd());
		updateScrollBars();
	}

	void TextBox::setSize( int width, int height )
	{
		Widget::setSize(width,height);
	}

	void TextBox::updateText()
	{
		if(isWordWrap())
		makeLinesFromWordWrap();
		else
		makeLinesFromNewline();

		rowLengths.clear();
		for(size_t i = 0; i < textRows.size(); ++i)
		{
			rowLengths.push_back(int(unicodeFunctions.length(textRows[i])));
		}
	}

	void TextBox::makeLinesFromNewline()
	{
		textRows.clear();
		textRows.push_back("");

		int bytesSkipped = 0;
		int curCharLen = 0;
		std::string curChar;

		size_t ind = 0;

		int len = getTextLength();
		for(int i = 0; i < len; ++i)
		{
			curCharLen = int(unicodeFunctions.bringToNextUnichar(ind,getText()));
			curChar = getText().substr(bytesSkipped,curCharLen);
			bytesSkipped += curCharLen;
		

			if(curChar[0] == '\n')
			{
				textRows.push_back("");
				continue;
			}

			if(curChar[0] != '\n')
				textRows.back() += curChar;
		}

		
			updateWidestLine();
			lineOffset.clear();
			for(size_t i = 0; i < textRows.size(); ++i)
			{
				lineOffset.push_back(0);
			}
	}

	void TextBox::setText( const std::string &text )
	{
		if((int)unicodeFunctions.length(text) > getMaxLength())
		{
			Widget::setText(unicodeFunctions.subStr(text,0,getMaxLength()));
		}
		else
		{
			Widget::setText(text);
		}
		
		updateText();
		updateScrollBars();
		setSelection(0,0);
		if(!isSelfSettingText())
		{
			mousePositionCaret(columnRowFromIndex(getTextLength()));
		}
	}

	void TextBox::makeLinesFromWordWrap()
	{
		textRows.clear();
		textRows.push_back("");
		std::string curStr;
		std::string curWord;

		int curWordWidth = 0;
		int curLetterWidth = 0;
		int curLineWidth = 0;

		bool isVscroll = pChildVScroll->isVisible();
		int voffset = 0;
		if(isVscroll)
		{
			voffset = pChildVScroll->getWidth();
		}
		int AdjWidthMinusVoffset = getAdjustedWidth() - voffset;
		size_t len = getTextLength();
		size_t bytesSkipped = 0;
		size_t letterLength = 0;
		size_t ind = 0;

		for(size_t i = 0; i < len; ++i)
		{
			
			//get the unicode character
			letterLength = unicodeFunctions.bringToNextUnichar(ind,getText());
			curStr = getText().substr(bytesSkipped,letterLength);
			
			
			bytesSkipped += letterLength;

			curLetterWidth = getTextWidth(curStr);

			//push a new line
			if(curStr[0] == '\n')
			{
				textRows.back() += curWord;
				curWord = "";
				curLetterWidth = 0;
				curWordWidth = 0;
				curLineWidth = 0;
				textRows.push_back("");
				continue;
			}


		
				//ensure word is not longer than the width
				if(curWordWidth + curLetterWidth >= AdjWidthMinusVoffset)
				{
					textRows.back() += curWord;
					
					textRows.push_back("");
					curWord = "";
					curWordWidth = 0;
					curLineWidth = 0;
				}

				//add letter to word
				curWord += curStr;
				curWordWidth += curLetterWidth;
			

			//if we need a Vscroll bar start over
			if(!isVscroll && isVScrollNeeded())
			{
				isVscroll = true;
				voffset = pChildVScroll->getWidth();
				AdjWidthMinusVoffset = getAdjustedWidth() - voffset;
				i = -1;
				curWord = "";
				curStr = "";
				textRows.clear();
				textRows.push_back("");
				ind = 0;

				curWordWidth = 0;
				curLetterWidth = 0;
				curLineWidth = 0;

				bytesSkipped = 0;
				continue;
			}

			if(curLineWidth + curWordWidth >= 
				AdjWidthMinusVoffset && textRows.back().length() >= 1)
			{
				textRows.push_back("");
				curLineWidth = 0;
			}

			if(isSplittingWords())
			{
				if(curStr[0] == ' ' || curStr[0] == '-')
				{
					textRows.back() += curWord;
					curLineWidth += curWordWidth;
					curWord = "";
					curWordWidth = 0;
				}
			}
		
		}

		if(curWord != "")
		{
			textRows.back() += curWord;
		}
		updateWidestLine();

		lineOffset.clear();
		for(size_t i = 0; i < textRows.size(); ++i)
		{
			switch(getTextAlignment())
			{
			case ALIGN_LEFT:
				lineOffset.push_back(0);
				break;
			case ALIGN_CENTER:
				lineOffset.push_back((AdjWidthMinusVoffset - 
					getTextWidth(textRows[i])) / 2);
				break;
			case ALIGN_RIGHT:
				lineOffset.push_back(AdjWidthMinusVoffset - 
					getTextWidth(textRows[i]));
				break;
			}
			
		}
	}

	void TextBox::setWheelScrollRate( int rate )
	{
		pChildVScroll->setMouseWheelAmount(rate);
	}

	int TextBox::getWheelScrollRate() const
	{
		return pChildVScroll->getMouseWheelAmount();
	}

	void TextBox::mouseWheelDown( MouseEvent &mouseEvent )
	{	
		pChildVScroll->wheelScrollDown(mouseEvent.getMouseWheelChange());
		if(isVScrollNeeded())
		{
			mouseEvent.consume();
		}
	}

	void TextBox::mouseWheelUp( MouseEvent &mouseEvent )
	{
		pChildVScroll->wheelScrollUp(mouseEvent.getMouseWheelChange());

		if(isVScrollNeeded())
		{
			mouseEvent.consume();
		}
	}

	int TextBox::getCaretRow() const
	{
		return int(caretRow);
	}

	int TextBox::getCaretColumn() const
	{
		return int(caretColumn);
	}

	int TextBox::getCaretRowLocation() const
	{
		return caretRowLocation;
	}

	int TextBox::getCaretColumnLocation() const
	{
		return caretColumnLocation;
	}

	void TextBox::relocateCaret()
	{
		if(caretRow >= (int)textRows.size())
		{
			caretRow = int(textRows.size()) - 1;
			int rowLen = int(unicodeFunctions.length(textRows[caretRow]));
			if(caretColumn > rowLen)
			{
				caretColumn = rowLen;
			}
		}
		if(textRows.size() <= 0)
		{
			caretColumnLocation = getHorizontalOffset();
			caretRowLocation = getVerticalOffset();
			return;
		}
		caretColumnLocation = getTextWidth(unicodeFunctions.subStr(textRows[getCaretRow()],
			0,getCaretColumn())) + getHorizontalOffset() + getLineOffset(getCaretRow());

		caretRowLocation = getVerticalOffset() + (getCaretRow() * getLineHeight());
	}

	void TextBox::positionCaret( int column, int row)
	{
		if(textRows.empty())
		{
			caretRow = 0;
			caretColumn = 0;
			caretColumnLocation = getHorizontalOffset();
			caretRowLocation = getVerticalOffset();

			return;
		}

		if(caretRow >= (int)textRows.size())
		{
			caretRow = int(textRows.size() - 1);
			int rowLen = int(unicodeFunctions.length(textRows[caretRow]));
			if(caretColumn > rowLen)
			{
				caretColumn = rowLen;
			}
		}

			if(row >= (int)textRows.size())
			{

				row = (int)textRows.size() - 1;
			}
			if(row < 0)
			{
				row = 0;
			}


			if(column > (int)unicodeFunctions.length(textRows[row]))
			{
				column = (int)unicodeFunctions.length(textRows[row]);
			}

			if(column < 0)
			{
				column = 0;
			}


		caretColumn = column;
		caretRow = row;
		relocateCaret();
		scrollToCaret();
	}

	void TextBox::scrollToCaret()
	{

		//handle row
		int hoffset = 0;
		if(pChildHScroll->isVisible())
		{
			hoffset = pChildHScroll->getHeight();
		}

		int rowLoc = (getCaretRow() * getLineHeight()) + getLineHeight();

		if(rowLoc + getVerticalOffset() - getTopPadding() + hoffset > getAdjustedHeight())
		{
			pChildVScroll->setValue((rowLoc - getAdjustedHeight()) + hoffset);
		}

		rowLoc -= getLineHeight();
		
		rowLoc += getVerticalOffset();
		rowLoc -= getTopPadding();

		if(rowLoc < 0)
		{
			pChildVScroll->setValue(pChildVScroll->getValue() + rowLoc);
		}

		//handle column
		int vscrollOffset = 0;
		if(pChildVScroll->isVisible())
		{
			vscrollOffset = pChildVScroll->getWidth();
		}

		int retOffset = 0;
		if(getTextLength() == 0 || getCaretColumn() == 0)
		{
			pChildHScroll->setValue(retOffset);
			return;
		}

		//do we need to move?
		if(getTextWidth(unicodeFunctions.subStr(textRows[getCaretRow()],
			0,getCaretColumn())) > pChildHScroll->getValue() + getAdjustedWidth()
			- vscrollOffset)
		{

			//scroll to end
			if((int)unicodeFunctions.length(textRows[getCaretRow()]) < getCaretColumn() + maxSkip)
			{

				retOffset += getTextWidth(textRows[getCaretRow()]) - getAdjustedWidth() + vscrollOffset; 
			}
			else
			{
				retOffset += getTextWidth(unicodeFunctions.subStr(textRows[getCaretRow()],
					0, getCaretColumn() + maxSkip )) - getAdjustedWidth() + vscrollOffset;
			}

			pChildHScroll->setValue(retOffset);

		}
		else if(-pChildHScroll->getValue() + getTextWidth(unicodeFunctions.subStr(textRows[getCaretRow()],
			0,getCaretColumn())) <= leftPadding)
		{

			if(getCaretColumn() - maxSkip > 0)
			{
				retOffset += getTextWidth(unicodeFunctions.subStr(textRows[getCaretRow()],
					0, getCaretColumn() - maxSkip )) ;
			}

			pChildHScroll->setValue(retOffset);
		}

	}

	void TextBox::changeTextOffset()
	{
		horizontalOffset = -pChildHScroll->getValue() + getLeftPadding();
		verticalOffset = -pChildVScroll->getValue() + getTopPadding();
	}

	void TextBox::keyDown( KeyEvent &keyEvent )
	{
		handleKeyboard(keyEvent);
	}

	int TextBox::columnFromPreviousRow( int row, int newRow, int column ) const
	{
		//used to make the caret descent or ascent look natural

		int oldRowWidth = getTextWidth(unicodeFunctions.subStr(textRows[row],0,column));

		return getFont()->getStringIndexFromPosition(textRows[newRow],oldRowWidth + getLineOffset(row) - getLineOffset(newRow));
	}

	void TextBox::keyRepeat( KeyEvent &keyEvent )
	{
		handleKeyboard(keyEvent);
	}

	void TextBox::setFont( const Font *font )
	{
		int index = indexFromColumnRow(getCaretColumn(),getCaretRow());
		Widget::setFont(font);
		updateText();
		updateScrollBars();
		Point newIndex = columnRowFromIndex(index);
		setSelection(getSelectionStart(),getSelectionEnd());
		mousePositionCaret(newIndex);
	}

	void TextBox::mouseDown( MouseEvent &mouseEvent )
	{
		if(mouseEvent.getButton() != MOUSE_BUTTON_LEFT)
		{
			return;
		}
		dragged = false;

		//relative mouse position
		Point p = Point(mouseEvent.getX(),
			mouseEvent.getY());

		Point columnRow = columnRowFromRelPosition(p);

		mousePositionCaret(columnRow);
		mouseDownIndex = indexFromColumnRow(columnRow.getX(),columnRow.getY());

		setSelection(0,0);
		mouseEvent.consume();
	}

	Point TextBox::columnRowFromRelPosition( const Point &pos ) const
	{
		if(getLineHeight() == 0)
		{
			return Point(0,0);
		}

		int x = pos.getX();
		int y = pos.getY();

		y += pChildVScroll->getValue();
		y -= getTopPadding();
		y -= getMargin(SIDE_TOP);

		int row = y / getLineHeight();
		int column = 0;


		if(row >= (int)textRows.size())
		{
			row = (int)(textRows.size() - 1);
		}

		if(row < 0)
		{
			row = 0;
		}
		x -= getLeftPadding();
		x -= getMargin(SIDE_LEFT);
		x += pChildHScroll->getValue();
		x -= getLineOffset(row);

		column = getFont()->getStringIndexFromPosition(textRows[row],x);
		return Point(column,row);

	}


	void TextBox::focusGained()
	{
		Widget::focusGained();

		setBlinking(true);
		invalidateBlink();
	}


	int TextBox::indexFromColumnRow( int column, int row) const
	{
		size_t rowLen = 0;

		int retIndex = -1;
		int bytesSkipped = 0;
		int curCharLen = 0;
		size_t ind = 0;

		
		//decrement column so that the lowest is -1
		column--;
		if(textRows.size() == 0 || (column == -1 && row == 0))
		{
			//not in the text
			return -1;
		}
		for(size_t i = 0; i < textRows.size(); ++i)
		{
			//get length of row
            rowLen = rowLengths[i];

			//handle -1th case

			//get next character
		
				curCharLen = int(unicodeFunctions.bringToNextUnichar(ind,getText()));
				//only increase for newlines
				if(getText()[bytesSkipped] != '\n')
				{
					bytesSkipped -= curCharLen;
					ind -= curCharLen;
				}
				else
				{
					retIndex++;
				}


				bytesSkipped += curCharLen;

		
			if((int)i == row && column == -1)
			{
				return retIndex;
			}

			
			for(size_t j = 0; j < rowLen; ++j)
			{
				//get next character
			
					curCharLen = int(unicodeFunctions.bringToNextUnichar(ind,getText()));
					bytesSkipped += curCharLen;

					retIndex++;

				if((int)i == row && (int)j == column)
				{
					return retIndex;
				}
			}
		}

		return retIndex;
	}

	Point TextBox::columnRowFromIndex( int index) const
	{
		size_t rowLen = 0;

		int retIndex = -1;
		size_t bytesSkipped = 0;
		size_t curCharLen = 0;
		size_t ind = 0;

		if(textRows.size() == 0 || index == -1)
		{
			//not in the text
			return Point(0,0);
		}
		for(size_t i = 0; i < textRows.size(); ++i)
		{
			//get length of row
			rowLen = rowLengths[i];

		
			if(index == retIndex)
			{
				return Point(0, int(i));
			}


			for(size_t j = 0; j < rowLen; ++j)
			{
				//get next character
					curCharLen = unicodeFunctions.bringToNextUnichar(ind, getText());
					bytesSkipped += curCharLen;

					retIndex++;

				if(retIndex == index)
				{
					return Point(int(j + 1) , int(i));
				}
			}

			//handle -1th case

			//get next character
				curCharLen = unicodeFunctions.bringToNextUnichar(ind, getText());

				//only increase for newlines
				if(getText()[bytesSkipped] != '\n')
				{
					bytesSkipped -= curCharLen;
					retIndex--;
					ind -= curCharLen;
				}
				bytesSkipped += curCharLen;
				retIndex++;

			
		}

		return Point(int(rowLen) , int(textRows.size() - 1));
	}

	void TextBox::mousePositionCaret(const Point& pos ) 
	{
		if(textRows.empty())
		{
			caretRow = 0;
			caretColumn = 0;
			caretColumnLocation = getHorizontalOffset();
			caretRowLocation = getVerticalOffset();

			return;
		}

		caretColumn = pos.getX();
		caretRow = pos.getY();
		relocateCaret();
		scrollToCaret();
	}

	void TextBox::keyPositionCaret( int column, int row)
	{
		if(textRows.empty())
		{
			caretRow = 0;
			caretColumn = 0;
			caretColumnLocation = getHorizontalOffset();
			caretRowLocation = getVerticalOffset();

			return;
		}

		if(caretRow >= (int)textRows.size())
		{
			caretRow = int(textRows.size()) - 1;
			int rowLen = getRowLength(caretRow);
			if(caretColumn > rowLen)
			{
				caretColumn = rowLen;
			}
		}

		if(row >= (int)textRows.size())
		{

			row = (int)textRows.size() - 1;
		}
		if(row < 0)
		{
			row = 0;
		}



		if( isWordWrap() && isStandardArrowKeyRules() && row == caretRow && 
			column > getRowLength(caretRow) - 1 &&
			row + 1 < (int)textRows.size() &&
			getRowLength(caretRow) > 0)
		{
			if(column > 0)
			{
				
				if(column == getRowLength(caretRow) && 
					(getTextLineAt(row)[getTextLineAt(row).length() - 1] != '\n'))
				{
					column = 0;
					row++;
				}
				else if(column > getRowLength(caretRow) && 
					(getTextLineAt(row)[getTextLineAt(row).length() - 1] != '\n'))
				{
					int ind = indexFromColumnRow(getRowLength(caretRow),caretRow) + 1;
					if(ind < getTextLength() && unicodeFunctions.subStr(getText(),ind,1) == "\n")
					{
						column = 0;
					}
					else
					{
						column = 1;
					}
					
					row++;
				}
				else if(column > getRowLength(caretRow))
				{
					column = 0;
					row++;
				}
			}

		}
		else if(isWordWrap() && isStandardArrowKeyRules() && row == caretRow && caretRow > 0 && column < 0)
		{
			row--;
			if(getTextLineAt(row).length() > 0 &&
				(getTextLineAt(row)[getTextLineAt(row).length() - 1] != '\n'))
			{
				int ind = indexFromColumnRow(getRowLength(row),row) + 1;
				if(ind < getTextLength() && unicodeFunctions.subStr(getText(),ind,1) == "\n")
				{
					column = getRowLength(row);
				}
				else
				{
					column = getRowLength(row) - 1;
				}
			}
			else
			{
				column = getRowLength(row);
			}
			
		}
		else if (column > getRowLength(caretRow) &&
			row + 1 < (int)textRows.size())
		{
			if(column > 0)
			{
				row++;
				column = 0;
			}

		}
		else if( caretRow > 0 && column < 0)
		{
			row--;
			column = getRowLength(row);
		}
		else if(row != caretRow)
		{
			column = columnFromPreviousRow(caretRow,row,column);
		}

		if(column > getRowLength(row))
		{
			column = (int)getRowLength(row);
		}

		if(column < 0)
		{
			column = 0;
		}


		caretColumn = column;
		caretRow = row;
		relocateCaret();
		scrollToCaret();
	}

	void TextBox::sizePositionCaret(const Point& pos )
	{
		if(textRows.empty())
		{
			caretRow = 0;
			caretColumn = 0;
			caretColumnLocation = getHorizontalOffset();
			caretRowLocation = getVerticalOffset();

			return;
		}

		caretColumn = pos.getX();
		caretRow = pos.getY();
		relocateCaret();
	}

	void TextBox::updateWidestLine()
	{

		if(isWordWrap())
		{
			widestLine = 0;
			return;
		}

		int h = 0;
		int curH = 0;
		for(int i = 0; i < (int)textRows.size(); ++i)
		{
			curH = getTextWidth(textRows[i]);
			if(curH > h)
			{
				h = curH;
			}
		}

		widestLine = h;
	}

	bool TextBox::isWordWrap() const
	{
		return wordWrap;
	}

	void TextBox::setWordWrap( bool wordWrap )
	{
		if(wordWrap == this->wordWrap)
		{
			return;
		}

		this->wordWrap = wordWrap;
		updateText();
		updateScrollBars();

		for(std::vector<TextBoxListener*>::iterator it = 
			textBoxListeners.begin();
			it != textBoxListeners.end(); ++it)
		{
			if((*it))
				(*it)->wordWrappedChanged(this,wordWrap);
		}
	}

	void TextBox::handleKeyboard( const KeyEvent &keyEvent )
	{


		if(handleHotkeys(keyEvent))
		{
			return;
		}

		if(keyEvent.getExtendedKey() == EXT_KEY_UP)
		{
			handleArrowKey(keyEvent,getCaretColumn(),getCaretRow() - 1);
			return;
		}
		else if(keyEvent.getExtendedKey() == EXT_KEY_DOWN)
		{
			handleArrowKey(keyEvent,getCaretColumn(),getCaretRow() + 1);
			return;
		}
		else if(keyEvent.getExtendedKey() == EXT_KEY_LEFT)
		{
			handleArrowKey(keyEvent,getCaretColumn() - 1,getCaretRow());
			return;
		}
		else if(keyEvent.getExtendedKey() == EXT_KEY_RIGHT)
		{
			handleArrowKey(keyEvent,getCaretColumn() + 1,getCaretRow());
			return;
		}
		else if(keyEvent.getKey() == KEY_BACKSPACE && !isReadOnly())
		{
			if(getCaretColumn() == 0 && getCaretRow() == 0 && isSelectionEmpty())
			{
				return;
			}

			setBlinking(true);
			invalidateBlink();

			if(!isSelectionEmpty())
			{
				deleteSelection();
				return;
			}
			removeLastCharacter();
		}
		else if(keyEvent.getKey() == KEY_DELETE && !isReadOnly())
		{
			if(indexFromColumnRow(
				getCaretColumn(),getCaretRow()) == getTextLength() - 1 
				&& isSelectionEmpty())
			{
				return;
			}

			setBlinking(true);
			invalidateBlink();

			if(!isSelectionEmpty())
			{
				deleteSelection();
				return;
			}
			removeNextCharacter();
		}
		else if(keyEvent.getKey() == KEY_ENTER && !isReadOnly())
		{
			setBlinking(true);
			invalidateBlink();

			if(!isSelectionEmpty())
			{
				deleteSelection();
			}

			addToNextCharacter('\n');
		}
		else if(keyEvent.getKey() == KEY_TAB && keyEvent.control() && !isReadOnly())
		{
			setBlinking(true);
			invalidateBlink();

			if(!isSelectionEmpty())
			{
				deleteSelection();
			}

			appendText("    ");
		}
		else if(keyEvent.getUnichar() >= ' ' && !isReadOnly())
		{
			setBlinking(true);
			invalidateBlink();

			if(!isSelectionEmpty())
			{
				deleteSelection();
			}
			addToNextCharacter(keyEvent.getUnichar());
		}


	}

	int TextBox::removeLastCharacter()
	{
			if(getText().length() == 0)
			{
				return -1;
			}

			int index = indexFromColumnRow(getCaretColumn(),getCaretRow());
			if(index < getTextLength() && index >= 0)
			{
				std::string *text = (std::string*)&getText();
				unicodeFunctions.erase(*text,index,1);
				setThisText(*text);
			
				index--;

				Point p = columnRowFromIndex(index);

				mousePositionCaret(p);

				return index + 1;
				
				
			}
			return -1;
	}

	int TextBox::removeNextCharacter()
	{
		if(getText().length() == 0)
		{
			return -1;
		}
		int index = indexFromColumnRow(getCaretColumn(),getCaretRow());
		int startIndex = index;
		int textLen = getTextLength();

		index++;
		
		if(index >= textLen)
		{
			return -1;
		}

		std::string text = getText();
		unicodeFunctions.erase(text,index,1);
		setThisText(text);
		Point p = columnRowFromIndex(startIndex);
		sizePositionCaret(p);

		return index;
	}

	int TextBox::addToNextCharacter( int unichar)
	{
		char buffer[8];
		for(int i = 0; i < 8; ++i)
		{
			buffer[i] = 0;
		}

		unicodeFunctions.encodeUtf8(buffer,unichar);
		std::string character = buffer;


		if(character.length() == 0)
		{
			return -1;
		}
		std::string *text = (std::string *)&getText();
		
		int index = indexFromColumnRow(getCaretColumn(),getCaretRow());

		index++;
		unicodeFunctions.insert(*text,index,character);
		setThisText(*text);

		Point p = columnRowFromIndex(index);

		mousePositionCaret(p);

		return index;
	}

	bool TextBox::isReadOnly() const
	{
		return readOnly;
	}

	void TextBox::setReadOnly( bool readOnly )
	{
		if(readOnly == this->readOnly)
		{
			return;
		}

		this->readOnly = readOnly;
		for(std::vector<TextBoxListener*>::iterator it = 
			textBoxListeners.begin();
			it != textBoxListeners.end(); ++it)
		{
			if((*it))
				(*it)->readOnlyChanged(this,readOnly);
		}
	}

	bool TextBox::getDrawBorder() const
	{
		return this->drawBorder;
	}

	void TextBox::setDrawBorder( bool drawBorder )
	{
		this->drawBorder = drawBorder;
	}

	void TextBox::setMaxCharacterSkip( int val )
	{
		if(val < 1)
		{
			val = 1;
		}
		if(maxSkip == val)
		{
			return;
		}

		maxSkip = val;

		for(std::vector<TextBoxListener*>::iterator it = 
			textBoxListeners.begin();
			it != textBoxListeners.end(); ++it)
		{
			if((*it))
				(*it)->maxCharacterSkippedChanged(this,val);
		}
	}

	int TextBox::getMaxCharacterSkip() const
	{
		return maxSkip;
	}

	void TextBox::mouseDrag( MouseEvent &mouseEvent )
	{
		if(mouseEvent.getButton() != MOUSE_BUTTON_LEFT ||
			!isSelectable())
		{
			return;
		}
		
		dragged = true;
		//relative mouse position
		Point p = Point(mouseEvent.getX(),
			mouseEvent.getY());

		Point columnRow = columnRowFromRelPosition(p);
		mousePositionCaret(columnRow);

		setSelection(mouseDownIndex + 1,indexFromColumnRow(
			columnRow.getX(),columnRow.getY()) + 1);
		mouseEvent.consume();
	}

	void TextBox::paintBackground( const PaintEvent &paintEvent )
	{
		paintEvent.graphics()->drawFilledRectangle(getSizeRectangle(),getBackColor());

		if(!this->getDrawBorder())
			return;

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

	const std::pair<Point,Point>& TextBox::getSelLineAt( int line ) const
	{
		return selPts[line];
	}

	int TextBox::getSelLineCount() const
	{
		return int(selPts.size());
	}


	void TextBox::setSelection( int startIndex, int endIndex )
	{
		if(!isSelectable())
		{
			if(selectionIndexes.getX() != 0 ||
				selectionIndexes.getY() != 0)
			{
				startIndex = 0;
				endIndex = 0;
			}
			else
			{
				return;
			}
		}

		//no selection
		if(startIndex == endIndex)
		{
			selPts.clear();
			selectionIndexes = Point(0,0);
			for(std::vector<TextBoxListener*>::iterator it = 
				textBoxListeners.begin();
				it != textBoxListeners.end(); ++it)
			{
				if((*it))
					(*it)->selectionChanged(this,0,0);
			}
			return;
		}
		//perform checks

		//swap so that the order is smallest to largest
		if(startIndex > endIndex)
		{
			int temp = startIndex;
			startIndex = endIndex;
			endIndex = temp;
		}

		//index bound checks

		if(startIndex < 0)
		{
			startIndex = -1;
		}

		if(endIndex > getTextLength())
		{
			endIndex = getTextLength() - 1;
		}

		//clear the selection
		selPts.clear();

		//get column row from index
		Point startColRow = columnRowFromIndex(startIndex - 1);
		Point endColRow = columnRowFromIndex(endIndex - 1);

		int colBegin = 0;
		int colEnd = 0;

		//only make the selection lines that are visible
		int linesSkipped = getVisibleLineStart();
		int maxitems =     getVisibleLineCount();

		int bottomItem = linesSkipped + maxitems;

		int rowBegin;
		int rowEnd;

		//ensure only visible rows are made
		rowBegin = linesSkipped > startColRow.getY() ? linesSkipped : startColRow.getY();
		rowEnd = bottomItem < endColRow.getY() ? bottomItem : endColRow.getY();

		for(int i = rowBegin; i <= rowEnd; ++i)
		{
			//push a new row
			selPts.push_back(std::pair<Point,Point>());

			//only a start position for the first row
			if(i > startColRow.getY())
			{
				colBegin = 0;
			}
			else
			{
				colBegin = startColRow.getX();
			}

			//only an end position for the last row
			if(i < endColRow.getY())
			{
				colEnd = int(unicodeFunctions.length(textRows[i]));
			}
			else
			{
				colEnd = endColRow.getX();
			}

			//top left
			if(textRows[i].length() > 0)
			{
				selPts.back().first = Point(
					getTextWidth(unicodeFunctions.subStr(
					textRows[i],0,colBegin)) + lineOffset[i],
					getLineHeight() * i );
			}
			else //render newline as space
			{
				selPts.back().first = Point(
					getTextWidth(" ") + lineOffset[i],
					getLineHeight() * i );
			}
		
			//bottom right
			selPts.back().second = Point(
				getTextWidth(unicodeFunctions.subStr(
				textRows[i],0,colEnd)) - selPts.back().first.getX() + lineOffset[i],
				(getLineHeight()));
		}

		//set selection index
		selectionIndexes = Point(startIndex,endIndex);

		for(std::vector<TextBoxListener*>::iterator it = 
			textBoxListeners.begin();
			it != textBoxListeners.end(); ++it)
		{
			if((*it))
				(*it)->selectionChanged(this,startIndex,endIndex);
		}

	}

	void TextBox::mouseUp( MouseEvent &mouseEvent )
	{
	
		dragged = false;
	}

	void TextBox::deleteSelection()
	{
		if(isSelectionEmpty())
		{
			return;
		}

		std::string *text = (std::string*)&getText();
		unicodeFunctions.erase(*text,getSelectionStart() ,
			getSelectionEnd() - getSelectionStart());

		Point cr = columnRowFromIndex(getSelectionStart() - 1);

		setThisText(*text);
		mousePositionCaret(cr);

		for(std::vector<TextBoxListener*>::iterator it = 
			textBoxListeners.begin();
			it != textBoxListeners.end(); ++it)
		{
			if((*it))
				(*it)->selectionDeleted(this);
		}
	}

	int TextBox::getLineHeight() const
	{
		return getFont()->getLineHeight();
	}

	int TextBox::getVisibleLineCount() const
	{
		if(getLineHeight() == 0)
		{
			return 0;
		}

		int hoffset = 0;
		if(pChildHScroll->isVisible())
		{
			hoffset = pChildHScroll->getHeight();
		}

		return ((getAdjustedHeight() - hoffset) / getLineHeight()) + 1;
	}

	int TextBox::getVisibleLineStart() const
	{
		if(getLineHeight() == 0)
		{
			return 0;
		}
		return pChildVScroll->getValue() / getLineHeight();
	}

	int TextBox::getSelectionStart() const
	{
		return selectionIndexes.getX();
	}

	int TextBox::getSelectionEnd() const
	{
		return selectionIndexes.getY();
	}

	bool TextBox::isSelectionEmpty() const
	{
		return getSelectionStart() == getSelectionEnd();
	}

	int TextBox::getTextLineCount() const
	{
		return int(textRows.size());
	}

	const std::string& TextBox::getTextLineAt( int line ) const
	{
		return textRows[line];
	}

	bool TextBox::isHScrollVisible() const
	{
		return pChildHScroll->isVisible();
	}

	bool TextBox::isVScrollVisible() const
	{
		return pChildVScroll->isVisible();
	}

	const Dimension& TextBox::getHSrollSize() const
	{
		return pChildHScroll->getSize();
	}

	const Dimension& TextBox::getVScrollSize() const
	{
		return pChildVScroll->getSize();
	}

	int TextBox::getRowLength( int row ) const
	{
		return rowLengths[row];
	}

	void TextBox::handleArrowKey( const KeyEvent &keyEvent, int column, int row )
	{
		
		int curIndex = 0;
		if(keyEvent.shift())
		{
			curIndex = indexFromColumnRow(getCaretColumn(),getCaretRow());
		}

		int oldRow = getCaretRow();
		int oldColumn = getCaretColumn();

		keyPositionCaret(column,row);
		if(getCaretRow() != oldRow || getCaretColumn() != oldColumn)
		{
			setBlinking(true);
			invalidateBlink();
		}
		if(keyEvent.shift())
		{
			int newIndex = indexFromColumnRow(getCaretColumn(),getCaretRow());
			if(curIndex == newIndex)
			{
				return;
			}
			if(isSelectionEmpty())
			{
				setSelection(curIndex + 1,newIndex + 1);
			}
			else
			{
				
				if((curIndex + 1 == getSelectionEnd()))
				{
					setSelection(getSelectionStart(),newIndex + 1);
				}
				else
				{
					setSelection(getSelectionEnd(),newIndex + 1);
				}
			}
		}
		else
		{
			setSelection(0,0);
		}
	}

	bool TextBox::isSplittingWords() const
	{
		return splittingWords;
	}

	void TextBox::setSplittingWords( bool splitting )
	{
		if(splitting == splittingWords)
		{
			return;
		}

		splittingWords = splitting;
		updateText();
		updateScrollBars();

		for(std::vector<TextBoxListener*>::iterator it = 
			textBoxListeners.begin();
			it != textBoxListeners.end(); ++it)
		{
			if((*it))
				(*it)->splittingWordsChanged(this,splitting);
		}
	}

	bool TextBox::isStandardArrowKeyRules() const
	{
		return standardArrowKeyRules;
	}

	void TextBox::setStandardArrowKeyRules( bool rules )
	{
		if(rules == standardArrowKeyRules)
		{
			return;
		}
		standardArrowKeyRules = rules;
		for(std::vector<TextBoxListener*>::iterator it = 
			textBoxListeners.begin();
			it != textBoxListeners.end(); ++it)
		{
			if((*it))
				(*it)->standardArrowKeyRulesChanged(this,rules);
		}
	}

	void TextBox::appendText( const std::string &text, bool atCurrentPosition /*= true*/,
								 bool repositionCaret /*= true*/ )
	{
		int length = int(unicodeFunctions.length(text));
		int numRemainingChar = getMaxLength() - getTextLength() + getSelectionLength();

		if(numRemainingChar == 0)
		{
			return;
		}

		size_t index = 0;
		if(atCurrentPosition)
		{
			index = indexFromColumnRow(getCaretColumn(),getCaretRow()) + 1;
		}
		else
		{
			index = getTextLength();
		}
	
		//ensure we don't go over the max length
		std::string *txt = (std::string*)&getText();
		if(numRemainingChar < length)
		{
			std::string shrunk = text;
			shrunk = unicodeFunctions.subStr(shrunk,0,numRemainingChar);
			length = numRemainingChar;
			unicodeFunctions.insert(*txt,index,shrunk);
		}
		else
		{
			unicodeFunctions.insert(*txt,index,text);
		}
		
		setThisText(*txt);

		if(repositionCaret)
		{
			int len = int(unicodeFunctions.length(text));
			int newIndex = int(index - 1) + len;
			mousePositionCaret(columnRowFromIndex(newIndex));
		}

		for(std::vector<TextBoxListener*>::iterator it = 
			textBoxListeners.begin();
			it != textBoxListeners.end(); ++it)
		{
			if((*it))
				(*it)->textAppended(this,text);
		}
	}

	std::string TextBox::getSelectedText() const
	{
		if(isSelectionEmpty())
		{
			return "";
		}
		return unicodeFunctions.subStr(getText(),getSelectionStart() ,getSelectionLength());
	}

	int TextBox::getSelectionLength() const
	{
		return getSelectionEnd() - getSelectionStart();
	}

	int TextBox::getLineOffset( int line ) const
	{
		if(line < 0 || line >= (int)lineOffset.size())
		{
			return 0;
		}

		return lineOffset[line];
	}

	void TextBox::setTextAlignment( AlignmentEnum align )
	{
		textAlignment = align;
		if(isWordWrap())
		{
			updateText();
			Point p = columnRowFromIndex(indexFromColumnRow(getCaretColumn(),getCaretRow()));
			sizePositionCaret(p);
		}
		setSelection(getSelectionStart(),getSelectionEnd());
		updateScrollBars();
	}

	AlignmentEnum TextBox::getTextAlignment() const
	{
		return textAlignment;
	}

	bool TextBox::intersectionWithPoint( const Point &p ) const
	{
		return Rectangle(getMargin(SIDE_LEFT),
			getMargin(SIDE_TOP),getInnerWidth(),getInnerHeight()).pointInside(p);
	}

	void TextBox::logic( double timeElapsed )
	{
		processBlinkEvent(timeElapsed);
	}

	int TextBox::getTextWidth( const std::string &text ) const
	{
		return getFont()->getTextWidth(text);
	}

	void TextBox::setSelectionBackColor( const Color &color )
	{
		selectionBackColor = color;
	}

	const Color& TextBox::getSelectionBackColor() const
	{
		return selectionBackColor;
	}

  void TextBox::setFrameColor(const Color& color)
  {
    this->frameColor = color;
  }

  const Color& TextBox::getFrameColor() const
  {
    return this->frameColor;
  }

	void TextBox::selectAll()
	{
		setSelection(0,getTextLength());
		mousePositionCaret(columnRowFromIndex(getTextLength()));
	}

	bool TextBox::isHidingSelection() const
	{
		return hideSelection;
	}

	void TextBox::setHideSelection( bool hide )
	{
		if(hide == hideSelection)
		{
			return;
		}
		hideSelection = hide;

		for(std::vector<TextBoxListener*>::iterator it = 
			textBoxListeners.begin();
			it != textBoxListeners.end(); ++it)
		{
			if((*it))
				(*it)->hidingSelectionChanged(this,hide);
		}
	}

	void TextBox::setThisText( const std::string &text )
	{
		selfSetText = true;
		setText(text);
		selfSetText = false;
	}

	bool TextBox::isSelfSettingText() const
	{
		return selfSetText;
	}

	int TextBox::getMaxLength() const
	{
		return maxLength;
	}

	void TextBox::setMaxLength( int length )
	{
		maxLength = length;
		setThisText(getText());

		for(std::vector<TextBoxListener*>::iterator it = 
			textBoxListeners.begin();
			it != textBoxListeners.end(); ++it)
		{
			if((*it))
				(*it)->maxLengthChanged(this,length);
		}
	}

	void TextBox::addTextBoxListener( TextBoxListener* listener )
	{
		if(!listener)
		{
			return;
		}
		for(std::vector<TextBoxListener*>::iterator it = 
			textBoxListeners.begin();
			it != textBoxListeners.end(); ++it)
		{
			if((*it) == listener)
				return;
		}

		textBoxListeners.push_back(listener);
	}

	void TextBox::removeTextBoxListener( TextBoxListener* listener )
	{
		textBoxListeners.erase(
			std::remove(textBoxListeners.begin(),
			textBoxListeners.end(), listener),
			textBoxListeners.end());
	}


	void TextBox::setSelectable( bool select )
	{
		if(select == selectable)
		{
			return;
		}
		selectable = select;
		if(!select)
		{
			setSelection(0,0);
		}
	}

	bool TextBox::isSelectable() const
	{
		return selectable;
	}

	void TextBox::resizeToContents()
	{
		int vscroll = 0;
		int hscroll = 0;
    updateWidestLine();
		if(getVScrollPolicy() == SHOW_ALWAYS)
		{
			vscroll = pChildVScroll->getWidth();
		}
		if(getHScrollPolicy() == SHOW_ALWAYS)
		{
			hscroll = pChildHScroll->getWidth();
		}

		if(isWordWrap())
		{
			setSize(getWidth(), getContentHeight() + 
				getTopPadding() + 
				getBottomPadding() +
				getMargin(SIDE_TOP) +
				getMargin(SIDE_BOTTOM) +
				hscroll);
		}
		else
		{
			setSize(getContentWidth() +
				getLeftPadding() +
				getRightPadding() +
				getMargin(SIDE_LEFT) +
				getMargin(SIDE_RIGHT) +
				vscroll,
				getContentHeight() + 
				getTopPadding() + 
				getBottomPadding() +
				getMargin(SIDE_TOP) +
				getMargin(SIDE_BOTTOM) +
				hscroll);
		}
	}

	bool TextBox::wantsHotkeys() const
	{
		return hotkeys;
	}

	void TextBox::setWantHotkeys( bool hotkeysEnabled )
	{
		hotkeys = hotkeysEnabled;
	}

	bool TextBox::handleHotkeys(const KeyEvent &keyEvent )
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
    
    bool TextBox::canAcceptKeyInput() const
    {
        return !isReadOnly();
    }
    
    bool TextBox::isTextBox() const
    {
        return true;
    }

	void TextBox::cut()
	{
		if(getSelectionLength() > 0)
		{
			copy();
			deleteSelection();
		}
	}

	void TextBox::copy()
	{
		if(getSelectionLength() > 0)
		{
			Clipboard::copy(getSelectedText());
		}
	}

	void TextBox::paste()
	{
		if(isReadOnly())
		{
			return;
		}

		std::string pasteResult = Clipboard::paste();

		if(pasteResult.length() == 0)
		{
			return;
		}

		deleteSelection();
		appendText(pasteResult,true,true);
		
	}

	CursorProvider::CursorEnum TextBox::getEnterCursor() const
	{
		return CursorProvider::EDIT_CURSOR;
	}

}
