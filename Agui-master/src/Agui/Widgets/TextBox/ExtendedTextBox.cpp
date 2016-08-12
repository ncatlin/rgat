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

#include "Agui/Widgets/TextBox/ExtendedTextBox.hpp"
#include <algorithm>
namespace agui {
	ExtendedTextBox::~ExtendedTextBox(void)
	{
	}


	ExtendedTextBox::ExtendedTextBox( HScrollBar *hScroll /*= NULL*/, 
		VScrollBar *vScroll /*= NULL*/, Widget* scrollInset /*= NULL*/ )
		: TextBox(hScroll,vScroll,scrollInset),isEditingText(false), colorIndexStart(0,0),
		currentColorChanged(false),selFontColor(false)
	{
		currentColor = getFontColor();
		selectionFontColor = Color(255,255,255);
		emoticonChar = "W";
	}

	void ExtendedTextBox::paintComponent( const PaintEvent &paintEvent )
	{
		int textX = getHorizontalOffset();
		int textY = getVerticalOffset();
		int voffset = 0;
		int hoffset = 0;
		if(isHScrollVisible())
		{
			hoffset = getHSrollSize().getHeight();
		}
		if(isVScrollVisible())
		{

			voffset = getVScrollSize().getWidth();
		}


		paintEvent.graphics()->pushClippingRect(Rectangle(getLeftPadding(),
			getTopPadding(), getAdjustedWidth() - voffset + 1, getAdjustedHeight() - hoffset));

		//only show selection if it's not hidden
	if(!isHidingSelection() || (isHidingSelection() && isFocused()))
		for(int i = 0; i < getSelLineCount(); ++i)
		{
			paintEvent.graphics()->drawFilledRectangle(Rectangle(
				getSelLineAt(i).first.getX() + textX,
				getSelLineAt(i).first.getY() + textY,
				getSelLineAt(i).second.getX(),
				getSelLineAt(i).second.getY()),getSelectionBackColor());
		}


		drawText(paintEvent);

		if(isFocused() && isBlinking())
			paintEvent.graphics()->drawLine(Point(getCaretColumnLocation() + 1 , getCaretRowLocation() ),
			Point(getCaretColumnLocation() + 1, getCaretRowLocation() + getLineHeight()),
			Color(0,0,0));

		paintEvent.graphics()->popClippingRect();
	}

	void ExtendedTextBox::valueChanged( VScrollBar* source, int val )
	{
		TextBox::valueChanged(source,val);
		setColorIndexStart();
	}

	void ExtendedTextBox::clearColors()
	{
		if(isEditingText)
		{
			return;
		}
		textColors.clear();

		for(size_t i = 0; i < textColors.size(); ++i)
		{
			textColors[i].first = getFontColor();
		}

	}

	const Point& ExtendedTextBox::getColorIndexStart() const
	{
		return colorIndexStart;
	}

	void ExtendedTextBox::setColorIndexStart()
	{

			int x;
			size_t y;
			x = indexFromColumnRow(0,getVisibleLineStart()) + 1;
			y = 0;
			for(int i = 0; i < x; ++i)
			{
				unicodeFunctions.bringToNextUnichar(y,getText());
			}
			colorIndexStart = Point(int(x), int(y));

	}

	void ExtendedTextBox::setText( const std::string &text )
	{
		//maintain

		if((int)unicodeFunctions.length(text) > getMaxLength())
		{
			Widget::setText(unicodeFunctions.subStr(text,0,getMaxLength()));
		}
		else
		{
			Widget::setText(text);
		}

		clearColors();
		updateText();
		updateScrollBars();
		setSelection(0,0);
		if(!isSelfSettingText())
		{
			mousePositionCaret(columnRowFromIndex(getTextLength()));
		}

		if(!isEditingText && textColors.size() == 0)
		{
			size_t uniPos = 0;
			int bytesSkipped = 0;
			std::string newStr;
			std::string curChar;
			size_t textLen = unicodeFunctions.length(text);


			for(size_t i = 0; i < textLen && (getTextLength() + i) < (size_t)getMaxLength(); ++i)
			{
				//get length of unichar
				int curLen = unicodeFunctions.bringToNextUnichar(uniPos,text);
				curStr = text.substr(bytesSkipped,curLen);
				bytesSkipped += curLen;

				Image* emoticon = getEmoticon(curStr);

				if(emoticon)
				{
					newStr += emoticonChar;
				}
				else
				{
					newStr += curStr;
				}

				textColors.insert(textColors.begin() + (i),std::make_pair(currentColor,emoticon));
			}

		}
	
	}

	int ExtendedTextBox::removeLastCharacter()
	{
		isEditingText = true;
		int index = TextBox::removeLastCharacter();
		isEditingText = false;

		if(index != -1)
		{
			textColors.erase(textColors.begin() + index);
		}
		return index;
	}

	int ExtendedTextBox::removeNextCharacter()
	{
		isEditingText = true;
		int index = TextBox::removeNextCharacter();
		isEditingText = false;

		if(index != -1)
		{
			textColors.erase(textColors.begin() + index);
		}
		return index;
	}

	void ExtendedTextBox::deleteSelection()
	{
		if(!isSelectionEmpty())
		{
			textColors.erase(textColors.begin() + (getSelectionStart()),
				textColors.begin() +( getSelectionStart())  + (getSelectionEnd() - getSelectionStart()));
		}
		

		isEditingText = true;
		TextBox::deleteSelection();
		isEditingText = false;
		
		
	}

	int ExtendedTextBox::addToNextCharacter( int unichar )
	{

		isEditingText = true;
		int index = TextBox::addToNextCharacter(unichar);
		isEditingText = false;

		if(index == -1)
		{
			return -1;
		}
		if(currentColorChanged)
		{
			currentColorChanged = false;
		}
		else
		{
			if(index - 1 >= 0 && index - 1 < (int)textColors.size())
			{
				currentColor = textColors[index - 1].first;
			}
			else if(index + 1 >= 0 && index + 1 < (int)textColors.size())
			{
				currentColor = textColors[index + 1].first;
			}
		}
		

		Image* img = NULL;
		textColors.insert(textColors.begin() + index,std::make_pair(currentColor,img));


		return index;
	}

	void ExtendedTextBox::setCurrentColor( const Color &color )
	{
		currentColor = color;
		currentColorChanged = true;
	}

	void ExtendedTextBox::setSelectionColor( const Color & color )
	{
		if(isSelectionEmpty())
		{
			return;
		}

		for(int i = getSelectionStart() ; i < getSelectionEnd(); ++i)
		{
			textColors[i].first = color;
		}
	}

	void ExtendedTextBox::setFont( const Font *font )
	{
		TextBox::setFont(font);
		lastVisibleIndex = -1;
		setColorIndexStart();
	}


	void ExtendedTextBox::appendText( const std::string &text, bool atCurrentPosition /* = true */,
										 bool repositionCaret /* = true */ )
	{
		int index = 0;
		if(atCurrentPosition)
		{
			index = indexFromColumnRow(getCaretColumn(),getCaretRow()) + 1;
		}
		else
		{
			index = getTextLength();
		}

		size_t uniPos = 0;
		int bytesSkipped = 0;
		std::string newStr;
		std::string curChar;
		size_t textLen = unicodeFunctions.length(text);
		

		for(size_t i = 0; i < textLen && (getTextLength() + i) < (size_t)getMaxLength(); ++i)
		{
			//get length of unichar
			int curLen = unicodeFunctions.bringToNextUnichar(uniPos,text);
			curStr = text.substr(bytesSkipped,curLen);
			bytesSkipped += curLen;
			
			Image* emoticon = getEmoticon(curStr);

			if(emoticon)
			{
				newStr += emoticonChar;
			}
			else
			{
				newStr += curStr;
			}

			textColors.insert(textColors.begin() + (i + index),std::make_pair(currentColor,emoticon));
		}
		

		isEditingText = true;
		TextBox::appendText(newStr,atCurrentPosition,repositionCaret);
		isEditingText = false;

		if(textLen > 0)
			currentColorChanged = false;
	}

	void ExtendedTextBox::updateText()
	{
		TextBox::updateText();
		setColorIndexStart();
	}

	void ExtendedTextBox::drawText( const PaintEvent &paintEvent )
	{
		/* start of crazy render procedure */

		//note: this won't work with Kerning so keep it off!

		int textX = getHorizontalOffset();
		int textY = getVerticalOffset();

		size_t curLen = 0;
		int curWidth = 0;
		int totalWidth = 0;
		size_t uniPos = 0;
		size_t colorUniPos = 0;
		size_t bytesSkipped = 0;


		int colorIndex = getColorIndexStart().getX();
		colorUniPos = getColorIndexStart().getY();
		int stopPos = 0;
		size_t stopUnichar;
		const Color *color;
		int selStart = 0; 
		int selEnd = 0; 

		if(!isHidingSelection() || (isHidingSelection() && isFocused()))
		{
			selStart = getSelectionStart() - 1;
			selEnd = getSelectionEnd() - 1;
		}

		int linesSkipped = getVisibleLineStart();
		int maxitems = getVisibleLineCount();
		for(int i = linesSkipped; i <= maxitems + linesSkipped; ++i)
		{
			int curColIndex = colorIndex;
			if(i >= getTextLineCount())
			{
				break;
			}
			uniPos = 0;
			bytesSkipped = 0;
			totalWidth = 0;

			int len = getRowLength(i);

			//increase color index if at newline
			if(getText()[colorUniPos] == '\n')
			{
				colorIndex++;

			}
			bool isSame = true;

			//check if line is same color
			//store result for later use and store stop position
			if(len == 1)
			{
				isSame = false;
				stopPos = len;
			}
			for(int x = len - 1; x > 0; --x)
			{
				//not null if emoticon is present
				if(textColors[colorIndex + x].first != textColors[colorIndex + x - 1].first ||
					textColors[colorIndex + x].second != NULL || textColors[colorIndex + x - 1].second != NULL)
				{
					isSame = false;
					stopPos = x;

					if(textColors[colorIndex + x].second != NULL || textColors[colorIndex + x - 1].second != NULL)
					{
						stopPos = len;
					}
					break;
				}
			}

			if(len == 0)
			{
				stopPos = 0;
			}

			//only use this method if the whole line is selected
			if(!isSelectionEmpty() && colorIndex + len >= selStart &&
				colorIndex <= selEnd &&
				!(colorIndex > selStart &&
				colorIndex + len < selEnd))
			{
				isSame = false;
				stopPos = len;
			}
			//if the whole line is the same color render it in one go
			if(isSame && len > 0 )
			{
				//white for selection
				if(colorIndex > selStart && colorIndex <= selEnd && isSelectionFontColorInUse())
				{
					color = &selectionFontColor;
				}
				else
				{
					color = &textColors[colorIndex].first;
				}

				paintEvent.graphics()->drawText(Point(textX + getLineOffset(i),
					textY + (i * getLineHeight())),
					getTextLineAt(i).c_str(),*color,getFont());

				//increase color index by how many unichars we drew
				colorIndex += len;

			}
			else //render char by char until last chunk
			{

				for(int j = 0; j < stopPos; ++j)
				{
					//get length of unichar
					curLen = unicodeFunctions.bringToNextUnichar(uniPos,getTextLineAt(i));

					//white for selection
					if(colorIndex > selStart && colorIndex <= selEnd && isSelectionFontColorInUse())
					{
						color = &selectionFontColor;
					}
					else
					{
						color = &textColors[colorIndex].first;
					}

					//extract current character
					curStr = getTextLineAt(i).substr(bytesSkipped,curLen);
					curWidth = getTextWidth(curStr);

					//increase byte count to keep track of where we are
					bytesSkipped += curLen;

					Image* img = textColors[colorIndex].second;
					if (img)
					{
						paintEvent.graphics()->drawScaledImage(
							img,
							Point(textX + totalWidth  + getLineOffset(i),
							textY + (i * getLineHeight())),
							Point(),Dimension(img->getWidth(),img->getHeight()),
							Dimension(curWidth,curWidth)
							);
					}
					else
					{
						//draw the char
						paintEvent.graphics()->drawText(Point(textX + totalWidth  + getLineOffset(i),
							textY + (i * getLineHeight())),
							curStr.c_str(),*color,getFont());
					}
			

					//increase the total width
					totalWidth += curWidth;

					colorIndex++;


				}
				//if we have 1 last chunk to draw, draw it
				if(stopPos < len && stopPos >= 0)
				{
					stopUnichar = 0;
					for(int x = 0; x < stopPos; ++x)
					{
						unicodeFunctions.bringToNextUnichar(stopUnichar,getTextLineAt(i));
					}
					//white for selection
					if(colorIndex > selStart && colorIndex <= selEnd && isSelectionFontColorInUse())
					{
						color = &selectionFontColor;
					}
					else
					{
						color = &textColors[colorIndex].first;
					}

					//draw the chunk
					paintEvent.graphics()->drawText(Point(textX + totalWidth  + getLineOffset(i),
						textY + (i * getLineHeight())),
						&getTextLineAt(i)[stopUnichar],*color,getFont());
				}
				//increase the color index by the number of unichars drawn
				colorIndex += len - stopPos;



			}

			int colorIndexChange = colorIndex - curColIndex;
			for(int i = 0; i < colorIndexChange; ++i)
			{
				unicodeFunctions.bringToNextUnichar(colorUniPos,getText());
			}
		}

		/* end of crazy render procedure */


	}

	void ExtendedTextBox::setSelectionFontColor( const Color &color )
	{
		selectionFontColor = color;
	}

	const Color& ExtendedTextBox::getSelectionFontColor() const
	{
		return selectionFontColor;
	}

	bool ExtendedTextBox::isSelectionFontColorInUse() const
	{
		return selFontColor;
	}

	void ExtendedTextBox::setIsSelectionFontColorInUse( bool wantSelectionColor )
	{
		selFontColor = wantSelectionColor;
	}

	void ExtendedTextBox::registerEmoticon( const std::string& triggerChar, Image* image, const std::string& clipboardText )
	{
		icons[triggerChar] = image;
		if(clipboardText != "")
		{
			iconClipboardText[image] = clipboardText;
		}
	}

	Image* ExtendedTextBox::getEmoticon(const std::string& triggerChar )
	{
		std::map<std::string,Image*>::iterator it = icons.find(triggerChar);

		if(it != icons.end())
		{
			return it->second;
		}
		
		return NULL;
	}

	std::string ExtendedTextBox::getEmoticonClipboardText( Image* emoticon )
	{
		std::map<Image*,std::string>::iterator it = iconClipboardText.find(emoticon);

		if(it != iconClipboardText.end())
		{
			return it->second;
		}

		return "";
	}

	void ExtendedTextBox::copy()
	{
		if(getSelectionLength() > 0)
		{
			int start = getSelectionStart();
			std::string text = getSelectedText();
			size_t uniPos = 0;
			int bytesSkipped = 0;
			std::string newStr;
			std::string curChar;
			size_t textLen = unicodeFunctions.length(text);

			for(size_t i = 0; i < textLen; ++i)
			{
				//get length of unichar
				int curLen = unicodeFunctions.bringToNextUnichar(uniPos,text);
				curStr = text.substr(bytesSkipped,curLen);
				bytesSkipped += curLen;

				Image* emoticon = textColors[start + i].second;

				if(emoticon)
				{
					newStr += getEmoticonClipboardText(emoticon);
				}
				else
				{
					newStr += curStr;
				}

			}


			Clipboard::copy(newStr);
		}
	}

}

