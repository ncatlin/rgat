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

#include "Agui/ResizableText.hpp"
#include "Agui/Graphics.hpp"
#include "Agui/Font.hpp"
namespace agui
{
	void ResizableText::drawTextArea( Graphics *g, 
									 const Font *font,const Rectangle &area, const Color &color, 
									 const std::vector<std::string> &lines,AreaAlignmentEnum align)
	{
		int curPosX = area.getLeft();
		int curPosY = area.getTop();


		int lagHeight = 0;
		int wordWidth = 0;
		int lagWidth = 0;
		int verticalOffset = 0;

		lagHeight = area.getHeight() - (font->getLineHeight() * (int)lines.size());

		if(align == ALIGN_MIDDLE_CENTER ||
			align == ALIGN_MIDDLE_LEFT   ||
			align == ALIGN_MIDDLE_RIGHT)
		{
			verticalOffset = (lagHeight / 2);

		}
		else if(align == ALIGN_BOTTOM_CENTER ||
			align == ALIGN_BOTTOM_LEFT   ||
			align == ALIGN_BOTTOM_RIGHT)
		{
			verticalOffset = lagHeight;
		}

		if(verticalOffset < 0)
		{
			verticalOffset = 0;
		}


		for(size_t i = 0; i < lines.size(); ++i)
		{
			wordWidth = font->getTextWidth(lines[i]) ;
			lagWidth = area.getWidth() - wordWidth;

			if(align == ALIGN_TOP_RIGHT    ||
				align == ALIGN_MIDDLE_RIGHT ||
				align == ALIGN_BOTTOM_RIGHT)
			{
				curPosX = area.getLeft() + lagWidth - 2;
			}
			else if(align == ALIGN_TOP_CENTER     ||
				align == ALIGN_MIDDLE_CENTER  ||
				align == ALIGN_BOTTOM_CENTER)
			{
				curPosX = area.getLeft() + (lagWidth / 2);
			}
			else // align left
			{
				curPosX = area.getLeft();
			}


			if(curPosY > area.getBottom() - font->getLineHeight() && i > 0)
			{

				return;
			}

			g->drawText(Point(curPosX,curPosY + verticalOffset),
				lines[i].c_str(),color,font);

			curPosY += font->getLineHeight();

		} //end for

	}


	void ResizableText::makeTextLines( const Font *font,const std::string &text, std::vector<std::string> &textRows, int maxWidth )
	{
		if(singleLine)
		{
			singleMakeLines(font,text,textRows,maxWidth);
		}
		else
		{
			multiMakeLines(font,text,textRows,maxWidth);
		}
	}

	ResizableText::ResizableText()
	: singleLine(true),wantEllipsis(true)
	{

	}

	ResizableText::~ResizableText()
	{

	}

	void ResizableText::setSingleLine( bool singleLine, bool wantEllipsis /*= false*/ )
	{
		if(!singleLine)
		{
			wantEllipsis = false;
		}
		this->wantEllipsis = wantEllipsis;
		this->singleLine = singleLine;
	}

	void ResizableText::multiMakeLines( const Font *font, const std::string &text, std::vector<std::string> &textRows, int maxWidth )
	{
		textRows.clear();
		textRows.push_back("");
		std::string curStr;
		std::string curWord;

		int curWordWidth = 0;
		int curLetterWidth = 0;
		int curLineWidth = 0;

		int len = int(utf8Manager.length(text));
		int bytesSkipped = 0;
		int letterLength = 0;

		std::string::const_iterator it = text.begin();
		std::string::const_iterator last = text.end();
		for(int i = 0; i < len; ++i)
		{
			//get the unicode character
			letterLength = (int)utf8Manager.bringToNextUnichar(it,last);
			if(letterLength == 1)
			{
				curStr = text[bytesSkipped];
			}
			else
			{
				curStr = text.substr(bytesSkipped,letterLength);
			}

			bytesSkipped += letterLength;

			curLetterWidth = font->getTextWidth(curStr);

			//push a new line
			if(curStr == "\n")
			{
				if(singleLine)
				{
					continue;
				}

				textRows.back() += curWord;
				curWord = "";
				curLetterWidth = 0;
				curWordWidth = 0;
				curLineWidth = 0;
				textRows.push_back("");
				continue;
			}

			if(curStr[0] >= ' ' || curStr[0] < 0)
			{
				//ensure word is not longer than the width
				if(curWordWidth + curLetterWidth > maxWidth && 
					curWord.length() >= 1 && !singleLine)
				{
					if(singleLine)
					{
						return;
					}

					textRows.back() += curWord;
					textRows.push_back("");
					curWord = "";
					curWordWidth = 0;
					curLineWidth = 0;
				}

				//add letter to word
				curWord += curStr;
				curWordWidth += curLetterWidth;
			}

			if(curLineWidth + curWordWidth >
				maxWidth && textRows.back().length() >= 1
				&& !singleLine)
			{
				textRows.push_back("");
				curLineWidth = 0;
			}

			if(curStr[0] == ' ' || curStr[0] == '-')
			{
				textRows.back() += curWord;
				curLineWidth += curWordWidth;
				curWord = "";
				curWordWidth = 0;
			}
		}

		if(curWord != "")
		{
			textRows.back() += curWord;
		}

	}

	void ResizableText::singleMakeLines( const Font *font, 
										const std::string &text, std::vector<std::string> &textRows, 
										int maxWidth )
	{
		textRows.clear();
		textRows.push_back("");
		std::string curStr;

		if (text.length() == 0)
		{
			return;
		}


		int len = int(utf8Manager.length(text));
		int bytesSkipped = 0;
		int letterLength = 0;

		std::string::const_iterator it = text.begin();
		std::string::const_iterator last = text.end();

		int textWidth = 0;
		if(wantEllipsis)
		{
			textWidth = font->getTextWidth(text);
		}

		bool wontFit = textWidth > maxWidth;

		for(int i = 0; i < len; ++i)
		{

			//get the unicode character
			letterLength = (int)utf8Manager.bringToNextUnichar(it,last);
			if(letterLength == 1)
			{
				curStr = text[bytesSkipped];
			}
			else
			{
				curStr = text.substr(bytesSkipped,letterLength);
			}

			bytesSkipped += letterLength;

			//we don't do new lines!
			if(curStr == "\n")
			{
				continue;
			}

			if(wontFit && font->getTextWidth(textRows.back() + curStr + "...") > maxWidth)
			{
				if(wantEllipsis)
				{
					textRows.back() += "...";
				}
				return;
			}
			else
			{
				textRows.back() += curStr;
            }
		}

	}

	bool ResizableText::isSingleLine() const
	{
		return singleLine;
	}

	bool ResizableText::wantsEllipsis() const
	{
		return wantEllipsis;
	}

}
