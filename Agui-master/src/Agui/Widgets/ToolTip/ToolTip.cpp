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

#include "Agui/Widgets/ToolTip/ToolTip.hpp"

namespace agui {


	ToolTip::ToolTip()
		: align(ALIGN_TOP_LEFT), invoker(NULL)
	{
		resizableText.setSingleLine(false);
		setVisibility(false);
		setFocusable(false);
		setTabable(false);
		setPreferredOffset(Point(10,10));
	}

	void ToolTip::mouseClick( MouseEvent &mouseEvent )
	{

		if(mouseEvent.getButton() == MOUSE_BUTTON_LEFT)
			dispatchActionEvent(ActionEvent(this));
	}

	void ToolTip::showToolTip( const std::string& text, int width, int x, int y, Widget* invoker )
	{
		this->invoker = invoker;

		
		int w = width <= 0 ? 1000 : width;
		resizableText.makeTextLines(getFont(),text,wrappedText,w);

		int newHeight = int(wrappedText.size()) * getFont()->getLineHeight();

		int newWidth = w;

			int widestLine = -1;
			for(size_t i = 0; i < wrappedText.size(); ++i)
			{
				int curWidth = getFont()->getTextWidth(wrappedText[i]);
				if(curWidth > widestLine)
				{
					widestLine = curWidth;
				}
			}

			if(widestLine < width)
			newWidth = widestLine;

		newWidth += getMargin(SIDE_LEFT) + getMargin(SIDE_RIGHT);
		newHeight += getMargin(SIDE_TOP) + getMargin(SIDE_BOTTOM);

		setSize(newWidth,newHeight);
		if(getParent())
		{
			int extraX = (x + newWidth) - getParent()->getWidth();
			int extraY = (y + newHeight) - getParent()->getHeight();

			if(extraX > 0)
				x -= extraX;

			if(extraY > 0)
				y -= extraY;
		}

		setLocation(x,y);
		setVisibility(true);
	}

	const std::vector<std::string>& ToolTip::getAreaText() const
	{
		return wrappedText;
	}

	void ToolTip::paintBackground( const PaintEvent &paintEvent )
	{
		paintEvent.graphics()->drawFilledRectangle(
			getSizeRectangle(),getBackColor());
    paintEvent.graphics()->drawRectangle(getSizeRectangle(), getFontColor());
	}

	void ToolTip::paintComponent( const PaintEvent &paintEvent )
	{
		resizableText.drawTextArea(
			paintEvent.graphics(),getFont(),getInnerRectangle(),
			getFontColor(),getAreaText(),align);
	}

	void ToolTip::setTextAlignment( AreaAlignmentEnum alignment )
	{
		align = alignment;
	}

	agui::AreaAlignmentEnum ToolTip::getTextAlignment() const
	{
		return align;
	}

	void ToolTip::hideToolTip()
	{
		setVisibility(false);
		invoker = NULL;
	}

	void ToolTip::setPreferredOffset( Point offset )
	{
		preferredOffset = offset;
	}

	Point ToolTip::getPreferredOffset() const
	{
		return preferredOffset;
	}
	Widget* ToolTip::getInvoker() const
	{
		return invoker;
	}

}



