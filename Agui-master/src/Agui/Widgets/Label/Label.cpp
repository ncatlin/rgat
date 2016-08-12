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

#include "Agui/Widgets/Label/Label.hpp"
#include "Agui/Widgets/Label/LabelListener.hpp"

namespace agui {
	Label::Label(void)
	{
		setMargins(0,0,0,0);
		setAutosizing(true);
		setAlignment(ALIGN_TOP_LEFT);
	}

	Label::Label( const std::string &text )
	{
		setMargins(0,0,0,0);
		setAutosizing(true);
		setAlignment(ALIGN_TOP_LEFT);
		setText(text);
		
	}

	Label::~Label(void)
	{
		for(std::vector<LabelListener*>::iterator it = 
			labelListeners.begin();
			it != labelListeners.end(); ++it)
		{
			if((*it))
				(*it)->death(this);
		}
	}

	void Label::paintComponent( const PaintEvent &paintEvent )
	{
		drawText(paintEvent);
	}

	void Label::updateLabel()
	{
		resizableText.makeTextLines(getFont(),getText(),lines,
			getInnerRectangle().getWidth());
	}



	void Label::setAlignment( AreaAlignmentEnum alignment )
	{
		for(std::vector<LabelListener*>::iterator it = 
			labelListeners.begin();
			it != labelListeners.end(); ++it)
		{
			if((*it))
				(*it)->alignmentChanged(this,alignment);
		}

		this->alignment = alignment;
		if(isAutosizing())
		{
			resizeToContents();
		}
		updateLabel();
	}

	AreaAlignmentEnum Label::getAlignment() const
	{
		return alignment;
	}

	void Label::resizeToContents()
	{
    double computedWidth = getFont()->getTextWidth(getText()) + getMargin(SIDE_LEFT) + getMargin(SIDE_RIGHT);
    if (this->getMaxSize().getWidth() > computedWidth)
      computedWidth = this->getMaxSize().getWidth();
		_setSizeInternal(Dimension(int(computedWidth), getFont()->getLineHeight() * getNumTextLines() + getMargin(SIDE_TOP) + getMargin(SIDE_BOTTOM)));
	}

  void Label::resizeToContentsPreserveWidth()
	{
    _setSizeInternal(Dimension(getWidth(), getFont()->getLineHeight() * getNumTextLines() + getMargin(SIDE_TOP) + getMargin(SIDE_BOTTOM)));
	}

	bool Label::isAutosizing()
	{
		return isLabelAutosizing;
	}

	void Label::setAutosizing( bool autosizing )
	{
		for(std::vector<LabelListener*>::iterator it = 
			labelListeners.begin();
			it != labelListeners.end(); ++it)
		{
			if((*it))
				(*it)->isAutosizingChanged(this,autosizing);
		}
		isLabelAutosizing = autosizing;
		if(isAutosizing())
		{
			resizeToContents();
			updateLabel();
		}
	}

	void Label::_setSizeInternal( const Dimension &size )
	{
		if(isAutosizing())
		{
			setSize(size);
			Widget::setSize(size);
		}
		else
		{
			setSize(size);
		}
	}

	void Label::drawText( const PaintEvent &paintEvent )
	{
		paintEvent.graphics()->pushClippingRect(getInnerRectangle());
		resizableText.drawTextArea(paintEvent.graphics(),
			getFont(),getInnerRectangle(),getFontColor(),lines,getAlignment());
		paintEvent.graphics()->popClippingRect();

	}

	void Label::addLabelListener(
		LabelListener* listener )
	{
		for(std::vector<LabelListener*>::iterator it = 
			labelListeners.begin();
			it != labelListeners.end(); ++it)
		{
			if((*it) == listener)
				return;
		}

		labelListeners.push_back(listener);
	}

	void Label::removeLabelListener( 
		LabelListener *listener )
	{
		labelListeners.erase(
			std::remove(labelListeners.begin(),
			labelListeners.end(), listener),
			labelListeners.end());
	}


	void Label::setSize( const Dimension &size )
	{
		if(!isAutosizing())
		{
			Widget::setSize(size);
			updateLabel();
		}
	}

	void Label::setSize( int width, int height )
	{
		Widget::setSize(width,height);
	}

	void Label::setText( const std::string &text )
	{
		Widget::setText(text);
		if(isAutosizing())
		{
			resizeToContents();
		}
		updateLabel();
	}

	void Label::setFont( const Font *font )
	{
		Widget::setFont(font);
		if(isAutosizing())
		{
			resizeToContents();
		}
		updateLabel();
	}

	void Label::paintBackground( const PaintEvent &)
	{

	}

	void Label::setSingleLine( bool singleLine, bool wantEllipsis /*= false*/ )
	{
		resizableText.setSingleLine(singleLine,wantEllipsis);
	}

	bool Label::wantsEllipsis() const
	{
		return resizableText.wantsEllipsis();
	}

	bool Label::isSingleLine() const
	{
		return resizableText.isSingleLine();
	}

	int Label::getNumTextLines() const
	{
		return int(lines.size());
	}

	std::vector<std::string>& Label::getTextLines()
	{
		return lines;
	}

}
