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

#include "Agui/Widgets/Tab/Tab.hpp"
#include "Agui/Widgets/Tab/TabbedPane.hpp"
namespace agui {
	Tab::Tab(void)
	: mouseInside(false), tabPane(NULL)
	{
		setBackColor(Color(60,140,180));
		setFocusable(true);
		setTabable(false);
	}

	Tab::~Tab(void)
	{
		if(tabPane)
		{
			tabPane->removeTab(this);
		}
	}

	void Tab::resizeToContents()
	{
		setSize(getFont()->getTextWidth(getText()) 
			+ getMargin(SIDE_LEFT) + getMargin(SIDE_RIGHT),
			getFont()->getLineHeight()
			+ getMargin(SIDE_TOP) + getMargin(SIDE_BOTTOM));
	}

	void Tab::setFont( const Font *font )
	{
		Widget::setFont(font);
		resizeToContents();
		if(tabPane)
		{
			tabPane->adjustSize();
		}
	}

	bool Tab::isMouseInside() const
	{
		return mouseInside;
	}

	void Tab::mouseEnter( MouseEvent &mouseEvent )
	{
		mouseEvent.consume();
		mouseInside = true;
	}

	void Tab::mouseLeave( MouseEvent &mouseEvent )
	{
		mouseEvent.consume();
		mouseInside = false;
	}

	void Tab::paintComponent( const PaintEvent &paintEvent )
	{
		paintEvent.graphics()->drawText(Point(0,0),
			getText().c_str(),getFontColor(),getFont());

	}

	bool Tab::isSelectedTab() const
	{
		if(tabPane)
		{
			return tabPane->getSelectedTab() == this;
		}
		else
		{
			return false;
		}
	}

	void Tab::gainedSelection()
	{
	}

	void Tab::lostSelection()
	{
	}

	void Tab::mouseDown( MouseEvent &mouseEvent )
	{
		if(tabPane)
		{
			tabPane->setSelectedTab(this);
			mouseEvent.consume();
		}
	}

	void Tab::setTabPane(TabbedPane* pane)
	{
		tabPane = pane;
	}

	void Tab::setText( const std::string &text )
	{
		Widget::setText(text);
		resizeToContents();
	}

	void Tab::keyDown( KeyEvent &keyEvent )
	{
		if(keyEvent.getExtendedKey() == EXT_KEY_LEFT && tabPane)
		{
			if(tabPane->getSelectedIndex() > 0)
			{
				tabPane->setSelectedTab(tabPane->getSelectedIndex() - 1);
			}
		}
		else if(keyEvent.getExtendedKey() == EXT_KEY_RIGHT && tabPane)
		{
			tabPane->setSelectedTab(tabPane->getSelectedIndex() + 1);
		}
	}

	void Tab::keyRepeat( KeyEvent &keyEvent )
	{
		if(keyEvent.getExtendedKey() == EXT_KEY_LEFT && tabPane)
		{
			if(tabPane->getSelectedIndex() > 0)
			{
				tabPane->setSelectedTab(tabPane->getSelectedIndex() - 1);
			}
		}
		else if(keyEvent.getExtendedKey() == EXT_KEY_RIGHT && tabPane)
		{
			tabPane->setSelectedTab(tabPane->getSelectedIndex() + 1);
		}
	}

	void Tab::paintBackground( const PaintEvent &paintEvent )
	{
		Color color = getBackColor();
		if(isSelectedTab())
		{
			color = Color(255,255,255);
		}
		else if(isMouseInside())
		{
			color = Color(
				color.getR() * 1.1f,
				color.getG() * 1.1f,
				color.getB() * 1.1f);
		}

		paintEvent.graphics()->drawFilledRectangle(getSizeRectangle(), color);


		Color black = Color(110,110,110);

		if(isFocused())
			black = Color(0,0,0);



		//top
		paintEvent.graphics()->drawLine(Point(0,1),
			Point(getSize().getWidth(),1),black);

		//left
		paintEvent.graphics()->drawLine(Point(1,0),
			Point(1,getSize().getHeight() + 1),black);

		//right
		paintEvent.graphics()->drawLine(Point(getSize().getWidth() ,0),
			Point(getSize().getWidth() ,getSize().getHeight() + 1),black);



		if(!isSelectedTab())
		{
			//bottom
			paintEvent.graphics()->drawLine(Point(0,getSize().getHeight()),
				Point(getSize().getWidth(),getSize().getHeight()),black);
		}
	}
}
