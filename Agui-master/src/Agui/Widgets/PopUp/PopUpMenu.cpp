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

#include "Agui/Widgets/PopUp/PopUpMenu.hpp"

namespace agui {
	

	void PopUpMenu::addItem( PopUpMenuItem* item )
	{
		insertItem(item,getLength());
	}

	void PopUpMenu::insertItem( PopUpMenuItem* item, int index )
	{
		items.insert(items.begin() + index,item);
		item->setParentMenu(this);
		if(item->getIcon())
		{
			if(item->getIcon()->getWidth() > getIconWidth())
			{
				setIconWidth(item->getIcon()->getWidth());
			}
		}
	}

	int PopUpMenu::getLength() const
	{
		return int(items.size());
	}

	void PopUpMenu::addItems( const std::vector<PopUpMenuItem*>& itemVec )
	{
		for(size_t i = 0; i < itemVec.size(); ++i)
		{
			addItem((itemVec[i]));
		}
	}

	bool PopUpMenu::itemExists( PopUpMenuItem* item ) const
	{
		for(size_t i = 0; i < items.size(); ++i)
		{
			if(items[i] == item)
			{
				return true;
			}
		}

		return false;
	}

	bool PopUpMenu::indexExists( int index ) const
	{
		return index >= 0 && index < (int)items.size();
	}

	void PopUpMenu::setItemHeight( int height )
	{
		itemHeight = height;
	}

	int PopUpMenu::getItemHeight() const
	{
		return itemHeight;
	}

	int PopUpMenu::getItemHeight( PopUpMenuItem* item ) const
	{
		return item->isSeparator() ? getSeparatorHeight() : getItemHeight();
	}

	void PopUpMenu::setShowIcon( bool show )
	{
		showIcon = show;
	}

	bool PopUpMenu::isShowingIcon() const
	{
		return showIcon;
	}

	Point PopUpMenu::alignString( const std::string& text, AreaAlignmentEnum align )
	{
		int w = getFont()->getTextWidth(text);
		int h = getFont()->getLineHeight();
		return createAlignedPosition(align,getInnerRectangle(),Dimension(w,h));
	}

	void PopUpMenu::setIconWidth( int width )
	{
		iconWidth = width;
	}

	int PopUpMenu::getIconWidth() const
	{
		return iconWidth;
	}

	void PopUpMenu::removeItem( PopUpMenuItem* item )
	{
		for(size_t i = 0; i < items.size(); ++i)
		{
			if(items[i] == item)
			{
				items.erase(items.begin() + i);
				return;
			}
		}
	}

	void PopUpMenu::setStartTextGap( int gap )
	{
		startTextGap = gap;
	}	
	
	int PopUpMenu::getStartTextGap() const
	{
		return startTextGap;
	}
	void PopUpMenu::setMiddleTextGap( int gap )
	{
		middleTextGap = gap;
	}

	int PopUpMenu::getMiddleTextGap() const
	{
		return middleTextGap;
	}
	void PopUpMenu::setEndTextGap( int gap )
	{
		endTextGap = gap;
	}

	int PopUpMenu::getEndTextGap() const
	{
		return endTextGap;
	}

	void PopUpMenu::setTextGaps( int start, int middle, int end )
	{
		setStartTextGap(start);
		setMiddleTextGap(middle);
		setEndTextGap(end);
	}

	int PopUpMenu::getItemWidth( PopUpMenuItem* item ) const
	{
		if(!item)
			return 0;

		int w = 0;
		if(isShowingIcon())
		{
			w += iconWidth;
		}
		w += getStartTextGap();
		w += getFont()->getTextWidth(item->getText());
		w += getMiddleTextGap();
		w += getFont()->getTextWidth(item->getShortcutText());
		w += getEndTextGap();

		return w;
	}

	void PopUpMenu::setSeparatorHeight( int height )
	{
		separatorHeight = height;
	}

	int PopUpMenu::getSeparatorHeight() const
	{
		return separatorHeight;
	}

	void PopUpMenu::resizeHeightToContents()
	{
		size_t h = 0;
		for(int i = 0; i < getLength(); ++i)
		{
			if(items[i]->isSeparator())
			{
				h += getSeparatorHeight();
			}
			else
			{
				h += getItemHeight();
			}
		}

		h += getMargin(SIDE_TOP) + getMargin(SIDE_BOTTOM);

		setSize(getWidth(), int(h));
	}

	void PopUpMenu::resizeWidthToContents()
	{
		int w = 0;
		for(int i = 0; i < getLength(); ++i)
		{
			int tempWidth = getItemWidth(items[i]);
			if(tempWidth > w)
			{
				w = tempWidth;
			}
		}

		w += getMargin(SIDE_LEFT) + getMargin(SIDE_RIGHT);

		setSize(int(w), getHeight());
	}

	void PopUpMenu::resizeToContents()
	{
		resizeWidthToContents();
		resizeHeightToContents();
	}

	int PopUpMenu::getIndexAtPoint( const Point& p ) const
	{
		if(p.getY() < getMargin(SIDE_TOP) ||
			p.getY() > getInnerHeight() + getMargin(SIDE_TOP) ||
			p.getX() < getMargin(SIDE_LEFT) ||
			p.getX() > getInnerWidth() + getMargin(SIDE_LEFT))
		{
			return -1;
		}

		int pY = p.getY() - getMargin(SIDE_TOP);
		int h = 0;

		for(int i = 0; i < getLength(); ++i)
		{
			int y = getItemHeight(items[i]);
			
			if(pY >= h && pY < h + y)
			{
				return i;
			}

			h += y;
		}

		return -1;
	}

	void PopUpMenu::clearItems()
	{
		items.clear();
	}

	void PopUpMenu::mouseLeave( MouseEvent &mouseEvent )
	{
        if(getGui()->getInput()->isUsingTouchCompatibility())
            return;
        
		Widget::mouseLeave(mouseEvent);
		if(getGui())
		{
			if(getGui()->getWidgetUnderMouse() != childMenu)
			{
				setSelectedIndex(-1);
				requestShowChildMenu();
			}
		}
	

	}

	void PopUpMenu::setSelectedIndex( int index )
	{
		if(index != getSelectedIndex())
		{
			selectedIndex = index;
			selectedIndexChanged();
		}
		
	}

	int PopUpMenu::getSelectedIndex() const
	{
		return selectedIndex;
	}

	void PopUpMenu::mouseMove( MouseEvent &mouseEvent )
	{
		int index = getSelectedIndex();
		setSelectedIndex(getIndexAtPoint(mouseEvent.getPosition()));
		if(index != getSelectedIndex())
		{
			requestShowChildMenu();
		}
	}


	void PopUpMenu::mouseUp( MouseEvent &mouseEvent )
	{
        
        if(getGui()->getInput()->isUsingTouchCompatibility())
            return;
        
		setSelectedIndex(getIndexAtPoint(mouseEvent.getPosition()));

		if((childMenu && !childMenu->isVisible()) || !childMenu) 
		requestShowChildMenu();
	}

	void PopUpMenu::mouseClick( MouseEvent &mouseEvent )
	{
        
        if(getGui()->getInput()->isUsingTouchCompatibility())
        {
            if(indexExists(getSelectedIndex()))
            {
                PopUpMenuItem* item = items[getSelectedIndex()];
                
                if(item->isSeparator() || item->isSubMenu())
                {
                    return;
                }
                
                needsToMakeSelecton = true;
            }
            
            return;
        }
        
		if(mouseEvent.getButton() != MOUSE_BUTTON_LEFT)
		{
			return;
		}

		setSelectedIndex(getIndexAtPoint(mouseEvent.getPosition()));

		if(indexExists(getSelectedIndex()))
		{
			PopUpMenuItem* item = items[getSelectedIndex()];

			if(item->isSeparator() || item->isSubMenu())
			{
				return;
			}

			needsToMakeSelecton = true;
		}
	}

	void PopUpMenu::makeSelection()
	{
		if(getSelectedIndex() == -1 ||
			!items[getSelectedIndex()]->isEnabled() ||
			items[getSelectedIndex()]->isSeparator())
		{
			return;
		}

	
		PopUpMenuItem* item = items[getSelectedIndex()];
		closeRootPopUp();	

		dispatchActionEvent(
			ActionEvent(item,item->getText()));
	}

	PopUpMenu::PopUpMenu()
		: itemHeight(15),showIcon(true),
		startTextGap(10),middleTextGap(10),endTextGap(16),
		iconWidth(16), separatorHeight(6), selectedIndex(-1),
		parentMenu(NULL),childMenu(NULL), invoker(NULL),
		mouseInside(false),needsClosure(false), needsToMakeSelecton(false),
		m_invokeButton(NULL)
	{
		setVisibility(false);
		setBackColor(Color(234,237,255));
		setMargins(3,3,3,3);
        setCausesLocationChange(true);

	}

	void PopUpMenu::mouseDownCB( MouseEvent &mouseEvent )
	{
		if(getGui())
		{
			getGui()->_widgetLocationChanged();
			Widget* wum = getGui()->getWidgetUnderMouse();

			bool underPopUp = false;
			PopUpMenu* root = getRootPopUp();

			do 
			{
				if(wum == root)
				{
					underPopUp = true;
					break;
				}
				root = root->getChildPopUp();
			} while (root);

			if(!underPopUp)
			{
				needsClosure = true;
			}
		}
	}

	void PopUpMenu::closePopUp()
	{
		if(childMenu)
		{
			childMenu->closePopUp();
		}

		childMenu = NULL;
		setSelectedIndex(-1);
		setVisibility(false);
		if(invoker && invoker->getGui())
		{
			invoker->getGui()->removeMousePreviewListener(this);
		}

		if(m_invokeButton)
		{
			m_invokeButton->setToggleState(false);
		}
	}

	PopUpMenu* PopUpMenu::getParentPopUp()
	{
		return parentMenu;
	}

	PopUpMenu* PopUpMenu::getRootPopUp()
	{
		PopUpMenu* parent = this;
		while(parent->getParentPopUp())
		{
			parent = parent->getParentPopUp();
		}

		return parent;
	}

	void PopUpMenu::closeRootPopUp()
	{
		getRootPopUp()->closePopUp();
	}

	void PopUpMenu::selectedIndexChanged() 
	{
	}

	void PopUpMenu::hideChildMenu()
	{
		if(childMenu)
		{
			childMenu->closePopUp();
		}
		setFocusable(true);
		focus();
		childMenu = NULL;
	}

	void PopUpMenu::showChildMenu()
	{
		if(childMenu)
		{
			Point pos = getChildShowPosition();
			childMenu->showPopUp(invoker,pos.getX(),pos.getY(),this);
			setFocusable(false);
		}
	}


	void PopUpMenu::showPopUp( Widget* invoker, int x, int y, PopUpMenu* parentPopUp /*= NULL*/ )
	{
		closePopUp();
		if(m_invokeButton)
		{
			m_invokeButton->setToggleState(true);
		}
		if(getParent())
		{
			getParent()->remove(this);
		}

		this->invoker = invoker;
		this->parentMenu = parentPopUp;
		invoker->getGui()->add(this);
		invoker->getGui()->addMousePreviewListener(this);

		if(getItemHeight() < getFont()->getHeight())
		{
			setItemHeight(getFont()->getHeight());
		}

		resizeToContents();

		if(parentMenu)
		{
			x += parentMenu->getAbsolutePosition().getX();
			y += parentMenu->getAbsolutePosition().getY();
		}
		else
		{
			x += invoker->getAbsolutePosition().getX();
			y += invoker->getAbsolutePosition().getY();
		}

		if(getParent())
		{
			if(x + getWidth() - (int)getMargin(SIDE_RIGHT) + 1 > getParent()->getWidth())
			{
				int diff = (x + getWidth() - getMargin(SIDE_RIGHT) + 1) - getParent()->getWidth();

				x -= diff;
			}

			if(y + getHeight() - (int)getMargin(SIDE_BOTTOM) + 1 > getParent()->getHeight())
			{
				y -= getInnerHeight();
			}
		}
		setLocation(x,y);
		setVisibility(true);
		focus();
		needsClosure = false;
	}

	Point PopUpMenu::getChildShowPosition() const
	{
		if(!childMenu)
		{
			return Point();
		}

		if(childMenu)
		{
			childMenu->resizeToContents();
		}

		int x = getInnerSize().getWidth() + getMargin(SIDE_LEFT);
		int y = getMargin(SIDE_TOP);
		for(int i = 0; i < getSelectedIndex(); ++i)
		{
			if(i == getSelectedIndex())
			{
				break;
			}
			else
			{
				y += getItemHeight(items[i]);
			}
		}

		if(getParent())
		{
			if(x + childMenu->getWidth() + getAbsolutePosition().getX() > getParent()->getWidth())
			{
				x = -childMenu->getWidth() + getMargin(SIDE_LEFT) + childMenu->getMargin(SIDE_RIGHT);
				x += getChildOffset().getX();
			}
			else
			{
				x -= childOffset.getX();
				x -= childMenu->getMargin(SIDE_LEFT);
			}

			if(y + childMenu->getHeight() + getAbsolutePosition().getY() > 
				getParent()->getHeight())
			{
				y -= childMenu->getInnerHeight();
				y += childMenu->getItemHeight();
				y += childMenu->getMargin(SIDE_BOTTOM);
				y += getChildOffset().getY();
			}
			else
			{
				y -= getChildOffset().getY();
				y -= childMenu->getMargin(SIDE_TOP);
			}
		}

		return Point(x,y);
	}

	void PopUpMenu::paintBackground( const PaintEvent &paintEvent )
	{
		paintEvent.graphics()->drawFilledRectangle(getSizeRectangle(),getBackColor());
		paintEvent.graphics()->drawRectangle(getSizeRectangle(),Color(100,100,100));
	}

	void PopUpMenu::paintComponent( const PaintEvent &paintEvent )
	{
		int totalHeight = 0;
		for(int i = 0; i < getLength(); ++i)
		{
			int w = 0;
			PopUpMenuItem* item = items[i];

			if(i == getSelectedIndex() && item->getItemType() != PopUpMenuItem::SEPARATOR)
			{
				paintEvent.graphics()->drawFilledRectangle(Rectangle(
					0,totalHeight,getWidth(),getItemHeight()),Color(169,193,214));
			}

			//draw the icon
			if(isShowingIcon())
			{
				if(item->getIcon())
				{
					paintEvent.graphics()->
						drawImage(item->getIcon(),getIconPosition(i,totalHeight));
				}
				
				w += getIconWidth();
			}

			if(item->isSeparator())
			{
				paintEvent.graphics()->drawLine(
					Point(w,totalHeight + (getItemHeight(item) / 2)),
					Point(getInnerWidth(),totalHeight + (getItemHeight(item) / 2)),
					Color(50,50,50));

				paintEvent.graphics()->drawLine(
					Point(w,totalHeight + (getItemHeight(item) / 2) + 1),
					Point(getInnerWidth(),totalHeight + (getItemHeight(item) / 2) + 1),
					Color(200,200,200));
			}

			w += getStartTextGap();

			paintEvent.graphics()->drawText(Point(w,getTextCenter() + totalHeight),
				item->getText().c_str(),getFontColor(),
				getFont());

			w+= getMiddleTextGap();

			Point shortcutPoint = alignString(item->getShortcutText(),ALIGN_MIDDLE_RIGHT);
			shortcutPoint.setX(shortcutPoint.getX() - getEndTextGap());
			shortcutPoint.setY(getTextCenter() + totalHeight);


			paintEvent.graphics()->drawText(shortcutPoint,
				item->getShortcutText().c_str(),getFontColor(),
				getFont());

			if(item->isSubMenu())
			{
				for(int x = 0; x < getEndTextGap(); ++x)
				{
					paintEvent.graphics()->drawLine(
						Point(getInnerWidth() - x, totalHeight + (getItemHeight() / 2) - (x / 2)),
						Point(getInnerWidth() - x, x + totalHeight + (getItemHeight() / 2) - (x / 2)),getFontColor());
				}
			}
		

			totalHeight += getItemHeight(item);
		}
	}

	Point PopUpMenu::getIconPosition( int index, int distanceY ) const
	{
		if(!indexExists(index))
		{
			return Point();
		}

		PopUpMenuItem* item = items[index];

		if(item->getIcon())
		{
			int h = item->getIcon()->getHeight();

			return Point(0,h);
		}

		return Point();
	}

	int PopUpMenu::getTextCenter() const
	{
		int h = getItemHeight();
		return (h - getFont()->getLineHeight()) / 2;

	}

	void PopUpMenu::focusLost()
	{
		Widget::focusLost();
		setFocusable(false);
	}

	void PopUpMenu::handleKeyboard( KeyEvent& keyEvent )
	{
		if(keyEvent.getExtendedKey() == EXT_KEY_UP)
		{
			setSelectedIndex(getPreviousIndex());
		}
		else if(keyEvent.getExtendedKey() == EXT_KEY_DOWN)
		{
			setSelectedIndex(getNextIndex());
		}
		else if(keyEvent.getExtendedKey() == EXT_KEY_LEFT)
		{
			if(parentMenu)
			{
				closePopUp();
				parentMenu->setFocusable(true);
				parentMenu->focus();
				
			}
		}
		else if(keyEvent.getExtendedKey() == EXT_KEY_RIGHT)
		{
			presentChildMenu();
			if(childMenu && childMenu->getLength() > 0)
			{
				childMenu->setSelectedIndex(0);
			}
		}

		if(keyEvent.getKey() == KEY_ENTER)
		{
			needsToMakeSelecton = true;
		}
	}

	int PopUpMenu::getNextIndex() const
	{
		if(getLength() == 0)
		{
			return -1;
		}

		int curIndex = getSelectedIndex();
		int newIndex = getSelectedIndex();

		do 
		{
			newIndex++;
			if(newIndex >= getLength())
			{
				newIndex = 0;
			}

			PopUpMenuItem* item = items[newIndex];
			if(!item->isSeparator())
			{
				break;
			}

		} while (curIndex != newIndex);

		return newIndex;
	}

	int PopUpMenu::getPreviousIndex() const
	{
		if(getLength() == 0)
		{
			return -1;
		}

		int curIndex = getSelectedIndex();
		int newIndex = getSelectedIndex();

		do 
		{
			newIndex--;
			if(newIndex < 0)
			{
				newIndex = getLength() - 1;
			}

			PopUpMenuItem* item = items[newIndex];
			if(!item->isSeparator())
			{
				break;
			}

		} while (curIndex != newIndex);

		return newIndex;
	}

	void PopUpMenu::requestShowChildMenu()
	{
		presentChildMenu();
	}

	void PopUpMenu::presentChildMenu()
	{
		if(getSelectedIndex() == -1)
		{
			hideChildMenu();
		}

		if(indexExists(getSelectedIndex()))
		{
			PopUpMenuItem* item = items[getSelectedIndex()];
			hideChildMenu();
			if(item->isSubMenu() && item->isEnabled() && item->getSubMenu())
			{
				childMenu = item->getSubMenu();
				showChildMenu();
			}
		}
	}

	PopUpMenu* PopUpMenu::getChildPopUp()
	{
		return childMenu;
	}

	void PopUpMenu::logic( double timeElapsed )
	{
		if(needsToMakeSelecton)
		{
			makeSelection();
			needsToMakeSelecton = false;
		}

		if(needsClosure)
		{
			needsClosure = false;
			closeRootPopUp();
		}
	}

	void PopUpMenu::keyDown( KeyEvent &keyEvent )
	{
		handleKeyboard(keyEvent);
	}

	void PopUpMenu::keyRepeat( KeyEvent &keyEvent )
	{
		handleKeyboard(keyEvent);
	}

	PopUpMenu::~PopUpMenu()
	{
		for(std::vector<PopUpMenuItem*>::iterator it = items.begin();
			it != items.end(); ++it)
		{
			(*it)->setParentMenu(NULL);
		}
	}

	PopUpMenuItem* PopUpMenu::getItemAt( int index ) const
	{
		if(indexExists(index))
		{
			return items[index];
		}

		return NULL;
	}

	void PopUpMenu::setFont( const Font *font )
	{
		Widget::setFont(font);
		int extra = 2;
		if(getItemHeight() < getFont()->getLineHeight() + extra)
		{
			setItemHeight(getFont()->getLineHeight() + extra);
		}
	}

	void PopUpMenu::setChildOffset( const Point& offset )
	{
		childOffset = offset;
	}

	const Point& PopUpMenu::getChildOffset() const
	{
		return childOffset;
	}

	void PopUpMenu::setInvokeButton( Button* button )
	{
		m_invokeButton = button;
	}

}



