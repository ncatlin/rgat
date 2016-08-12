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

#include "Agui/Widgets/ListBox/ListBox.hpp"
#include "Agui/EmptyWidget.hpp"
namespace agui {
	//used to sort items
	struct LBCompare
	{
		NumericStringCompare numCmp;
		std::string toUpper(const std::string &str) {

			std::string retstr = str;
			for (size_t i=0;i< str.length();i++) 
				if (str[i] >= 0x61 && str[i] <= 0x7A) 
					retstr[i] = retstr[i] - 0x20;
			return retstr;
		}
		bool operator()(const std::pair<ListBoxItem,bool>& a, const std::pair<ListBoxItem,bool>& b)
		{
			return numCmp.compare(toUpper(a.first.text),toUpper(b.first.text));
		}
	};

	ListBox::ListBox( HScrollBar *hScroll /*= NULL*/, VScrollBar *vScroll /*= NULL*/, Widget* scrollInset /*=NULL*/ )
    : firstSelIndex(-1),lastSelIndex(-1),lastMouseY(-1),verticalOffset(0),
      horizontalOffset(0),  sorted(false), rsorted(false), multiselect(false),
      multiselectExtended(false), hoverSelection(false), itemHeight(0),
      hoveredIndex(-1),	widestItem(0), wrapping(false), allowRightClick(false)
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

		hScrollPolicy = SHOW_NEVER;
		vScrollPolicy = SHOW_AUTO;
    setItemHeight(20);
		updateScrollBars();

		setBackColor(Color(255,255,255));
		setFontColor(getFontColor());
		pChildInset->setBackColor(Color(120,120,120));

		setWheelScrollRate(2);
		setHKeyScrollRate(6);
		setVKeyScrollRate(6);

		setMouseWheelSelection(false);
		setFocusable(true);
		setTabable(true);
	}

	ListBox::~ListBox(void)
	{
		for(std::vector<ListBoxListener*>::iterator it = listboxListeners.begin();
			it != listboxListeners.end(); ++it)
		{
			(*it)->death(this);
		}

		pChildHScroll->removeHScrollBarListener(this);
		pChildVScroll->removeVScrollBarListener(this);

		if(isMaintainingHScroll)
		delete pChildHScroll;

		if(isMaintainingVScroll)
		delete pChildVScroll;

		if(isMaintainingScrollInset)
		{
			delete pChildInset;
		}
	}

	void ListBox::addItem( const std::string &item )
	{
		addItemAt(item,getLength());
	}

	void ListBox::removeItem( const std::string &item )
	{
		int selIndex = getSelectedIndex();
		//remove first occurrence of item
		for(ListItem::iterator it = items.begin();
			it != items.end(); ++it)
		{
			if(it->first.text == item)
			{
				items.erase(it);

				for(std::vector<ListBoxListener*>::iterator it = listboxListeners.begin();
					it != listboxListeners.end(); ++it)
				{
					(*it)->itemRemoved(this,item);
				}

				if(isSorted())
				{
					sort();
				}
				setWidestItem();
				updateScrollBars();
				setHoverIndex(getIndexAtPoint(agui::Point(getWidth() / 2,lastMouseY)));
				if(isHoverSelection())
				{
					setSelectedIndex(hoveredIndex);
				}
				return;
			}
		}

		if(getSelectedIndex() != selIndex)
		{
			displatchSelectionEvent(getSelectedIndex(),
				items[getSelectedIndex()].second);
		}
	}

	int ListBox::getLength() const
	{
		return int(items.size());
	}

	void ListBox::addItemAt( const std::string &item, int index )
	{
		if(indexExists(index) || index == getLength())
		{
			items.insert(items.begin() + index,std::pair<ListBoxItem,bool>(ListBoxItem(
				item,newItemColor),false));
			if(isSorted())
			{
				sort();
			}
			int iWidth = getFont()->getTextWidth(item);
			if(iWidth > widestItem)
			{
				widestItem = iWidth;
			}
			setWidestItem();
			updateScrollBars();
			setHoverIndex(getIndexAtPoint(agui::Point(getWidth() / 2,lastMouseY)));
			if(isHoverSelection())
			{
				setSelectedIndex(hoveredIndex);
			}
			for(std::vector<ListBoxListener*>::iterator it = listboxListeners.begin();
				it != listboxListeners.end(); ++it)
			{
				(*it)->itemAdded(this,item);
			}
		}
	}

	bool ListBox::indexExists( int index ) const
	{
		return index >= 0 && index < (int)items.size();
	}

	void ListBox::removeItemAt( int index )
	{
		if(indexExists(index))
		{
			for(std::vector<ListBoxListener*>::iterator it = listboxListeners.begin();
				it != listboxListeners.end(); ++it)
			{
				(*it)->itemRemoved(this,items[index].first.text);
			}

			items.erase(items.begin() + index);

			if(isSorted())
			{
				sort();
			}
			setWidestItem();
			updateScrollBars();
			setHoverIndex(getIndexAtPoint(agui::Point(getWidth() / 2,lastMouseY)));
			if(isHoverSelection())
			{
				setSelectedIndex(hoveredIndex);
			}
		}
	}

	int ListBox::getIndexOf( const std::string &item ) const
	{
		int count = 0;
		//return first occurrence of item
		for(ListItem::const_iterator it = items.begin();
			it != items.end(); ++it)
		{
			if(it->first.text == item)
			{
				return count;
			}
			count++;
		}
		return -1;
	}


	int ListBox::getSelectedIndex() const
	{
		int count = 0;
		//finds the first selected index
		if(!items.empty())
		{
			for(ListItem::const_iterator it = items.begin();
				it != items.end(); ++it)
			{
				if(it->second)
				{
					return count;
				}
				
				count++;
			}
		}
		return -1;
	}

	void ListBox::setSelectedIndex( int index )
	{
		if(indexExists(index) || index == -1)
		{
			if(index == getSelectedIndex() && 
				getSelectedIndex() == getBottomSelectedIndex())
			{
				return;
			}

			clearSelectedIndexes();
			firstSelIndex = -1;
			lastSelIndex = -1;
			
			if(index >= 0)
			{
				firstSelIndex = index;
				lastSelIndex = index;
				items[index].second = true;
			}

			

			displatchSelectionEvent(index,true);
		}
	}

	void ListBox::clearItems()
	{
		if(getSelectedIndex() != -1)
		{
			displatchSelectionEvent(-1,false);
		}
		
		items.clear();
		setWidestItem();
		updateScrollBars();
	}

	std::vector<int> ListBox::getSelectedIndexes() const
	{
		std::vector<int> indexes;
		if(items.empty())
		{
			return indexes;
		}
		int count = 0;
		for(ListItem::const_iterator it = items.begin();
			it != items.end(); ++it)
		{
			if(it->second)
			{
				indexes.push_back(count);
			}
			count++;
		}
		return indexes;
	}

	void ListBox::setSelectedIndexes( const std::vector<int> &indexes )
	{
		if(indexes.empty())
		{
			return;
		}

		clearSelectedIndexes();

		//if it is not multiselect then only select the first one
		if(!isMultiselect())
		{
			if(indexExists(indexes[0]) )
			{
				items[indexes[0]].second = true;
				displatchSelectionEvent(indexes[0],true);
			}

			return;
		}
		for(std::vector<int>::const_iterator it = indexes.begin();
			it != indexes.end(); ++it)
		{
			if(indexExists(*it) )
			{
				items[*it].second = true;
				displatchSelectionEvent(*it,true);
			}
		}
		
	}

	void ListBox::clearSelectedIndexes()
	{
		for(ListItem::iterator it = items.begin();
			it != items.end(); ++it)
		{
			it->second = false;
		}

		displatchSelectionEvent(-1,false);
	}

	void ListBox::sort()
	{
		if(!isReverseSorted())
		std::sort(getItemsBegin(),getItemsEnd(),LBCompare());
		else
			std::sort(getItemsRBegin(),getItemsREnd(),LBCompare());
	}


	void ListBox::paintComponent( const PaintEvent &paintEvent )
	{
		
		int itemsSkipped = getVisibleItemStart();

		int maxitems = getVisibleItemCount();

		int h = getItemHeight() * itemsSkipped;
		int rcount = 0;
		int diff = getItemHeight() - getFont()->getLineHeight();

		Color inverseFont = Color(255,255,255);

		Color * color;
		for(ListItem::const_iterator it = items.begin() + itemsSkipped ;
			it != items.end(); ++it)
		{
			if(rcount == maxitems)
			{
				break;
			}
			if(it->second)
			{
				paintEvent.graphics()->drawFilledRectangle(Rectangle(Point
					(0,h + verticalOffset),
					Dimension(getSize().getWidth(),getItemHeight())),Color(169,193,214));

				color = &inverseFont;
			}
			else if(itemsSkipped + rcount == getHoverIndex())
			{
				paintEvent.graphics()->drawFilledRectangle(Rectangle(Point
					(0,h + verticalOffset),
					Dimension(getInnerSize().getWidth(),getItemHeight())),Color(194,217,239));

				color = (Color*)&it->first.color;
			}
			else
			{
				color = (Color*)&it->first.color;
			}
			paintEvent.graphics()->drawText(Point(horizontalOffset,
				h + verticalOffset + (diff / 2)),it->first.text.c_str(),*color,
				getFont());


			h += getItemHeight();
			rcount++;
		
		}


	}

	void ListBox::setSorted( bool sorted )
	{
		if(sorted != this->sorted)
		{
			for(std::vector<ListBoxListener*>::iterator it = listboxListeners.begin();
				it != listboxListeners.end(); ++it)
			{
				(*it)->sortedChanged(this,sorted);
			}
		}
		this->sorted = sorted;
		if(isSorted())
		{
			sort();
		}
	}

	void ListBox::setReverseSorted( bool reverse )
	{
		for(std::vector<ListBoxListener*>::iterator it = listboxListeners.begin();
			it != listboxListeners.end(); ++it)
		{
			(*it)->rSortedChanged(this,reverse);
		}
		rsorted = reverse;
		if(isSorted())
		{
			sort();
		}
	}

	bool ListBox::isReverseSorted() const
	{
		return rsorted;
	}

	bool ListBox::isSorted() const
	{
		return sorted;
	}

	ListItem::iterator ListBox::getItemsBegin()
	{
		return items.begin();
	}

	ListItem::const_iterator ListBox::getItemsBegin() const
	{
		return items.begin();
	}

	ListItem::iterator ListBox::getItemsEnd()
	{
		return items.end();
	}

	ListItem ::const_iterator ListBox::getItemsEnd() const
	{
		return items.end();
	}

	ListItem::reverse_iterator ListBox::getItemsRBegin()
	{
		return items.rbegin();
	}

	ListItem::const_reverse_iterator ListBox::getItemsRBegin() const
	{
		return items.rbegin();
	}

	ListItem::reverse_iterator ListBox::getItemsREnd()
	{
		return items.rend();
	}

	ListItem ::const_reverse_iterator ListBox::getItemsREnd() const
	{
		return items.rend();
	}

	void ListBox::setFont( const Font *font )
	{
		Widget::setFont(font);
		
		if(getItemHeight() < getFont()->getLineHeight())
		{
			setItemHeight(getFont()->getLineHeight());
		}

		setWidestItem();
		updateScrollBars();
	}

	int ListBox::getItemHeight() const
	{
		return itemHeight;
	}

	void ListBox::setItemHeight( int height )
	{
		if(height < getFont()->getLineHeight())
		{
			height = getFont()->getLineHeight();
		}

		if(height <= 0)
		{
			height = 1;
		}

		if(itemHeight != height)
		{
			for(std::vector<ListBoxListener*>::iterator it = listboxListeners.begin();
				it != listboxListeners.end(); ++it)
			{
				(*it)->itemHeightChanged(this,multiselect);
			}
			itemHeight = height;

			updateScrollBars();
		}
	}

	void ListBox::checkScrollPolicy()
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

	void ListBox::resizeSBsToPolicy()
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

	void ListBox::adjustSBRanges()
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
		pChildVScroll->setRangeFromPage(getInnerSize().getHeight() - extraH,getContentHeight());


		//set horizontal value
		pChildHScroll->setRangeFromPage(getInnerSize().getWidth() - extraV,getContentWidth());
	}

	void ListBox::updateScrollBars()
	{
		checkScrollPolicy();
		resizeSBsToPolicy();
		adjustSBRanges();
	}


	void ListBox::keyAction(ExtendedKeyEnum key, bool shift)
	{
		switch (key)
		{
		case EXT_KEY_UP:
			if(isMultiselectExtended() &&
				getSelectedIndex() == 0 &&
				getSelectedIndex() != getBottomSelectedIndex()
				&& !shift)
			{
				clearSelectedIndexes();
				setSelectedIndex(0);
				return;
			}
			if(!isMultiselect())
			{
				if(isWrapping() && getSelectedIndex() == 0 && !shift)
				{

					makeSelection(getLength() - 1,false,shift);
					
				}
				else
				{
					if(firstSelIndex == -1 && lastSelIndex == -1)
					{
						setSelectedIndex(-1);
						return;
					}

					makeSelection(lastSelIndex - 1,false,shift);
				}

				moveToSelection(lastSelIndex);
			}
			else //simple multiselect action
			{
				pChildVScroll->setValue(pChildVScroll->getValue()
					- getVKeyScrollRate());
			}
			break;
		case EXT_KEY_DOWN:
		
			if(isMultiselectExtended() &&
				getBottomSelectedIndex() == getLength() - 1 &&
				getSelectedIndex() != getBottomSelectedIndex() 
				&& !shift)
			{
				clearSelectedIndexes();
				setSelectedIndex(getLength() - 1);
				return;
			}

			if(getSelectedIndex() == -1 && !shift)
			{
				setSelectedIndex(0);
				moveToSelection(getSelectedIndex());
				return;
			}

				if(!isMultiselect())
				{

					if(isWrapping() && getSelectedIndex() == getLength() - 1)
					{
						makeSelection(0,false,false);
					}
					else
					{
						if(firstSelIndex == -1 && lastSelIndex == -1)
						{
							setSelectedIndex(-1);
							return;
						}

						makeSelection(lastSelIndex + 1,false,shift);
					}

					moveToSelection(lastSelIndex);
				
			}
			else //simple multiselect action
			{
				pChildVScroll->setValue(pChildVScroll->getValue()
					+ getVKeyScrollRate());
			}
			break;
		case EXT_KEY_LEFT:
			pChildHScroll->setValue(pChildHScroll->getValue()
				- getHKeyScrollRate());
			break;
		case EXT_KEY_RIGHT:
			pChildHScroll->setValue(pChildHScroll->getValue()
				+ getHKeyScrollRate());
			break;
		case EXT_KEY_PAGE_DOWN:
			pChildVScroll->setValue(pChildVScroll->getValue() +
				pChildVScroll->getLargeAmount());
			break;
		case EXT_KEY_PAGE_UP:
			pChildVScroll->setValue(pChildVScroll->getValue() -
				pChildVScroll->getLargeAmount());
			break;
		case EXT_KEY_HOME:
			if(isMultiselectExtended())
			{
				makeSelection(0,false,shift);
				moveToSelection(getSelectedIndex());
			}
			else
			{
				setSelectedIndex(0);
				moveToSelection(getSelectedIndex());
			}
			break;
		case EXT_KEY_END:
			if(isMultiselectExtended())
			{
				makeSelection(getLength() - 1,false,shift);
				moveToSelection(getBottomSelectedIndex());
			}
			else
			{
				setSelectedIndex(getLength() - 1);
				moveToSelection(getSelectedIndex());
			}

			
			break;
        default: break;
		}

	}

	void ListBox::valueChanged( HScrollBar* source, int val )
	{
		(void)source;
		horizontalOffset = -val;
	}

	void ListBox::valueChanged( VScrollBar* source,int val )
	{
		(void)source;
		verticalOffset = -val;
	}


	void ListBox::mouseWheelDown( MouseEvent &mouseEvent )
	{

		if(isMouseWheelSelection() && !isMultiselect())
		{
			keyAction(EXT_KEY_DOWN,mouseEvent.shift());
			dispatchActionEvent(ActionEvent(
				this));
		}
		else
		{
			pChildVScroll->wheelScrollDown(mouseEvent.getMouseWheelChange());
		}
		setHoverIndex(getIndexAtPoint(Point(0,lastMouseY)));

		if(isVScrollNeeded())
		{
			mouseEvent.consume();
		}
		
	}

	void ListBox::mouseWheelUp( MouseEvent &mouseEvent )
	{

		if(isMouseWheelSelection() && !isMultiselect())
		{
			keyAction(EXT_KEY_UP,mouseEvent.shift());
			dispatchActionEvent(ActionEvent(
				this));
		}
		else
		{
			pChildVScroll->wheelScrollUp(mouseEvent.getMouseWheelChange());
		}
		
		setHoverIndex(getIndexAtPoint(Point(0,lastMouseY)));
		if(isVScrollNeeded())
		{
			mouseEvent.consume();
		}

	}

	void ListBox::keyDown( KeyEvent &keyEvent )
	{
		keyAction(keyEvent.getExtendedKey(),keyEvent.shift());
		if(keyEvent.getKey() == KEY_SPACE || keyEvent.getKey() == KEY_ENTER)
		{
			dispatchActionEvent(ActionEvent(this));
		}
		keyEvent.consume();
	}

	void ListBox::keyRepeat( KeyEvent &keyEvent )
	{
		keyAction(keyEvent.getExtendedKey(),keyEvent.shift());
		keyEvent.consume();
	}

	void ListBox::keyUp( KeyEvent &keyEvent )
	{
		(void)keyEvent;
	}

	int ListBox::getContentWidth() const
	{
		return widestItem;
	}

	int ListBox::getContentHeight() const
	{
		return getLength() * getItemHeight();
	}

	bool ListBox::isHScrollNeeded() const
	{
		if(getHScrollPolicy() == SHOW_NEVER)
		{
			return false;
		}
		if(getContentWidth() > getInnerSize().getWidth())
		{
			return true;
		}
		else if(getVScrollPolicy() != SHOW_NEVER &&
			(getContentHeight() >  getInnerSize().getHeight()  &&
			getContentWidth() > (getInnerSize().getWidth() - pChildVScroll->getWidth() )))
		{
			return true;
		}
		return false;
	}

	bool ListBox::isVScrollNeeded() const
	{
		if(getVScrollPolicy() == SHOW_NEVER)
		{
			return false;
		}
		if(getContentHeight() > getInnerSize().getHeight())
		{
			return true;
		}
		else if(getHScrollPolicy() != SHOW_NEVER &&
			(getContentWidth() >  getInnerSize().getWidth()  &&
			getContentHeight() > (getInnerSize().getHeight() - pChildHScroll->getHeight() )))
		{
			return true;
		}
		return false;
	}

	void ListBox::setHScrollPolicy( ScrollPolicy policy )
	{
		hScrollPolicy = policy;
		updateScrollBars();
	}

	void ListBox::setVScrollPolicy( ScrollPolicy policy )
	{
		vScrollPolicy = policy;
		updateScrollBars();
	}

	ScrollPolicy ListBox::getHScrollPolicy() const
	{
		return hScrollPolicy;
	}

	ScrollPolicy ListBox::getVScrollPolicy() const
	{
		return vScrollPolicy;
	}

	void ListBox::setSize( const Dimension &size )
	{
		Widget::setSize(size);
		updateScrollBars();
	}

	void ListBox::setSize( int width, int height )
	{
		Widget::setSize(width,height);
	}

	void ListBox::setWheelScrollRate( int rate )
	{
		pChildVScroll->setMouseWheelAmount(rate);
	}

	int ListBox::getWheelScrollRate() const
	{
		return pChildVScroll->getMouseWheelAmount();
	}

	void ListBox::setHKeyScrollRate( int rate )
	{
		hKeyScrollRate = rate;
	}

	int ListBox::getHKeyScrollRate() const
	{
		return hKeyScrollRate;
	}

	int ListBox::getVerticalOffset() const
	{
		return verticalOffset;
	}

	int ListBox::getHorizontalOffset() const
	{
		return horizontalOffset;
	}

	int ListBox::getIndexAtPoint( const Point &p ) const
	{
		int y = p.getY();
		y -= getVerticalOffset();

		if(y < 0)
		{
			return -1;
		}

		int itemIndex = y / getItemHeight();

		if(indexExists(itemIndex))
		{
			return itemIndex;
		}
		return -1;

		
	}

	void ListBox::mouseDown( MouseEvent &mouseEvent )
	{
			if(mouseEvent.getButton() != MOUSE_BUTTON_LEFT &&
				(!allowRightClick && mouseEvent.getButton() == MOUSE_BUTTON_RIGHT))
			{
				return;
			}

			mouseEvent.consume();
			makeSelection(getIndexAtPoint(mouseEvent.getPosition()),
				mouseEvent.control(),mouseEvent.shift());
			dispatchActionEvent(ActionEvent(
				this));

			moveToSelection(getIndexAtPoint(mouseEvent.getPosition()));
	}

	void ListBox::setMultiselect( bool multiselect )
	{
		if(this->multiselect != multiselect)
		{
			for(std::vector<ListBoxListener*>::iterator it = listboxListeners.begin();
				it != listboxListeners.end(); ++it)
			{
				(*it)->multiselectChanged(this,multiselect);
			}

			this->multiselect = multiselect;
			setMultiselectExtended(false);
		}

		if(!multiselect)
		{
			clearSelectedIndexes();
		}
		
	}

	bool ListBox::isMultiselect() const
	{
		return multiselect;
	}


	void ListBox::makeSelection( int selection, bool controlKey, bool shiftKey)
	{
		if(firstSelIndex == -1 && lastSelIndex == -1
			&& isMultiselectExtended() && !controlKey)
		{
			setSelectedIndex(-1);
		}

		if(!indexExists(selection))
		{
			return;
		}

		if(isMultiselect())
		{
			items[selection].second = !items[selection].second;
			if(items[selection].second)
			{
				firstSelIndex = selection;
				lastSelIndex = selection;
			}
			else
			{
				firstSelIndex = -1;
				lastSelIndex = -1;
			}
			displatchSelectionEvent(selection,items[selection].second);
		}
		else if(isMultiselectExtended())
		{
			//no selection 
			if(getSelectedIndex() == -1)
			{
				setSelectedIndex(selection);

			}
			else if(shiftKey)
			{
				lastSelIndex = selection;
				selectRange(firstSelIndex,lastSelIndex);

			}
			else if(controlKey)
			{
				items[selection].second = !items[selection].second;
				if(items[selection].second)
				{
					firstSelIndex = selection;
					lastSelIndex = selection;
				}
				else
				{
					firstSelIndex = -1;
					lastSelIndex = -1;
				}
				displatchSelectionEvent(selection,items[selection].second);

			}
			else
			{
				if(getSelectedIndex() != getBottomSelectedIndex())
				{
					clearSelectedIndexes();
				}
				setSelectedIndex(selection);
			}

			//end of multiselect extended
		}
		else
		{
			setSelectedIndex(selection);
		}
	}

	void ListBox::mouseMove( MouseEvent &mouseEvent )
	{
		if(mouseEvent.getX() >= (int)getMargin(SIDE_LEFT) + getInnerWidth()
		|| mouseEvent.getY() >= (int)getMargin(SIDE_TOP) + getInnerHeight())
		{
			return;
		}
		lastMouseY = mouseEvent.getPosition().getY();

		setHoverIndex(getIndexAtPoint(mouseEvent.getPosition()));
		if(isHoverSelection())
		{
			setSelectedIndex(hoveredIndex);
		}
		mouseEvent.consume();

	}

	int ListBox::getHoverIndex() const
	{
		return hoveredIndex;
	}

	void ListBox::setHoverIndex( int index )
	{
		if(hoveredIndex == index)
		{
			return;
		}
		for(std::vector<ListBoxListener*>::iterator it = listboxListeners.begin();
			it != listboxListeners.end(); ++it)
		{
			(*it)->hoverIndexChanged(this,index);
		}
		hoveredIndex = index;

		//show a new tooltip
		if(getGui())
		{
			getGui()->invalidateToolTip();
		}
		
	}

	void ListBox::mouseLeave( MouseEvent &mouseEvent )
	{
		lastMouseY = -1;
		setHoverIndex(-1);
		mouseEvent.consume();
	}

	void ListBox::addItems( const std::string &items )
	{
		int curpos = 0;
		int len = 0;

		//parse the string for newlines and add an item when a newline is found
		for(size_t i = 0; i < items.length(); ++i)
		{
			if(items[i] == '\n')
			{
				if(len > 0)
				{
					this->items.push_back(
						std::pair<ListBoxItem,bool>(
						ListBoxItem(items.substr(curpos,len),newItemColor),false));
					
					for(std::vector<ListBoxListener*>::iterator it = listboxListeners.begin();
						it != listboxListeners.end(); ++it)
					{
						(*it)->itemAdded(this,this->items.back().first.text);
					}
					len = 0;
				}

				curpos = int(i + 1);
			}
			else
			{
				len++;
			}

		}

		if(curpos < (int)items.length() && len > 0)
		{
			this->items.push_back(
				std::pair<ListBoxItem,bool>(ListBoxItem(
				items.substr(curpos,len),newItemColor),false));

			int iWidth = getFont()->getTextWidth(this->items.back().first.text);
			if(iWidth > widestItem)
			{
				widestItem = iWidth;
			}
		}

		if(isSorted())
		{
			sort();
		}
		setWidestItem();
		updateScrollBars();
		setHoverIndex(getIndexAtPoint(agui::Point(getWidth() / 2,lastMouseY)));
		if(isHoverSelection())
		{
			setSelectedIndex(hoveredIndex);
		}
	}

	void ListBox::addItems( const std::vector<std::string> &items )
	{
		for(std::vector<std::string>::const_iterator it = items.begin();
			it != items.end(); ++it)
		{
			this->items.push_back(std::pair<ListBoxItem,bool>(ListBoxItem(*it,newItemColor),false));
			int iWidth = getFont()->getTextWidth(*it);
			if(iWidth > widestItem)
			{
				widestItem = iWidth;
			}

			for(std::vector<ListBoxListener*>::iterator iter = listboxListeners.begin();
				iter != listboxListeners.end(); ++iter)
			{
				(*iter)->itemAdded(this,*it);
			}
			
		}

		if(isSorted())
		{
			sort();
		}

		setWidestItem();
		updateScrollBars();
		setHoverIndex(getIndexAtPoint(agui::Point(getWidth() / 2,lastMouseY)));
		if(isHoverSelection())
		{
			setSelectedIndex(hoveredIndex);
		}
	}

	void ListBox::moveToSelection(int selection)
	{
		if(selection == -1 || !indexExists(selection))
		{
			return;
		}

		//find the location of the item
		int itemY = selection * getItemHeight();
		itemY += getVerticalOffset();

		int fixedheight = getInnerSize().getHeight();
		if(pChildHScroll->isVisible())
		{
			fixedheight -= pChildHScroll->getHeight();
		}
		//check the top
		if(itemY < 0)
		{
			pChildVScroll->setValue(pChildVScroll->getValue() + itemY);
		}
		//check at bottom
		else if(itemY + getItemHeight() >= fixedheight)
		{

			pChildVScroll->setValue(
				pChildVScroll->getValue() + ( (itemY + getItemHeight()) - fixedheight));
		}

		setHoverIndex(getIndexAtPoint(Point(0,lastMouseY)));

	}

	std::string ListBox::getItemAt( int index ) const
	{
		if(!indexExists(index))
		{
			return std::string("");
		}
		else
		{
			return items[index].first.text;
		}
	}

	void ListBox::setWrapping( bool wrapping )
	{
		if(this->wrapping != wrapping)
		{
			for(std::vector<ListBoxListener*>::iterator it = listboxListeners.begin();
				it != listboxListeners.end(); ++it)
			{
				(*it)->wrappingChanged(this,wrapping);
			}

			this->wrapping = wrapping;
		}
		
	}

	bool ListBox::isWrapping() const
	{
		return wrapping;
	}

	void ListBox::setWidestItem()
	{
		if(getLength() == 0)
		{
			widestItem = 0;
			return;
		}

		int cSz = 0;
		int h = 0;

		for(ListItem::const_iterator it = items.begin();
			it != items.end(); ++it)
		{
			cSz = getFont()->getTextWidth(it->first.text);
			if( cSz > h)
			{
				h = cSz;
			}
		}
		widestItem = h;

	}

	void ListBox::displatchSelectionEvent( int index, bool selected )
	{
		if(indexExists(index))
		{
			for(std::vector<SelectionListener*>::iterator it = selectionListeners.begin();
				it != selectionListeners.end(); ++it)
			{
				(*it)->selectionChanged(this,items[index].first.text,index,selected);
			}
		}
		else if(index == -1)
		{
			for(std::vector<SelectionListener*>::iterator it = selectionListeners.begin();
				it != selectionListeners.end(); ++it)
			{
				(*it)->selectionChanged(this,"",index,false);
			}
		}

		
	}

	void ListBox::addSelectionListener( SelectionListener* listener )
	{
		if(!listener)
		{
			return;
		}
		for(std::vector<SelectionListener*>::iterator it = 
			selectionListeners.begin();
			it != selectionListeners.end(); ++it)
		{
			if((*it) == listener)
				return;
		}

		selectionListeners.push_back(listener);
	}

	void ListBox::removeSelectionListener( SelectionListener* listener )
	{
		selectionListeners.erase(
			std::remove(selectionListeners.begin(),
			selectionListeners.end(), listener),
			selectionListeners.end());
	}

	
	void ListBox::addListBoxListener( ListBoxListener* listener )
	{
		if(!listener)
		{
			return;
		}
		for(std::vector<ListBoxListener*>::iterator it = 
			listboxListeners.begin();
			it != listboxListeners.end(); ++it)
		{
			if((*it) == listener)
				return;
		}

		listboxListeners.push_back(listener);
	}

	void ListBox::removeListBoxListener( ListBoxListener* listener )
	{
			listboxListeners.erase(
			std::remove(listboxListeners.begin(),
			listboxListeners.end(), listener),
			listboxListeners.end());
	}

	void ListBox::setVKeyScrollRate( int rate )
	{
		vKeyScrollRate = rate;
	}

	int ListBox::getVKeyScrollRate() const
	{
		return vKeyScrollRate;
	}

	bool ListBox::isMultiselectExtended() const
	{
		return multiselectExtended;
	}

	void ListBox::setMultiselectExtended( bool multiselect )
	{
		if(this->multiselectExtended != multiselect)
		{
			for(std::vector<ListBoxListener*>::iterator it = listboxListeners.begin();
				it != listboxListeners.end(); ++it)
			{
				(*it)->multiselectExtendedChanged(this,multiselect);
			}

			this->multiselectExtended = multiselect;
			setMultiselect(false);
		}

		if(!multiselect)
		{
			clearSelectedIndexes();
		}
	}

	int ListBox::getBottomSelectedIndex() const
	{

		int count = getLength() - 1;
		//finds the last selected index
		if(!items.empty())
		{
			for(ListItem::const_reverse_iterator it = items.rbegin();
				it != items.rend(); ++it)
			{
				if(it->second)
				{
					return count;
				}

				count--;
			}
		}

		return -1;
	}

	void ListBox::selectRange( int startIndex, int endIndex )
	{
		if(!indexExists(startIndex) || !indexExists(endIndex)
			|| (startIndex == endIndex && 
			getSelectedIndex() == getBottomSelectedIndex()) )
		{
			return;
		}

		if(startIndex > endIndex)
		{
			int temp = startIndex;
			startIndex = endIndex;
			endIndex = temp;
		}

		clearSelectedIndexes();

		for (int i = startIndex; i <= endIndex; ++i)
		{
			items[i].second = true;
			displatchSelectionEvent(i,true);
		}


	}

	bool ListBox::isMouseWheelSelection() const
	{
		return mouseWheelSelection;
	}

	void ListBox::setMouseWheelSelection( bool mWSelsection )
	{
    mouseWheelSelection = mWSelsection;
	}

	void ListBox::mouseDrag( MouseEvent &mouseEvent )
	{
		lastMouseY = mouseEvent.getY();
		
			if(mouseEvent.getButton() != MOUSE_BUTTON_LEFT)
			{
				return;
			}
			//ensure the bottom does not mess up

			int index = getIndexAtPoint(mouseEvent.getPosition());

			int y = mouseEvent.getPosition().getY();
			y -= getVerticalOffset();

			int itemIndex = y / getItemHeight();

			if(itemIndex >= getLength() - 1)
			{
				index = getLength() - 1;
			}

			if(isMultiselectExtended())
			{
				makeSelection(index,
					mouseEvent.control(),true);
			}
			else if(!isMultiselect())
			{
				if(index < 0)
				{
					index = 0;
				}
				setSelectedIndex(index);
			}
		
			dispatchActionEvent(ActionEvent(
				this));

			moveToSelection(index);

			mouseEvent.consume();
	}

	void ListBox::mouseUp( MouseEvent &mouseEvent )
	{
		setHoverIndex(getIndexAtPoint(mouseEvent.getPosition()));
		mouseEvent.consume();
	}

	void ListBox::paintBackground( const PaintEvent &paintEvent )
	{
		//draw background
		paintEvent.graphics()->drawFilledRectangle(getSizeRectangle(),getBackColor());

		Color  Top = Color(133,133,133);
		Color  Left = Color(133,133,133);
		Color  Bottom = Color(133,133,133);
		Color  Right = Color(133,133,133);


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

	const Dimension& ListBox::getHSrollSize() const
	{
		return pChildHScroll->getSize();
	}

	const Dimension& ListBox::getVScrollSize() const
	{
		return pChildVScroll->getSize();
	}

	int ListBox::getVisibleItemStart() const
	{
		return  -getVerticalOffset() / getItemHeight();
	}


	int ListBox::getVisibleItemCount() const
	{
		int hScrollHeight = 0;
		if(pChildHScroll->isVisible())
		{
			hScrollHeight = pChildHScroll->getHeight();
		}
		return ((getInnerSize().getHeight() - hScrollHeight) / getItemHeight()) + 2;
	}

	void ListBox::setHoverSelection( bool selecting )
	{
		hoverSelection = selecting;
	}

	bool ListBox::isHoverSelection() const
	{
		return hoverSelection;
	}

	bool ListBox::intersectionWithPoint( const Point &p ) const
	{
		return Rectangle(getMargin(SIDE_LEFT),
			getMargin(SIDE_TOP),getInnerWidth(),getInnerHeight()).pointInside(p);
	}

	void ListBox::resizeToContents()
	{
		resizeWidthToContents();
		resizeHeightToContents();
		resizeWidthToContents();
		resizeHeightToContents();
	}

	void ListBox::resizeWidthToContents()
	{
		int vscroll = 0;
		if(getVScrollPolicy() == SHOW_ALWAYS)
		{
			vscroll = pChildVScroll->getWidth();
		}

		setSize(getMargin(SIDE_LEFT) +
			getMargin(SIDE_RIGHT) +
			widestItem +
			vscroll + (vscroll != 0 ? 2 : 0),
			getHeight());

		if(pChildVScroll->isVisible())
		{
			vscroll = pChildVScroll->getWidth();

			setSize(getMargin(SIDE_LEFT) + 
				getMargin(SIDE_RIGHT) +
				widestItem +
				vscroll + (vscroll != 0 ? 2 : 0),
				getHeight());
		}
	}

	void ListBox::resizeHeightToContents()
	{
		int hscroll = 0;
		if(getHScrollPolicy() == SHOW_ALWAYS)
		{
			hscroll = pChildHScroll->getWidth();
		}
		setSize(getWidth(),
			getMargin(SIDE_TOP) +
			getMargin(SIDE_BOTTOM) +
			int(items.size()) * getItemHeight() +
			hscroll
			);
	}

	void ListBox::setSingleSelection()
	{
		setMultiselect(false);
		setMultiselectExtended(false);
	}

	bool ListBox::isSingleSelection() const
	{
		return !isMultiselect() && !isMultiselectExtended();
	}

	void ListBox::setNewItemColor( const agui::Color& color )
	{
		newItemColor = color;
	}

	const agui::Color& ListBox::getNewItemColor() const
	{
		return newItemColor;
	}

	const ListBoxItem& ListBox::getListItemAt( int index ) const
	{
		if(!indexExists(index))
		{
			throw agui::Exception("ListItem Not Found");
		}

		return items[index].first;
	}

	void ListBox::setItemToolTipText( const std::string& text, int index )
	{
		if(!indexExists(index))
		{
			throw agui::Exception("ListItem Not Found, ToolTip NOT set");
		}

		items[index].first.tooltip = text;
	}

	void ListBox::setItemTextColor( const agui::Color& color, int index )
	{
		if(!indexExists(index))
		{
			throw agui::Exception("ListItem Not Found, Item Color NOT set");
		}

		items[index].first.color = color;
	}

	std::string ListBox::getToolTipText()
	{
		if(indexExists(getHoverIndex()))
		{
			return items[getHoverIndex()].first.tooltip;
		}

		return Widget::getToolTipText();
	}

	void ListBox::setFontColor( const Color &color )
	{
		agui::Widget::setFontColor(color);
		setNewItemColor(color);
	}

	void ListBox::setAllowRightClickSelection( bool allow )
	{
		allowRightClick = allow;
	}

	bool ListBox::isRightClickSelectionAllowed() const
	{
		return allowRightClick;
	}

	void ListBox::_setWidestItem( int widest )
	{
		widestItem = widest;
	}

	int ListBox::getItemCount() const
	{
		return items.size();
	}

}

