/*   _____                           
 * /\  _  \                     __    
 * \ \ _\ \      __    __  __ /_\   
 *  \ \  __ \   /'_ `\ /\ /\ \/\ \  
 *   \ \ /\ \ /\ _\ \\ \ _\ \\ \ \ 
 *    \ _\ _\\ ____ \\ ____/ \ _\
 *     /_//_/ /____\ \/___/   /_/
 *                /____/             
 *                _/__/              
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

#include "Agui/Widgets/Tab/TabbedPane.hpp"
namespace agui {
  TabbedPane::TabbedPane( Widget * tabContainer /*= NULL*/,
                   Widget *widgetContainer /*= NULL*/ )
   : highestTab(0), tabPadding(0), resizeTabContent(false),
     selectedTab(reinterpret_cast<Tab*>(NULL),reinterpret_cast<Widget*>(NULL))
  {
    if(tabContainer)
    {
      isMaintainingTabContainer = false;
      this->tabContainer = tabContainer;
    }
    else
    {
      isMaintainingTabContainer = true;
      this->tabContainer = new EmptyWidget();
    }

    if(widgetContainer)
    {
      isMaintainingWidgetContainer = false;
      this->widgetContainer = widgetContainer;
    }
    else
    {
      isMaintainingWidgetContainer = true;
      this->widgetContainer = new EmptyWidget();
    }

    addPrivateChild(this->tabContainer);
    addPrivateChild(this->widgetContainer);
    setTabable(true);
    setFocusable(true);
	setReverseTabable(false);

    adjustTabs();
  }

  TabbedPane::~TabbedPane(void)
  {
    for(std::vector<TabbedPaneListener*>::iterator it = tabListeners.begin();
      it != tabListeners.end(); ++it)
    {
      (*it)->death(this);
    }

    int sz = int(tabs.size());

    for(int i = 0; i < sz; ++i)
    {
      removeTab(0);
    }
    if(isMaintainingTabContainer)
    delete tabContainer;

    if(isMaintainingWidgetContainer)
    delete widgetContainer;
  }

  void TabbedPane::adjustTabs()
  {
    tabContainer->setLocation(0,0);

    highestTab = 0;

    //get highest tab
    for(std::vector<std::pair<Tab*,Widget*> >::iterator it =
      tabs.begin(); it != tabs.end(); ++it)
    {
      if(it->first->getSize().getHeight() > highestTab)
      {
        highestTab = it->first->getSize().getHeight();
      }
    }

    //set container size
    tabContainer->setSize(getInnerSize().getWidth(),highestTab);

    //move the tabs

    totalTabWidth = 0;
    for(std::vector<std::pair<Tab*,Widget*> >::iterator it =
      tabs.begin(); it != tabs.end(); ++it)
    {
      it->first->setLocation(totalTabWidth,
        tabContainer->getSize().getHeight() - 
        it->first->getSize().getHeight());

      totalTabWidth += it->first->getSize().getWidth() + getTabPadding();
    }
  }

  void TabbedPane::adjustWidgetContainer()
  {
    widgetContainer->setSize(getInnerSize().getWidth(),
      getInnerSize().getHeight() - highestTab);

    widgetContainer->setLocation(0,highestTab);

    if(isResizingTabContent() && selectedTab.second)
    {
      selectedTab.second->setSize(widgetContainer->getInnerSize());
    }
    if(selectedTab.second)
    {
      selectedTab.second->setLocation(0,0);
    }

  }

  void TabbedPane::adjustSize()
  {
    adjustTabs();
    adjustWidgetContainer();
  }

  void TabbedPane::setResizeTabContent( bool resizing )
  {
    resizeTabContent = resizing;
    for(std::vector<TabbedPaneListener*>::iterator it = tabListeners.begin();
      it != tabListeners.end(); ++it)
    {
      (*it)->resizingTabContentChanged(this,resizing);
    }
  }

  bool TabbedPane::isResizingTabContent() const
  {
    return resizeTabContent;
  }

  void TabbedPane::addTab( Tab *tab, Widget *content )
  {
    if(!tab || !content)
    {
      return;
    }

    tab->setTabPane(this);
    tabs.push_back(std::pair<Tab*,Widget*>(tab,content));
    
    tabContainer->add(tab);

    if(tabs.size() == 1 && getSelectedTab() == NULL)
    {
      setSelectedTab(tab);
    }

    adjustSize();

    for(std::vector<TabbedPaneListener*>::iterator it = tabListeners.begin();
      it != tabListeners.end(); ++it)
    {
      (*it)->tabAdded(this,tab,content);
    }

  }

  void TabbedPane::setSelectedTab( Tab *tab )
  {
    if(tab == NULL)
    {
      setSelectedTab(-1);
      return;
    }

    int foundIndex = getIndex(tab);
    if(foundIndex != -1)
    {
      setSelectedTab(foundIndex);
    }



  }

  void TabbedPane::setSelectedTab( int index )
  {
    //set to no selected tab
    if(index == -1)
    {
      if(selectedTab.first)
      {
        selectedTab.first->lostSelection();
        widgetContainer->remove(selectedTab.second);
      }
      
      selectedTab.first = NULL;
      selectedTab.second = NULL;

      adjustSize();
      return;
    }
    //set to desired tab
    else if(index < (int)tabs.size())
    {
      //no need to select the same thing
      if(tabs[index].first == selectedTab.first)
      {
        return;
      }

      if(selectedTab.first)
      {
        selectedTab.first->lostSelection();
      }
      Widget* oldSecTab = NULL;
      if(selectedTab.second)
      {
        oldSecTab = selectedTab.second;
      }

        selectedTab = tabs[index];
        selectedTab.first->gainedSelection();

        widgetContainer->add(selectedTab.second);
        selectedTab.first->focus();
        selectedTab.first->bringToFront();

        if(oldSecTab)
        {
          widgetContainer->remove(oldSecTab);
        }
        adjustSize();

        for(std::vector<TabbedPaneListener*>::iterator it = tabListeners.begin();
          it != tabListeners.end(); ++it)
        {
          (*it)->selectedTabChanged(this,tabs[index].first);
        }
      
    }
  }

  Tab* TabbedPane::getSelectedTab() const
  {
    return selectedTab.first;
  }

  void TabbedPane::setSize( const Dimension &size )
  {
    Widget::setSize(size);
    adjustSize();
  }

  void TabbedPane::setSize( int width, int height )
  {
    Widget::setSize(width,height);
  }

  void TabbedPane::paintComponent( const PaintEvent &paintEvent )
  {
  }

  int TabbedPane::getHighestTabHeight() const
  {
    return highestTab;
  }

  void TabbedPane::removeTab( Tab *tab )
  {
    int index = getIndex(tab);

    if(index != -1)
    {
      removeTab(index);
    }
  }

  void TabbedPane::removeTab( int index )
  {
    if(index < 0 || index >= (int)tabs.size())
    {
      return;
    }

    int newSelectedIndex = getSelectedIndex();

    if(newSelectedIndex > 0 && tabs.size() >= 2)
    {
      newSelectedIndex--;
    }
    else if(newSelectedIndex == 0 && tabs.size() == 1)
    {
      newSelectedIndex = -1;
    }

    tabs[index].first->setTabPane(NULL);

    tabContainer->remove(tabs[index].first);
    tabs.erase(tabs.begin() + index);

    for(std::vector<TabbedPaneListener*>::iterator it = tabListeners.begin();
      it != tabListeners.end(); ++it)
    {
      (*it)->tabRemoved(this,tabs[index].first);
    }

    setSelectedTab(newSelectedIndex);
    
  }

  int TabbedPane::getIndex( Tab *tab ) const
  {
    int index = -1;
    int foundIndex = -1;
    for(std::vector<std::pair<Tab*,Widget*> >::const_iterator it =
      tabs.begin(); it != tabs.end(); ++it)
    {
      index++;
      if(it->first == tab)
      {
        foundIndex = index;
      }
    }

    return foundIndex;

  }

  int TabbedPane::getSelectedIndex() const
  {
    return getIndex(getSelectedTab());
  }

  void TabbedPane::keyDown( KeyEvent &keyEvent )
  {
    if(keyEvent.getExtendedKey() == EXT_KEY_LEFT)
    {
      if(getSelectedIndex() > 0)
      {
        setSelectedTab(getSelectedIndex() - 1);
        keyEvent.consume();
      }
    }
    else if(keyEvent.getExtendedKey() == EXT_KEY_RIGHT)
    {
      setSelectedTab(getSelectedIndex() + 1);
      keyEvent.consume();
    }
  }

  void TabbedPane::focusGained()
  {
    Widget::focusGained();
    if(getSelectedTab() != NULL)
    {
      getSelectedTab()->focus();
    }
  }

  void TabbedPane::paintBackground( const PaintEvent &paintEvent )
  {
    int szMinusH = getSize().getHeight() - tabContainer->getSize().getHeight()
      + getMargin(SIDE_TOP);

    paintEvent.graphics()->drawFilledRectangle(Rectangle(0,tabContainer->getSize().getHeight(),
      getSize().getWidth(),szMinusH),
      getBackColor());


    Color  Top = Color(133,133,133);
    Color  Left = Color(133,133,133);
    Color  Bottom = Color(133,133,133);
    Color  Right = Color(133,133,133);


    //top
    paintEvent.graphics()->drawLine(Point(0,tabContainer->getSize().getHeight() + 
      getMargin(SIDE_TOP)),
      Point(getSize().getWidth(),
      tabContainer->getSize().getHeight() + getMargin(SIDE_TOP)),Top);
    //left
    paintEvent.graphics()->drawLine(Point(1,tabContainer->getSize().getHeight() + 
      getMargin(SIDE_TOP)),
      Point(1,getSize().getHeight()),Left);

    //right
    paintEvent.graphics()->drawLine(Point(getSize().getWidth() ,
      tabContainer->getSize().getHeight() + getMargin(SIDE_TOP)),
      Point(getSize().getWidth() ,getSize().getHeight()),Right);

    //bottom
    paintEvent.graphics()->drawLine(Point(0,getSize().getHeight()),
      Point(getSize().getWidth(),getSize().getHeight()),Bottom);
  }

  void TabbedPane::setFont( const Font *font )
  {
    Widget::setFont(font);
    for(int i = 0; i < (int)tabs.size(); ++i)
    {
      tabs[i].first->resizeToContents();
    }
    adjustSize();
  }

  void TabbedPane::setTabPadding( int padding )
  {
    tabPadding = padding;
    adjustSize();
  }

  int TabbedPane::getTabPadding() const
  {
    return tabPadding;
  }

  void TabbedPane::addTabbedPaneListener( TabbedPaneListener* listener )
  {
    if(!listener)
    {
      return;
    }
    for(std::vector<TabbedPaneListener*>::iterator it = 
      tabListeners.begin();
      it != tabListeners.end(); ++it)
    {
      if((*it) == listener)
        return;
    }

    tabListeners.push_back(listener);
  }

  void TabbedPane::removeTabbedPaneListener( TabbedPaneListener* listener )
  {
    tabListeners.erase(
      std::remove(tabListeners.begin(),
      tabListeners.end(), listener),
      tabListeners.end());
  }

  void TabbedPane::flagAllChildrenForDestruction()
  {
    Widget::flagAllChildrenForDestruction();
    for(size_t i = 0; i < tabs.size(); ++i)
    {
      tabs[i].first->flagForDestruction();
      tabs[i].first->flagAllChildrenForDestruction();

      tabs[i].second->flagForDestruction();
      tabs[i].second->flagAllChildrenForDestruction();
    }
  }

  void TabbedPane::resizeToContentsRecursive()
  {
    for (int i = 0; i < (int)tabs.size(); ++i)
    {
      tabs[i].second->resizeToContentsRecursive();
      tabs[i].first->resizeToContents();
    }
    resizeToContents();
  }

  void TabbedPane::resizeToContents()
  {
    adjustSize();

    int highestWidget = 0;
    int widestWidget = 0;
    for (int i = 0; i < (int)tabs.size(); ++i)
    {
      highestWidget = std::max(highestWidget, tabs[i].second->getHeight());
      widestWidget = std::max(widestWidget, tabs[i].second->getWidth());
    }
    setSize(std::max(widestWidget, totalTabWidth), highestWidget + highestTab);
  }
}
