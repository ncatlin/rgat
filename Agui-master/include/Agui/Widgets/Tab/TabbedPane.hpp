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

#ifndef AGUI_TABBED_PANE_HPP
#define AGUI_TABBED_PANE_HPP

#include "Agui/Widget.hpp"
#include "Agui/EmptyWidget.hpp"
#include "Agui/Widgets/Tab/Tab.hpp"
#include "Agui/Widgets/Tab/TabbedPaneListener.hpp"
namespace agui {
	/**
	 * Class that represents a container to hold Tabs.
	 *
	 * Uses:
	 *
	 * Tab
	 *
	 * Optional constructor widget:
	 *
	 * Widget (Tab container)
	 *
	 * Widget  (Content Widget container)
	 *
	 * Widget (Bottom Arrow)
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class TabbedPane :
		public Widget
	{
		Widget *tabContainer;
		Widget *widgetContainer;

		int highestTab;
		int totalTabWidth;
		bool isMaintainingWidgetContainer;
		bool isMaintainingTabContainer;
		int tabPadding;
		bool resizeTabContent;
		std::vector<TabbedPaneListener*> tabListeners;
		std::vector<std::pair<Tab*,Widget*> > tabs;
		std::pair<Tab*,Widget*> selectedTab;
	protected:
	/**
	 * Resizes and repositions the tabs.
     * @since 0.1.0
     */
		virtual void adjustTabs();
	/**
	 * Resizes and repositions the container that holds the widget associated with the selected Tab.
     * @since 0.1.0
     */
		virtual void adjustWidgetContainer();
		virtual void paintComponent(const PaintEvent &paintEvent);
		virtual void paintBackground(const PaintEvent &paintEvent);
	public:
	/**
	 * Flags, in addition, all Tabs and their associated Widget.
     * @since 0.1.0
     */
		virtual void flagAllChildrenForDestruction();
	/**
	 * Adds the parameter TabbedPaneListener.
     * @since 0.1.0
     */
		void addTabbedPaneListener(TabbedPaneListener* listener);
	/**
	 * Removes the parameter TabbedPaneListener.
     * @since 0.1.0
     */
		void removeTabbedPaneListener(TabbedPaneListener* listener);
	/**
	 * Sets the amount of space between each Tab.
     * @since 0.1.0
     */
		virtual void setTabPadding(int padding);
	/**
	 * @return The amount of space between each Tab.
     * @since 0.1.0
     */
		int getTabPadding() const;
		virtual void setFont(const Font *font);
		virtual void focusGained();
			/**
	 * Selects the next Tab and gives it focus.
     * @since 0.1.0
     */
		virtual void keyDown(KeyEvent &keyEvent);
	/**
	 * @return The height of the highest Tab.
     * @since 0.1.0
     */
		virtual int getHighestTabHeight() const;
	/**
	 * Adjusts the size of the TabbedPane, done automatically when it resizes.
     * @since 0.1.0
     */
		virtual void adjustSize();
		virtual void setSize(const Dimension &size);
		virtual void setSize(int width, int height);
	/**
	 * Adds a Tab and its associated content Widget.
     * @since 0.1.0
     */
		virtual void addTab(Tab *tab, Widget *content);
	/**
	 * Removes a Tab and its associated content Widget.
     * @since 0.1.0
     */
		virtual void removeTab(Tab *tab);
	/**
	 * Removes a Tab and its associated content Widget by index.
     * @since 0.1.0
     */
		virtual void removeTab(int index);
	/**
	 * @return The index of the parameter tab, -1 if not found.
     * @since 0.1.0
     */
		virtual int getIndex(Tab *tab) const;
	/**
	 * @return The index of the selected tab, -1 if not found.
     * @since 0.1.0
     */
		virtual int getSelectedIndex() const;
	/**
	 * Sets the selected Tab to the parameter one and shows its content.
     * @since 0.1.0
     */
		virtual void setSelectedTab(Tab *tab);
	/**
	 * Sets the selected Tab to the parameter index one and shows its content.
     * @since 0.1.0
     */
		virtual void setSelectedTab(int index);
	/**
	 * @return The selected Tab or NULL if none are selected.
     * @since 0.1.0
     */
		virtual Tab* getSelectedTab() const;
	/**
	 * @return True if the content Widget will be resized to fit the container.
     * @since 0.1.0
     */
		bool isResizingTabContent() const;
	/**
	 * @Sets whether or not the content Widget will be resized to fit the container.
     * @since 0.1.0
     */
		void setResizeTabContent(bool resizing);
    virtual void resizeToContentsRecursive();
    virtual void resizeToContents();
	/**
	 * Construct with optional tab container and content widget container.
     * @since 0.1.0
     */
		TabbedPane(Widget * tabContainer = NULL,
			Widget *widgetContainer = NULL);
	/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~TabbedPane(void);
	};
}
#endif
