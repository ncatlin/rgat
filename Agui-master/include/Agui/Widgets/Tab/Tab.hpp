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

#ifndef AGUI_TAB_HPP
#define AGUI_TAB_HPP

#include "Agui/Widget.hpp"
namespace agui {
	class AGUI_CORE_DECLSPEC TabbedPane;
	/**
	 * Class that represents a Tab.
	 *
	 * Used with:
	 *
	 * TabbedPane
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC Tab : public Widget
	{
		bool mouseInside;
		TabbedPane *tabPane;
	protected:
		virtual void paintComponent(const PaintEvent &paintEvent);
		virtual void paintBackground(const PaintEvent &paintEvent);
	public:
		/**
	 * Uses left and right arrow keys to navigate tabs in the tab pane.
	 *
	 * If the TabbedPane this tab belongs to gets focus, it will be forwarded
	 * to the selected tab.
     * @since 0.1.0
     */
		virtual void keyDown(KeyEvent &keyEvent);
	/**
	 * Uses left and right arrow keys to navigate tabs in the tab pane.
	 *
	 * If the TabbedPane this tab belongs to gets focus, it will be forwarded
	 * to the selected tab.
     * @since 0.1.0
     */
		virtual void keyRepeat(KeyEvent &keyEvent);
	/**
	 * Sets the TabbedPane this Tab belongs to.
	 *
	 * Called by the TabPane to add itself to this Tab.
     * @since 0.1.0
     */
		virtual void setTabPane(TabbedPane* pane);
		virtual void mouseEnter(MouseEvent &mouseEvent);
		virtual void mouseLeave(MouseEvent &mouseEvent);
	/**
	 * @return True if the mouse is inside this tab.
     * @since 0.1.0
     */
		bool isMouseInside() const;
	/**
	 * Called by the TabbedPane when this Tab becomes the selected Tab.
     * @since 0.1.0
     */
		virtual void gainedSelection();
	/**
	 * Called by the TabbedPane when this Tab is no longer the selected Tab.
     * @since 0.1.0
     */
		virtual void lostSelection();
	/**
	 * Sets this tab as the selected tab (if possible).
     * @since 0.1.0
     */
		virtual void mouseDown(MouseEvent &mouseEvent);
	/**
	 * @return True if this tab is the selected tab in the TabbedPane it belongs to.
     * @since 0.1.0
     */
		virtual bool isSelectedTab() const;
		virtual void setFont(const Font *font);
	/**
	 * Resizes the Tab to fit its caption.
     * @since 0.1.0
     */
		virtual void resizeToContents();
		virtual void setText(const std::string &text);
	/**
	 * Default constructor.
     * @since 0.1.0
     */
		Tab(void);
	/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~Tab(void);
	};
}
#endif