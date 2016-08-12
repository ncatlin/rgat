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

#ifndef AGUI_SCROLLPANE_HPP
#define AGUI_SCROLLPANE_HPP

#include "Agui/Widget.hpp"
#include "Agui/EmptyWidget.hpp"
#include "Agui/Widgets/ScrollBar/HScrollBar.hpp"
#include "Agui/Widgets/ScrollBar/VScrollBar.hpp"
#include "Agui/WidgetListener.hpp"
#include "Agui/MouseListener.hpp"
#include "Agui/KeyboardListener.hpp"

namespace agui {
	/**
	 * Class that represents a ScrollPane to scroll an area that is larger than the size of the widget.
	 *
	 * Optional constructor widget:
	 *
	 * HScrollBar (Horizontal Scroll Bar)
	 *
	 * VScrollBar (Vertical Scroll Bar)
	 *
	 * Widget (Scroll Inset)
	 *
	 * Widget (Content Container)
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC ScrollPane : public Widget,
		protected HScrollBarListener, 
		protected VScrollBarListener,
		protected WidgetListener,
		protected MouseListener,
		protected KeyboardListener
	{

	private:
		ScrollPolicy hScrollPolicy;
		ScrollPolicy vScrollPolicy;

		int hKeyScrollRate;
		int vKeyScrollRate;

		HScrollBar *pChildHScroll;
		VScrollBar *pChildVScroll;
		Widget     *pChildContent;
		Widget     *pChildInset;

		bool isMaintainingHScroll;
		bool isMaintainingVScroll;
		bool isMaintainingInset;
		bool isMaintainingContent;
	protected:
	/**
     * Enables or disables the ScrollBars based on the ScrollPolicy.
     * @since 0.1.0
     */
		virtual void checkScrollPolicy();
	/**
     * Will resize the ScrollBars based on the policy.
     * @since 0.1.0
     */
		virtual void resizeSBsToPolicy();
	/**
     * Will adjust the ScrollBar ranges based on the content width and content height.
     * @since 0.1.0
     */
		virtual void adjustSBRanges();
	/**
     * Checks the policy, resizes the scroll bars, and adjusts the ranges.
     * @since 0.1.0
     */
		virtual void updateScrollBars();
	/**
     * Uses arrow keys to scroll when another widget has focus. 
	 * You can call this in the ScrollPane's keyDown and keyRepeat events if you need it when it
	 * is focused.
     * @since 0.1.0
     */
		virtual void keyAction(ExtendedKeyEnum key);

		virtual void paintBackground(const PaintEvent &paintEvent);
		virtual void paintComponent(const PaintEvent &paintEvent);
	/**
     * It is expected that the content widget's size is the size of the content.
	 *
	 * This will move the content widget into view. Override this if that is not what you want.
     * @since 0.1.0
     */
		virtual void valueChanged(HScrollBar* source, int val);
	/**
     * It is expected that the content widget's size is the size of the content.
	 *
	 * This will move the content widget into view. Override this if that is not what you want.
     * @since 0.1.0
     */
		virtual void valueChanged(VScrollBar* source,int val);

		virtual void textChanged(Widget* source, const std::string &text);
	/**
	 * This will resize the content widget to the content width and height and update the scrollbars.
	 * Override this if that is not what you want.
     * @since 0.1.0
     */
		virtual void sizeChanged(Widget* source, const Dimension &size);
	/**
	 * This will resize the content widget to the content width and height and update the scrollbars.
	 * Override this if that is not what you want.
     * @since 0.1.0
     */
		virtual void locationChanged(Widget* source, const Point &location);
		virtual void mouseWheelDownCB(MouseEvent &mouseEvent);
		virtual void mouseWheelUpCB(MouseEvent &mouseEvent);
		virtual void mouseWheelDown(MouseEvent &mouseEvent);
		virtual void mouseWheelUp(MouseEvent &mouseEvent);

		virtual void keyDownCB(KeyEvent &keyEvent);
		virtual void keyRepeatCB(KeyEvent &keyEvent);
		virtual void keyUpCB(KeyEvent &keyEvent);


		virtual void childAdded(Widget* source, Widget* widget);
		virtual void childRemoved(Widget* source, Widget* widget);
	public:
	/**
     * Also flags the content Widget's children.
     * @since 0.1.0
     */
		virtual void flagAllChildrenForDestruction();
		virtual bool intersectionWithPoint(const Point &p) const;

		/**
     * Adds the parameter Widget to the content Widget.
     * @since 0.1.0
     */
		virtual void add(Widget *widget);
	/**
     * Removes the parameter Widget from the content Widget.
     * @since 0.1.0
     */
		virtual void remove(Widget *widget);

	/**
     * @return The content width. 
	 * Used to determine the range and visibility of the HScrollBar.
	 *
	 * Override this if you do not use widgets and draw your own content.
     * @since 0.1.0
     */
		int getContentWidth() const;
			/**
     * @return The content height. 
	 * Used to determine the range and visibility of the VScrollBar.
	 *
	 * Override this if you do not use widgets and draw your own content.
     * @since 0.1.0
     */
		int getContentHeight() const;
	/**
	 * @return True if the Horizontal Scrollbar is needed (Does not consider policy).
     * @since 0.1.0
     */
		bool isHScrollNeeded() const;
			/**
	 * @return True if the Vertical Scrollbar is needed (Does not consider policy).
     * @since 0.1.0
     */
		bool isVScrollNeeded() const;
	/**
	 * Sets the Horizontal Scrollbar's policy. (SHOW_ALWAYS, SHOW_AUTO, SHOW_NEVER).
     * @since 0.1.0
     */
		void setHScrollPolicy(ScrollPolicy policy);
	/**
	 * Sets the Vertical Scrollbar's policy. (SHOW_ALWAYS, SHOW_AUTO, SHOW_NEVER).
     * @since 0.1.0
     */
		void setVScrollPolicy(ScrollPolicy policy);
	/**
	 * #return The Horizontal Scrollbar's policy. (SHOW_ALWAYS, SHOW_AUTO, SHOW_NEVER).
     * @since 0.1.0
     */
		ScrollPolicy getHScrollPolicy() const;
	/**
	 * @return The Vertical Scrollbar's policy. (SHOW_ALWAYS, SHOW_AUTO, SHOW_NEVER).
     * @since 0.1.0
     */
		ScrollPolicy getVScrollPolicy() const;

	/**
	 * This will resize the content widget to the content width and height and update the scrollbars.
	 * Override this if that is not what you want.
     * @since 0.1.0
     */
		virtual void setSize(const Dimension &size);
	/**
	 * This will resize the content widget to the content width and height and update the scrollbars.
	 * Override this if that is not what you want.
     * @since 0.1.0
     */
		virtual void setSize(int width, int height);

	/**
	 * Sets how many values in addition to the actual delta mouse wheel, 
	 * the vertical scrollbar will be 
	 * moved when a mouse wheel event is triggered.
	 *
	 * The widget under the mouse has priority. 
	 * If a widget like a ListBox consumes the event, it will scroll instead.
	 *
     * @since 0.1.0
     */
		virtual void setWheelScrollRate(int rate);
		
	/**
	 * @return How many values in addition to the actual delta mouse wheel, 
	 * the vertical scrollbar will be 
	 * moved when a mouse wheel event is triggered.
	 *
	 * The widget under the mouse has priority. 
	 * If a widget like a ListBox consumes the event, it will scroll instead.
     * @since 0.1.0
     */
		virtual int getWheelScrollRate() const;

	/**
	 * Sets how many values the left and right keys will move the Horizontal Scrollbar.
     * @since 0.1.0
     */
		virtual void setHKeyScrollRate(int rate);
	/**
	 * @return How many values the left and right keys will move the Horizontal Scrollbar.
     * @since 0.1.0
     */
		virtual int getHKeyScrollRate() const;
			/**
	 * Sets how many values the up and down keys will move the Vertical Scrollbar.
     * @since 0.1.0
     */
		virtual void setVKeyScrollRate(int rate);
	/**
	 * @return How many values the up and down keys will move the Vertical Scrollbar.
     * @since 0.1.0
     */
		virtual int getVKeyScrollRate() const;

	/**
	 * @return How much pressing the top arrow will move the thumb.
     * @since 0.1.0
     */
		int getTopArrowAmount() const;
	/**
	 * @return How much pressing the bottom arrow will move the thumb.
     * @since 0.1.0
     */
		int getBottomArrowAmount() const;
	/**
	 * @return How much pressing the left arrow will move the thumb.
     * @since 0.1.0
     */
		int getLeftArrowAmount() const;
	/**
	 * @return How much pressing the right arrow will move the thumb.
     * @since 0.1.0
     */
		int getRightArrowAmount() const;
	/**
	 * Sets how much pressing the top arrow will move the thumb.
     * @since 0.1.0
     */
		void setTopArrowAmount(int amount);
	/**
	 * Sets how much pressing the bottom arrow will move the thumb.
     * @since 0.1.0
     */
		void setBottomArrowAmount(int amount);
	/**
	 * Sets how much pressing the left arrow will move the thumb.
     * @since 0.1.0
     */
		void setLeftArrowAmount(int amount);
	/**
	 * Sets how much pressing the right arrow will move the thumb.
     * @since 0.1.0
     */
		void setRightArrowAmount(int amount);
	/**
	 * Sets the smallest the Horizontal thumb will ever be.
     * @since 0.1.0
     */
		void setHMinThumbSize(int size);
	/**
	 * @return The smallest the Horizontal thumb will ever be.
     * @since 0.1.0
     */
		int getHMinThumbSize() const;
	/**
	 * Sets the smallest the Vertical thumb will ever be.
     * @since 0.1.0
     */
		void setVMinThumbSize(int size);
	/**
	 * @return The smallest the Vertical thumb will ever be.
     * @since 0.1.0
     */
		int getVMinThumbSize() const;

	/**
	 * Will resize the width so that the content width is fully seen without needing to scroll.
     * @since 0.1.0
     */
		virtual void resizeWidthToContents();
	/**
	 * Will resize the height so that the content height is fully seen without needing to scroll.
     * @since 0.1.0
     */
		virtual void resizeHeightToContents();
	/**
	 * Will resize both the width and height so that the content width and height
	 * is fully seen without needing to scroll.
     * @since 0.1.0
     */
		virtual void resizeToContents();
	/**
	 * Construct with optional HorizontalScrollBar ,
	 * VerticalScrollBar , ScrollInset Widget , and content Widget.
     * @since 0.1.0
     */
		ScrollPane(HScrollBar *hScroll = NULL,
			VScrollBar* vScroll = NULL,
			Widget* scrollBarInset = NULL,
			Widget* contentContainer = NULL);

	/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~ScrollPane(void);
	};
}
#endif
