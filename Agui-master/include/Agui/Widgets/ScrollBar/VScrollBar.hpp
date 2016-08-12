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

#ifndef AGUI_VSCROLLBAR_HPP
#define AGUI_VSCROLLBAR_HPP

#include "Agui/Widget.hpp"
#include "Agui/Widgets/Button/Button.hpp"
#include "Agui/MouseListener.hpp"
#include "Agui/Widgets/ScrollBar/VScrollBarListener.hpp"
namespace agui {
		/**
	 * Class that represents a Vertical ScrollBar.
	 *
	 * ActionEvent when:
	 * Value changes.
	 *
	 * Optional constructor widget:
	 *
	 * Widget (Top Arrow)
	 *
	 * Widget  (Thumb)
	 *
	 * Widget (Bottom Arrow)
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC VScrollBar : 
		public Widget, protected MouseListener
	{
	private:
		std::vector<VScrollBarListener*> vScrollListeners;
		int largeAmount;
		int topArrowAmount;
		int bottomArrowAmount;
		double lastArrowTick;
		int minValue;
		int maxValue;
		int wheelSpeed;
		int currentValue;

		int downThumbPos;
		int downMousePos;

		bool topArrowDown;
		bool bottomArrowDown;

		float autoScrollStartInterval;

		int minThumbSize;

		bool stickToBottom;

		Widget *pChildThumb;
		Widget *pChildTopArrow;
		Widget *pChildBottomArrow;

		bool isMaintainingThumb;
		bool isMaintainingTopArrow;
		bool isMaintainingBottomArrow;

	protected:
	/**
	 * Resizes the arrows when the bar resizes.
     * @since 0.1.0
     */
		virtual void resizeArrows();
	/**
	 * Resizes the thumb to fit page requirements.
     * @since 0.1.0
     */
		virtual void resizeThumb();
	/**
	 * Positions the thumb on resize.
     * @since 0.1.0
     */
		virtual void positionThumb();
	/**
	 * Positions the arrows on resize.
     * @since 0.1.0
     */
		virtual void positionArrows();
	/**
	 * @return The maximum thumb size with constraint considerations.
     * @since 0.1.0
     */
		
		int			getAdjustedMaxThumbSize() const;
			/**
	 * Moves the thumb by bottomArrowAmount when the arrow is pressed and held down.
     * @since 0.1.0
     */
		virtual void arrowMoveDown();
	/**
	 * Moves the thumb by topArrowAmount when the arrow is pressed and held down.
     * @since 0.1.0
     */
		virtual void arrowMoveUp();
		virtual void paintComponent(const PaintEvent &paintEvent);
		virtual void paintBackground(const PaintEvent &paintEvent);
		virtual void mouseDownCB(MouseEvent &mouseEvent);
		virtual void mouseUpCB(MouseEvent &mouseEvent);
		virtual void mouseDragCB(MouseEvent &mouseEvent);
		virtual void mouseWheelDownCB(MouseEvent &mouseEvent);
		virtual void mouseWheelUpCB(MouseEvent &mouseEvent);
	/**
	 * Called in the logic method. Ensures the arrow continues to 
	 * move the thumb if it is not released.
     * @since 0.1.0
     */
		virtual void handleAutoscroll(double timeElapsed);

	public:
		virtual void setSize(const Dimension &size);
		virtual void setSize(int width, int height);

		virtual void mouseDown(MouseEvent &mouseEvent);
	/**
	 * Sets the amount to scroll in wheelScrollUp and wheelScrollDown.
     * @since 0.1.0
     */
		void setMouseWheelAmount(int amount);
	/**
	 * @return The amount to scroll in wheelScrollUp and wheelScrollDown.
     * @since 0.1.0
     */
		int getMouseWheelAmount() const;
	/**
	 * Moves the ScrollBar by the amount set in setMouseWheelAmount and 
	 * the deltaWheel parameter. deltaWheel is NOT expected to be an absolute value.
     * @since 0.1.0
     */
		virtual void wheelScrollDown(int deltaWheel);
			/**
	 * Moves the ScrollBar by the amount set in setMouseWheelAmount and 
	 * the deltaWheel parameter. deltaWheel is NOT expected to be an absolute value.
     * @since 0.1.0
     */
		virtual void wheelScrollUp(int deltaWheel);
			/**
	 * @return True if the thumb is at the maximum value, it should
	 * stick there when the bar is resized. Useful for chat TextBoxes.
     * @since 0.1.0
     */
		bool isStickingToBottom() const;
	/**
	 * Sets whether or not if the thumb is at the maximum value, it should
	 * stick there when the bar is resized. Useful for chat TextBoxes.
     * @since 0.1.0
     */
		void setStickToBottom();
	/**
	 * Adjusts the scrollbar so that the largeAmount is pageHeight 
	 * and there are enough pages to fill the content height.
     * @since 0.1.0
     */
		void setRangeFromPage(int pageHeight, int contentHeight);
	/**
	 * Sets the large amount. This is often the size of the thumb, or the size of a page.
     * @since 0.1.0
     */
		void setLargeAmount(int amount);
	/**
	 * Sets the value of the scroll bar. Must be between min and max value.
     * @since 0.1.0
     */
		void setValue(int val);
	/**
	 * Sets the minimum value of the scroll bar. Can be negative.
     * @since 0.1.0
     */
		void setMinValue(int val);
	/**
	 * Sets the maximum value of the scroll bar. Can be negative.
     * @since 0.1.0
     */
		void setMaxValue(int val);
		virtual void mouseWheelDown(MouseEvent &mouseEvent);
		virtual void mouseWheelUp(MouseEvent &mouseEvent);
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
	 * @return The value of the scrollbar when the 
	 * thumb is at the parameter position on the Y axis.
     * @since 0.1.0
     */
		int getValueFromPosition(int position) const;
	/**
	 * @return Value from 0.0f to 1.0f indicating how far into the values the thumb is.
	 * When the thumb is at min value it returns 0.0f, if it is at max value, 1.0f.
     * @since 0.1.0
     */
		float getRelativeValue() const;
	/**
	 * @return The large amount. This is often the size of the thumb, or the size of a page.
     * @since 0.1.0
     */
		int getLargeAmount() const;
	/**
	 * @return The value of the bar. It is also the value that the thumb is on.
     * @since 0.1.0
     */
		int getValue() const;
			/**
	 * @return The minimum value of the scrollbar.
     * @since 0.1.0
     */
		int getMinValue() const;
	/**
	 * @return The maximum value of the scrollbar.
     * @since 0.1.0
     */
		int getMaxValue() const;
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
	 * @return True if the mouse is pressed on the top arrow and has not been released.
     * @since 0.1.0
     */
		bool isTopArrowDown() const;
	/**
	 * @return True if the mouse is pressed on the bottom arrow and has not been released.
     * @since 0.1.0
     */
		bool isBottomArrowDown() const;
		
	/**
	 * @return The maximum size of the thumb. Subtracts the arrow heights from the inner height.
     * @since 0.1.0
     */
		int getMaxThumbSize() const;

	/**
	 * Sets the height of the arrows.
     * @since 0.1.0
     */
		virtual void setArrowHeight(int height);
	/**
	 * @return The height of the arrows.
     * @since 0.1.0
     */
		virtual int getArrowHeight() const;

	/**
	 * @return Increases the value by 1.
     * @since 0.1.0
     */
		virtual void scrollDown();
		/**
	 * @return Decreases the value by 1.
     * @since 0.1.0
     */
		virtual void scrollUp();
	/**
	 * @return True if the thumb is completely at the top.
     * @since 0.1.0
     */
		virtual bool  isThumbAtTop() const;
	/**
	 * @return True if the thumb is completely at the top.
     * @since 0.1.0
     */
		virtual bool isThumbAtBottom() const;
	/**
	 * Adds the parameter Vertical ScrollBar Listener.
     * @since 0.1.0
     */
		void addVScrollBarListener(VScrollBarListener* listener);
	/**
	 * Removes the parameter Vertical ScrollBar Listener.
     * @since 0.1.0
     */
		void removeVScrollBarListener(VScrollBarListener* listener);
	/**
	 * Sets the amount of time, in seconds, that the mouse must be pressed on
	 * an arrow for auto scrolling to start.
     * @since 0.1.0
     */
		void setAutoscrollStartInterval(float interval);
		/**
	 * @return The amount of time, in seconds, that the mouse must be pressed on
	 * an arrow for auto scrolling to start.
     * @since 0.1.0
     */
		float getAutoscrollStartInterval() const;
	/**
	 * @return The smallest the thumb will ever be.
     * @since 0.1.0
     */
		int getMinThumbHeight() const;
	/**
	 * Sets the smallest the thumb will ever be.
     * @since 0.1.0
     */
		virtual void setMinThumbHeight(int size);

		virtual void logic(double timeElapsed);
	/**
	 * Construct with optional Thumb, Top Arrow, and Bottom Arrow widgets.
     * @since 0.1.0
     */
		VScrollBar(Widget *thumb = NULL, Widget *topArrow = NULL,
			Widget *bottomArrow = NULL);
	/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~VScrollBar(void);
	};

	
}
#endif