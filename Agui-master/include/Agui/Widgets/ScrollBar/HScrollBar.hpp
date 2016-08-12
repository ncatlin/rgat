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

#ifndef AGUI_HSCROLLBAR_HPP
#define AGUI_HSCROLLBAR_HPP
#include "Agui/Widget.hpp"
#include "Agui/Widgets/Button/Button.hpp"
#include "Agui/MouseListener.hpp"
#include "Agui/Widgets/ScrollBar/HScrollBarListener.hpp"
namespace agui {
	/**
	 * Class that represents a Horizontal ScrollBar.
	 *
	 * ActionEvent when:
	 * Value changes.
	 *
	 * Optional constructor widget:
	 *
	 * Widget (Left Arrow)
	 *
	 * Widget  (Thumb)
	 *
	 * Widget (Right Arrow)
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC HScrollBar :	public Widget, 
		protected MouseListener
	{
	private:
		std::vector<HScrollBarListener*>hScrollListeners;
		double lastArrowTick;
		int largeAmount;
		int leftArrowAmount;
		int rightArrowAmount;
		int minValue;
		int maxValue;
		int currentValue;

		int downThumbPos;
		int downMousePos;

		bool leftArrowDown;
		bool rightArrowDown;

		float autoScrollStartInterval;

		int minThumbSize;

		Widget *pChildThumb;
		Widget *pChildLeftArrow;
		Widget *pChildRightArrow;

		bool isMaintainingThumb;
		bool isMaintainingLeftArrow;
		bool isMaintainingRightArrow;
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
	 * Moves the thumb by rightArrowAmount when the arrow is pressed and held down.
     * @since 0.1.0
     */
		virtual void arrowMoveRight();
			/**
	 * Moves the thumb by leftArrowAmount when the arrow is pressed and held down.
     * @since 0.1.0
     */
		virtual void arrowMoveLeft();
			/**
	 * @return The maximum thumb size with constraint considerations.
     * @since 0.1.0
     */
		int getAdjustedMaxThumbSize() const;
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
	/**
	 * Handles auto scrolling when an arrow is held down.
     * @since 0.1.0
     */
		virtual void logic(double timeElapsed);
		virtual void setSize(const Dimension &size);
		virtual void setSize(int width, int height);

		virtual void mouseDown(MouseEvent &mouseEvent);
	/**
	 * Adjusts the scrollbar so that the largeAmount is pageWidth 
	 * and there are enough pages to fill the content width.
     * @since 0.1.0
     */
		void setRangeFromPage(int pageWidth, int contentWidth);
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
	 * @return The value of the scrollbar when the 
	 * thumb is at the parameter position on the X axis.
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
	 * @return True if the mouse is pressed on the left arrow and has not been released.
     * @since 0.1.0
     */
		bool isLeftArrowDown() const;
			/**
	 * @return True if the mouse is pressed on the right arrow and has not been released.
     * @since 0.1.0
     */
		bool isRightArrowDown() const;

	/**
	 * @return The maximum size of the thumb. Subtracts the arrow widths from the inner width.
     * @since 0.1.0
     */
		int getMaxThumbSize() const;

	/**
	 * Sets the width of the arrows.
     * @since 0.1.0
     */
		virtual void setArrowWidth(int width);
	/**
	 * @return The width of the arrows.
     * @since 0.1.0
     */
		virtual int getArrowWidth() const;

	/**
	 * @return Increases the value by 1.
     * @since 0.1.0
     */
		virtual void scrollRight();
	/**
	 * @return Decreases the value by 1.
     * @since 0.1.0
     */
		virtual void scrollLeft();

	/**
	 * @return True if the thumb is completely to the left.
     * @since 0.1.0
     */
		virtual bool  isThumbAtLeft() const;
		/**
	 * @return True if the thumb is completely to the right.
     * @since 0.1.0
     */
		virtual bool isThumbAtRight() const;
	/**
	 * Adds the parameter Horizontal ScrollBar Listener.
     * @since 0.1.0
     */
		void addHScrollBarListener(HScrollBarListener* listener);
	/**
	 * Removes the parameter Horizontal ScrollBar Listener.
     * @since 0.1.0
     */
		void removeHScrollBarListener(HScrollBarListener* listener);
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
		int getMinThumbWidth() const;
	/**
	 * Sets the smallest the thumb will ever be.
     * @since 0.1.0
     */
		virtual void setMinThumbWidth(int size);
	/**
	 * Construct with optional Thumb, Left Arrow, and Right Arrow widgets.
     * @since 0.1.0
     */
		HScrollBar(Widget *thumb = NULL, Widget *leftArrow = NULL,
			Widget *rightArrow = NULL);
			/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~HScrollBar(void);
		
	};

}
#endif
