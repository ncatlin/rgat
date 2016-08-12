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

#ifndef AGUI_FRAME_HPP
#define AGUI_FRAME_HPP

#include "Agui/Widget.hpp"
#include "Agui/EmptyWidget.hpp"
#include "Agui/Widgets/Frame/FrameListener.hpp"
namespace agui {
	/**
	 * Class that represents a movable and resizable Frame / Window.
	 *
	 * Optional constructor widget:
	 *
	 * Widget
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC Frame :
		public Widget
	{
		int topMargin;
		int titleFontMargin;
		int leftMargin;
		int rightMargin;
		int bottomMargin;
		Color frontColor;

		bool movable;
		bool resizable;
		int dragX;
		int dragY;
		bool moving;
		bool resizing;
		Dimension initialSize;

		bool isMaintainingContainer;
		Widget *pChildContainer;

		std::vector<FrameListener*> frameListeners;
	protected:
		virtual void paintComponent(const PaintEvent &paintEvent);
		virtual void paintBackground(const PaintEvent &paintEvent);
	/**
	 * Resizes the container to fit the frame's margins and widget margins.
     * @since 0.1.0
     */
		virtual void resizeContainer();
	/**
	 * @return The bottom right rectangle used to determine if dragging results in a resize.
     * @since 0.1.0
     */
		virtual Rectangle getBRResizeRect() const;
	public:
	/**
	 * Adds the parameter FrameListener.
     * @since 0.1.0
     */
		virtual void addFrameListener(FrameListener* listener);
	/**
	 * Removes the parameter FrameListener.
     * @since 0.1.0
     */
		
		virtual void removeFrameListener(FrameListener* listener);
	/**
	 * Flags the content pane's public children in addition to its Frame children.
     * @since 0.1.0
     */
		virtual void flagAllChildrenForDestruction();
		virtual void setFont(const Font *font);
	/**
	 * @return The content pane.
     * @since 0.1.0
     */
		virtual Widget* getContentPane();
	/**
	 * Sets whether or not dragging the bottom right corner will resize the Frame.
     * @since 0.1.0
     */
		virtual void setResizable(bool resize);
	/**
	 * @return True if dragging the bottom right corner will resize the Frame.
     * @since 0.1.0
     */
		virtual bool isResizable() const;
	/**
	 * Adds the parameter widget to the frame itself (not the content pane).
     * @since 0.1.0
     */
		virtual void addToFrame(Widget *widget);
		/**
	 * Removes the parameter widget from the frame itself (not the content pane).
     * @since 0.1.0
     */
		virtual void removeFromFrame(Widget *widget);
	/**
	 * @return The inner size of the content pane.
     * @since 0.1.0
     */
		virtual const Dimension& getContentSize() const;
		virtual void mouseDown(MouseEvent &mouseEvent);
		virtual void mouseDrag(MouseEvent &mouseEvent);
	/**
	 * Sets whether or not dragging the caption bar (top of the frame) will result in moving
	 * the Frame.
     * @since 0.1.0
     */
		virtual void setMovable(bool move); 
		/**
	 * @return True if dragging the caption bar (top of the frame) will result in moving
	 * the Frame.
     * @since 0.1.0
     */
		virtual bool isMovable() const;
		virtual void mouseUp(MouseEvent &mouseEvent);
		virtual void setSize(const Dimension &size);
		virtual void setSize(int width, int height);

	/**
	 * Sets the size of the content pane to the parameter size and properly factors in margins.
     * @since 0.2.0
     */
		virtual void setClientSize(const Dimension &size);
			/**
	 * Sets the size of the content pane to the parameter size and properly factors in margins.
     * @since 0.2.0
     */
		virtual void setClientSize(int width, int height);
	/**
	 * @return The frame's top margin (not the same as widget margins).
     * @since 0.1.0
     */
		int getTopMargin() const;
	/**
	 * @return The frame's left margin (not the same as widget margins).
     * @since 0.1.0
     */
		int getLeftMargin() const;
	/**
	 * @return The frame's bottom margin (not the same as widget margins).
     * @since 0.1.0
     */
		int getBottomMargin() const;
	/**
	 * @return The frame's right margin (not the same as widget margins).
     * @since 0.1.0
     */
		int getRightMargin() const;
	/**
	 * Sets the frame's top margin (not the same as widget margins).
     * @since 0.1.0
     */
		void setTopMargin(int margin);
	/**
	 * Sets the frame's left margin (not the same as widget margins).
     * @since 0.1.0
     */
		void setLeftMargin(int margin);
	/**
	 * Sets the frame's bottom margin (not the same as widget margins).
     * @since 0.1.0
     */
		void setBottomMargin(int margin);
	/**
	 * Sets the frame's right margin (not the same as widget margins).
     * @since 0.1.0
     */
		void setRightMargin(int margin);
			/**
	 * Sets the frame's margins all at once (not the same as widget margins).
     * @since 0.1.0
     */
		void setFrameMargins(int t, int l, int b, int r);
    void setFrontColor(const Color& color);
	/**
	 * Adds the parameter widget to the content pane.
     * @since 0.1.0
     */
		virtual void add(Widget *widget);
	/**
	 * Removes the parameter widget from the content pane.
     * @since 0.1.0
     */
		virtual void remove(Widget *widget);
    virtual void resizeToContents();
    void setTitleFontMargin(int margin);
	/**
	 * Construct with optional Widget for the content pane.
     * @since 0.1.0
     */
		Frame(Widget *contentPane = NULL);
	/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~Frame(void);
	};
}
#endif
