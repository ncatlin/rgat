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

#ifndef AGUI_RESIZABLE_BORDER_LAYOUT_HPP
#define AGUI_RESIZABLE_BORDER_LAYOUT_HPP
#include "Agui/BorderLayout.hpp"

namespace agui
{
	/**
     * Class that extends the BorderLayout to allow resizing in the gaps.
	 *
	 * Requires that the CENTER widget be set to work properly.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC ResizableBorderLayout :
		public BorderLayout
	{
		bool resizingNorth;
		bool resizingSouth;
		bool resizingEast;
		bool resizingWest;
		bool resizing;

		bool constrainToCenter;

		BorderLayoutEnum mouseResult;
		int oldMargin;

		int dragX;
		int dragY;
	public:
	/**
     * Sets whether or not a widget cannot be resized beyond the CENTER widget.
     * @since 0.1.0
     */
		void setConstrainToCenter(bool constrain);
	/**
     * @return True if a widget cannot be resized beyond the CENTER widget.
     * @since 0.1.0
     */
		bool isConstrainedToCenter() const;
	/**
     * Finds and stores the region of the mouse and mouse coordinates.
     * @since 0.1.0
     */
		virtual void mouseDown(MouseEvent &mouseEvent);
	/**
     * Changes the margin of the region and effectively resizes the region.
     * @since 0.1.0
     */
		virtual void mouseDrag(MouseEvent &mouseEvent);
		/**
     * @return Which region the mouse is in. 
	 * NORTH, SOUTH, EAST, and WEST are valid but CENTER indicates that
	 * the mouse is outside a resizable region.
     * @since 0.1.0
     */
		BorderLayoutEnum getPointRegion(const Point &p);
	/**
     * Sets whether or not the margins will be resized with the mouse.
     * @since 0.2.0
     */
		void setResizable(bool resize);
	/**
     * @return True if the margins will be resized with the mouse.
     * @since 0.2.0
     */
		bool isResizable() const;
	/**
     * Default constructor.
     * @since 0.1.0
     */
		ResizableBorderLayout(void);
	/**
     * Default destructor.
     * @since 0.1.0
     */
		virtual ~ResizableBorderLayout(void);
	};
}
#endif
