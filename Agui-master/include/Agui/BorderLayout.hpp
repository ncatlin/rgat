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

#ifndef AGUI_BORER_LAYOUT_HPP
#define	AGUI_BORER_LAYOUT_HPP

#include "Agui/Layout.hpp"

namespace agui
{
	 /**
	 * Class to layout up to 5 widgets with North, South, East, West, Center.
	 *
	 * The center stretches, but the other 4 are always the same size.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC BorderLayout :
		public Layout
	{
	public:
		enum BorderLayoutEnum
		{
			NORTH,
			SOUTH,
			EAST,
			WEST,
			CENTER
		};
	private:
		Widget *north;
		Widget *south;
		Widget *east;
		Widget *west;
		Widget *center;
		int northMargin;
		int southMargin;
		int eastMargin;
		int westMargin;
		int horizontalSpacing;
		int verticalSpacing;
	protected:
		virtual void layoutChildren();
	public:
	/**
     * Add a widget.
	 *
	 * Using this method will place the first widget North, and the last one at Center.
     * @param widget The widget to add.
	 * @since 0.1.0
     */
		virtual void add(Widget* widget);
	/**
     * Remove a widget.
	 *
	 * Using this method will place the first widget North, and the last one at Center.
     * @param widget The widget to remove.
	 * @since 0.1.0
     */
		virtual void remove(Widget* widget);
	/**
     * Add a widget.
	 *
	 * Using this method will place the widget at the parameter place.
     * @param widget The widget to add.
	 * @param which The place it should occupy.
	 * @since 0.1.0
     */
		virtual void add(Widget* widget, BorderLayoutEnum which);
		/**
     * @return A boolean indicating if the widget at this place has been added.
	 * @param which The place to verify.
	 * @since 0.1.0
     */
		bool isWidgetSet(BorderLayoutEnum which) const;
	/**
     * @return How wide or high the parameter place is.
	 * Center will return 0.
	 * @param which The place to verify.
	 * @since 0.1.0
     */
		int getBorderMargin(BorderLayoutEnum which) const;
	/**
	 * Sets height for North and South, and width for East and West.
	 *
	 * Center will not be set.
	 * @param which The place to set.
	 * @param margin The desired width or height.
	 * @since 0.1.0
     */
		void setBorderMargin(BorderLayoutEnum which, int margin);
	/**
	 * Sets height for North and South, and width for East and West.
	 * @param north The height of the top.
	 * @param south The height of the bottom.
	 * @param east The width of the left.
	 * @param west The width of the right.
	 * @since 0.1.0
     */
		void setBorderMargins(int north, int south, int east, int west);
	/**
	 * Sets the horizontal spacing.
	 * @param spacing The amount of spacing between the center and east, and the center and west.
	 * @since 0.1.0
     */
		void setHorizontalSpacing(int spacing);
	/**
	 * Sets the vertical spacing.
	 * @param spacing The amount of spacing between the center and north, and the center and south.
	 * @since 0.1.0
     */
		void setVerticalSpacing(int spacing);
	/**
	 * @return The amount of horizontal spacing.
	 * @since 0.1.0
     */
		int getHorizontalSpacing() const;
	/**
	 * @return The amount of vertical spacing.
	 * @since 0.1.0
     */
		int getVerticalSpacing() const;

	/**
	 * @return The widget associate with that border or NULL.
	 * @since 0.1.0
     */
		Widget* getWidget(BorderLayoutEnum which);
	/**
	 * Default constructor.
	 * @since 0.1.0
     */
		BorderLayout(void);
	/**
	 * Default destructor.
	 * @since 0.1.0
     */
		virtual ~BorderLayout(void);
	};
}

#endif