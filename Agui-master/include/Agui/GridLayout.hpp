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

#ifndef AGUI_GRID_LAYOUT_HPP
#define AGUI_GRID_LAYOUT_HPP

#include "Agui/Layout.hpp"
namespace agui
{
	/**
     * Class to layout widgets in an equidistant
	 * grid where each widget occupies the same amount of room.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class GridLayout :
		public Layout
	{
		int rows;
		int columns;
		int horizontalSpacing;
		int verticalSpacing;
	protected:
	/**
     * Lays out the children in a grid.
     * @since 0.1.0
     */
		virtual void layoutChildren();
	public:
	/**
     * Sets the number of rows expected to have.
	 *
	 * This can be set to zero if you do not know however 
	 * either number of rows or number of columns must be non zero.
	 * They cannot both be zero.
     * @since 0.1.0
     */
		virtual void setNumberOfRows(int rows);
	/**
     * Sets the number of columns expected to have.
	 *
	 * This can be set to zero if you do not know however 
	 * either number of rows or number of columns must be non zero.
	 * They cannot both be zero.
     * @since 0.1.0
     */
		virtual void setNumberOfColumns(int columns);
		/**
	 * Sets the horizontal spacing between each widget. The first widget in the row receives no spacing.
	 * Use the margins for this.
     * @since 0.1.0
     */
		virtual void setHorizontalSpacing(int spacing);
	/**
	 * Sets the vertical spacing between each widget. The first widget in the column receives no spacing.
	 * Use the margins for this.
     * @since 0.1.0
     */
		virtual void setVerticalSpacing(int spacing);
	/**
	 * @return The number of rows in the grid or zero if unknown.
     * @since 0.1.0
     */
		virtual int getNumberOfRows() const;
	/**
	 * @return The number of columns in the grid or zero if unknown.
     * @since 0.1.0
     */
		virtual int getNumberOfColumns() const;
			/**
	 * @return The horizontal spacing between widgets.
     * @since 0.1.0
     */
		virtual int getHorizontalSpacing() const;
	/**
	 * @return The vertical spacing between widgets.
     * @since 0.1.0
     */
		virtual int getVerticalSpacing() const;
	/**
	 * Default constructor.
     * @since 0.1.0
     */
		GridLayout(void);
		/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~GridLayout(void);
	};
}
#endif
