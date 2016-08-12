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

#ifndef AGUI_FLOW_LAYOUT_HPP
#define AGUI_FLOW_LAYOUT_HPP
#include "Agui/Layout.hpp"
namespace agui
{
	/**
     * Class that implements a Flow Layout.
	 *
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC FlowLayout : public Layout
	{
		int horizontalSpacing;
		int verticalSpacing;
		bool topToBottom;
		bool leftToRight;
		bool singleRow;
		bool center;
		bool alignLastRow;
		int contentHSz;
		int maxOnRow;
		bool resizeElemToWidth;
	protected:
	/**
	 * Will layout the children using Flow Layout rules and
	 * will leave the desired spacing between each widget.
     * @since 0.1.0
     */
		virtual void layoutChildren();
	public:

	/**
	 * Default constructor.
     * @since 0.1.0
     */
		FlowLayout(void);

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
	 * Sets the direction to start laying out widgets. If set to false, the first widget will appear at the complete right
	 * of the row.
     * @since 0.1.0
     */
		virtual void setLeftToRight(bool orientation);
	/**
	 * Sets the direction to start laying out widgets. If set to false, the first widget will appear at the complete bottom
	 * of the column.
     * @since 0.1.0
     */
		virtual void setTopToBottom(bool orientation);
	/**
	 * Sets whether all widgets should be laid out on a single row.
     * @since 0.1.0
     */
		virtual void setSingleRow(bool single);
	/**
	 * @return Boolean indicating if all widgets are on a single row.
     * @since 0.1.0
     */
		virtual bool isSingleRow() const;
	/**
	 * @return Boolean indicating the direction that widgets should be laid out.
     * @since 0.1.0
     */
		virtual bool isLeftToRight() const;
	/**
	 * @return Boolean indicating the direction that widgets should be laid out.
     * @since 0.1.0
     */
		virtual bool isTopToBottom() const;

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
	 * @return True if the widgets will be horizontally centered.
     * @since 0.2.0
     */
		virtual bool isHorizontallyCentered() const;

		/**
	 * Used with centering. Rather than center, the
	 * last row will align to the first widget horizontally.
     * @since 0.2.0
     */
		virtual void setAlignLastRow(bool align);

		/**
		* @return True when Used with centering. Rather than center, the
		* last row will align to the first widget horizontally.
     * @since 0.2.0
     */
		virtual bool isLastRowAligned() const;

	/**
	 * Ensures that the widget consumes the whole row.
	 * Sets max on row to 1.
     * @since 0.2.0
     */
		virtual void setResizeRowToWidth(bool resize);

		/**
	 * @return True if the widget consumes the whole row.
     * @since 0.2.0
     */
		virtual bool isResizingRowToWidth() const;

		/**
	 * Sets the maximum widgets on a row or 0 if not set.
     * @since 0.2.0
     */
		virtual void setMaxOnRow(int max);

		/**
		* @return The maximum widgets on a row or 0 if not set.
     * @since 0.2.0
     */
		virtual int getMaxOnRow() const;

		/**
	 * @Sets if the widgets will be horizontally centered.
     * @since 0.2.0
     */
		virtual void setHorizontallyCentered(bool centered);

	/**
	 * @return The height of the contents.
     * @since 0.2.0
     */
		virtual int getContentsHeight() const;
  	/**
	 * @return The height of the contents.
     * @since 0.2.0
     */
		virtual int getContentsWidth() const;

	/**
	 * Resizes to contents.
     * @since 0.2.0
     */
		virtual void resizeToContents();

		
	/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~FlowLayout(void);
	};
}
#endif
