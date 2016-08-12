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

#ifndef AGUI_ImageWidget_HPP
#define AGUI_ImageWidget_HPP

#include "Agui/Widget.hpp"
#include "Agui/EmptyWidget.hpp"
namespace agui {
	/**
	 * Class that represents a Image as widget.
	 *
	 * Widget
     * @author Michal Kovarik
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC ImageWidget :
		public Widget
	{
		agui::Image* image;
		int topMargin;
		int leftMargin;
		int rightMargin;
		int bottomMargin;

	protected:
		virtual void paintComponent(const PaintEvent &paintEvent);
    virtual void paintBackground(const PaintEvent&) {}
	public:
		virtual void setSize(const Dimension &size);
		virtual void setSize(int width, int height);

	/**
	 * Sets the size of the content pane to the parameter size and properly factors in margins.
     * @since 0.2.0
     */
		virtual void setClientSize(const Dimension &size);
	/**
	 * @return The ImageWidget's top margin (not the same as widget margins).
     * @since 0.1.0
     */
		int getTopMargin() const;
	/**
	 * @return The ImageWidget's left margin (not the same as widget margins).
     * @since 0.1.0
     */
		int getLeftMargin() const;
	/**
	 * @return The ImageWidget's bottom margin (not the same as widget margins).
     * @since 0.1.0
     */
		int getBottomMargin() const;
	/**
	 * @return The ImageWidget's right margin (not the same as widget margins).
     * @since 0.1.0
     */
		int getRightMargin() const;
	/**
	 * Sets the ImageWidget's top margin (not the same as widget margins).
     * @since 0.1.0
     */
		void setTopMargin(int margin);
	/**
	 * Sets the ImageWidget's left margin (not the same as widget margins).
     * @since 0.1.0
     */
		void setLeftMargin(int margin);
	/**
	 * Sets the ImageWidget's bottom margin (not the same as widget margins).
     * @since 0.1.0
     */
		void setBottomMargin(int margin);
	/**
	 * Sets the ImageWidget's right margin (not the same as widget margins).
     * @since 0.1.0
     */
		void setRightMargin(int margin);
			/**
	 * Sets the ImageWidget's margins all at once (not the same as widget margins).
     * @since 0.1.0
     */
		void setMargins(int t, int l, int b, int r);
	/**
	 * Construct, takes ownership of the image
     * @since 0.1.0
     */
    ImageWidget(agui::Image* image);
    void load(agui::Image* image);
    bool isLoaded() const { return this->image != NULL; }
	/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~ImageWidget(void);
	};
}
#endif
