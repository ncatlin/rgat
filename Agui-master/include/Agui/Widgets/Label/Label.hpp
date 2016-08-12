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

#ifndef AGUI_LABEL_HPP
#define AGUI_LABEL_HPP

#include "Agui/Widget.hpp"
namespace agui {
	class AGUI_CORE_DECLSPEC LabelListener;

	/**
	 * Class that represents a simple Label.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC Label : public Widget {
		AreaAlignmentEnum alignment;
		std::vector<std::string> words;
		std::vector<std::string> lines;
		std::vector<LabelListener*> labelListeners;
		bool isLabelAutosizing;
	/**
	 * Internally sets the size. Used when auto sizing.
     * @since 0.1.0
     */
		void _setSizeInternal(const Dimension &size);
	protected:
		ResizableText resizableText;
		virtual void paintComponent(const PaintEvent &paintEvent);
		virtual void paintBackground(const PaintEvent &paintEvent);
	/**
	 * Updates the text of the label.
     * @since 0.1.0
     */
		void updateLabel();
	/**
	 * Draws the text of the label.
     * @since 0.1.0
     */
		virtual void drawText(const PaintEvent &paintEvent);
	public:
			/**
     * Sets whether this should only be rendered on a single line
	 * and if an ellipsis should be appended
	 * if the text does not fit maxWidth.
     * @since 0.1.0
     */
		virtual void setSingleLine(bool singleLine, bool wantEllipsis = false);
			/**
     * @return True if an ellipsis (...) should be rendered at the end of the text.
	 * Only applicable if isSingleLine is true.
     * @since 0.1.0
     */
		virtual bool wantsEllipsis() const;
		/**
     * @return True if the text should render in a whole line. 
	 * False if rendered as multiple lines.
     * @since 0.1.0
     */
		virtual bool isSingleLine() const;
		virtual void setSize(const Dimension &size);
		virtual void setSize(int width, int height);
		virtual void setText(const std::string &text);
		virtual void setFont(const Font *font);
	/**
     * Adds the parameter LabelListener.
     * @since 0.1.0
     */
		virtual void addLabelListener(
			LabelListener* listener);
	/**
     * Removes the parameter LabelListener.
     * @since 0.1.0
     */
		virtual void removeLabelListener(
			LabelListener *listener);
	/**
     * Resizes the Label to fit the caption text.
     * @since 0.1.0
     */
		void resizeToContents();
	/**
	 * @return True if the Label is automatically sizing itself.
	 *
	 * If this is true, any calls to setSize will not do anything.
     * @since 0.1.0
     */
		bool isAutosizing();
		/**
	 * Sets whether or not the Label is automatically sizing itself.
	 *
	 * If this is true, any calls to setSize will not do anything.
     * @since 0.1.0
     */
		void setAutosizing(bool autosizing);
	/**
	 * @return The caption text's alignment.
     * @since 0.1.0
     */
		AreaAlignmentEnum getAlignment() const;
		/**
	 * Sets the caption text's alignment.
     * @since 0.1.0
     */
		void setAlignment(AreaAlignmentEnum alignment);

		/**
	 * @return Number of text lines.
     * @since 0.2.0
     */
		int getNumTextLines() const;

			/**
	 * @return The array of text lines used to render the text.
     * @since 0.2.0
     */
		std::vector<std::string>& getTextLines();

    /**
    * Resizes the Label to fit the caption text, adjusts only height.
    * @since 0.1.0
    */
    void resizeToContentsPreserveWidth();

	/**
	 * Default constructor.
     * @since 0.1.0
     */
		Label(void);
	/**
	 * Construct with caption text.
     * @since 0.1.0
     */
		Label(const std::string &text);
	/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~Label(void);
	};
}
#endif
