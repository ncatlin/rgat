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

#ifndef AGUI_RESIZABLE_TEXT_HPP
#define AGUI_RESIZABLE_TEXT_HPP
#include <stdlib.h>
#include <vector>
#include "Agui/Platform.hpp"
#include "Agui/UTF8.hpp"
#include "Agui/Rectangle.hpp"
#include "Agui/Enumerations.hpp"
namespace agui
{
	class AGUI_CORE_DECLSPEC Font;
	class AGUI_CORE_DECLSPEC Graphics;
	/**
     * Class that allows flexible text rendering.
	 *
	 * Allows rendering an area of text using alignment.
	 *
	 * Also allows rendering a single line of text with an ellipsis (...).
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC ResizableText {
		bool singleLine;
		bool wantEllipsis;
	protected:
	/**
     * Splits the text into lines that respect the maxWidth parameter and newline characters.
     * @since 0.1.0
     */
		virtual void multiMakeLines(const Font *font, const std::string &text,
			std::vector<std::string> &textRows, int maxWidth );
	/**
     * Ignores newline characters and adds an ellipsis if requested while respecting maxWidth.
     * @since 0.1.0
     */
		virtual void singleMakeLines(const Font *font, const std::string &text,
			std::vector<std::string> &textRows, int maxWidth);
		UTF8 utf8Manager;
	public:
	/**
     * Default constructor.
     * @since 0.1.0
     */
		ResizableText();
	/**
     * Default destructor.
     * @since 0.1.0
     */
		virtual ~ResizableText();
	/**
     * @return True if the text should render in a whole line. 
	 * False if rendered as multiple lines.
     * @since 0.1.0
     */
		bool isSingleLine() const;
	/**
     * @return True if an ellipsis (...) should be rendered at the end of the text.
	 * Only applicable if isSingleLine is true.
     * @since 0.1.0
     */
		bool wantsEllipsis() const;
	/**
     * Sets whether this should only be rendered on a single line
	 * and if an ellipsis should be appended
	 * if the text does not fit maxWidth.
     * @since 0.1.0
     */
		void setSingleLine(bool singleLine, bool wantEllipsis = false);
	/**
     * Draws the text area with the specified alignment.
	 * @param g The graphics context. Obtained from paintEvent.graphics().
	 * @param font The font to draw the text.
	 * @param area Rectangle that determines the maximum height and starting position.
	 * @param color The color of the text.
	 * @param lines The std::vector that was previously passed to makeTextLines.
	 * @param align The area alignment of the text.
     * @since 0.1.0
     */
		void drawTextArea(Graphics *g, const Font *font,
			const Rectangle &area,
			const Color &color, const std::vector<std::string> &lines,
			AreaAlignmentEnum align);

	/**
     * Generates lines of text to be rendered.
	 * @param font The font to draw the text.
	 * @param text The UTF8 encoded string.
	 * @param lines The std::vector that will be filled with lines.
	 * @param maxWidth The width to respect for each line.
     * @since 0.1.0
     */
		void makeTextLines(const Font *font, const std::string &text,
			std::vector<std::string> &textRows, int maxWidth );


	};
}

#endif
