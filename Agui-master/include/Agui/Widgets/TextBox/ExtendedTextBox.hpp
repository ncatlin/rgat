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

#ifndef AGUI_EXTENDED_TEXTBOX_HPP
#define AGUI_EXTENDED_TEXTBOX_HPP

#include "Agui/Widgets/TextBox/TextBox.hpp"
#include <map>
namespace agui {
	/**
	 * Class that extends the TextBox. It adds text coloring. Each character can
	 * have a different color. Also allows the highlighted text to be a different color.
	 *
	 * For efficient rendering, the default drawText method does not work with Kerning.
	 *
	 * Optional constructor widget:
	 *
	 * HScrollBar (Horizontal Scroll Bar)
	 *
	 * VScrollBar (Vertical Scroll Bar)
	 *
	 * Widget (Scroll Inset)
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC ExtendedTextBox : public TextBox
	{
	private:
		bool isEditingText;
		Color currentColor;
		std::string curStr;
		Point colorIndexStart;
		bool currentColorChanged;
		int lastVisibleIndex;
		std::vector<std::pair<Color,Image*> > textColors;
		std::map<std::string,Image*> icons;
		std::map<Image*,std::string> iconClipboardText;
		Color selectionFontColor;
		bool selFontColor;
		std::string emoticonChar;
	protected:
	/**
	 * Clears the text color std::vector.
     * @since 0.1.0
     */
		virtual void clearColors();
		/**
	 * Used for rendering. Sets where the color index should start from based on line visibility.
     * @since 0.1.0
     */
		virtual void setColorIndexStart();
	/**
	 * Updates the text and the colors. WordWraps if that option is set. Updates the scrollbars.
     * @since 0.1.0
     */
		virtual void updateText();
	/**
	 * @return The index of the color for the first character that is visible.
     * @since 0.1.0
     */
		virtual const Point& getColorIndexStart() const;
		virtual void paintComponent(const PaintEvent &paintEvent);
	/**
	 * Called when the vertical scrollbar's value changes.
     * @since 0.1.0
     */
		virtual void valueChanged(VScrollBar* source, int val);
	/**
	 * Removes character behind the caret.
     * @since 0.1.0
     */
		virtual int removeLastCharacter();
	/**
	 * Removes character in front of the caret.
     * @since 0.1.0
     */
		virtual int removeNextCharacter();
	/**
	 * Appends the UTF32 encoded character, as UTF8, in front of the caret.
     * @since 0.1.0
     */
		virtual int addToNextCharacter(int unichar);
	/**
	 * Draws the text using an efficient algorithm. 
     * @since 0.1.0
     */
		virtual void drawText(const PaintEvent &paintEvent);
	public:
		/**
	 * Set to true if you would like highlighted text to use the selection font color. 
	 * Otherwise only a filled rectangle will represent the selection and the text color will
	 * maintain its color when selected.
     * @since 0.1.0
     */
		virtual void setIsSelectionFontColorInUse(bool wantSelectionColor);
	/**
	 * @return True if highlighted text uses the selection font color. 
	 * Otherwise only a filled rectangle will represent the selection and the text color will
	 * maintain its color when selected.
     * @since 0.1.0
     */
		virtual bool isSelectionFontColorInUse() const;
	/**
	 * Sets the color that selected text will appear
	 * as if isSelectionFontColorInUse returns true.
     * @since 0.1.0
     */
		virtual void setSelectionFontColor(const Color &color);
	/**
	* @return The color that selected text will appear
	* as if isSelectionFontColorInUse returns true.
     * @since 0.1.0
     */
		virtual const Color& getSelectionFontColor() const;
		virtual void appendText(const std::string &text,
			bool atCurrentPosition = true, bool repositionCaret = true);
		virtual void setFont(const Font *font);
	/**
	 * Sets the color that subsequent text will appear as. This will change 
	 * when at least one character has been appended and the caret is put behind another color.
     * @since 0.1.0
     */
		virtual void setCurrentColor(const Color &color);
	 /**
	 * Sets the color of the rectangle that represents the selection.
     * @since 0.1.0
     */
		virtual void setSelectionColor(const Color & color);
	/**
	 * Deletes the characters that are selected
     * @since 0.1.0
     */
		virtual void deleteSelection();
	/**
	 * Registers an emoticon image. This image will be displayed when the trigger character is typed or appended.
     * @since 0.2.0
     */
		virtual void registerEmoticon(const std::string& triggerChar, Image* image, const std::string& clipboardText);
	/**
	 * @return The Image of the emoticon associated with this string or NULL if not found.
     * @since 0.2.0
     */
		virtual Image* getEmoticon(const std::string& triggerChar);

			/**
	 * @return The clipboard text of the emoticon associated with this string or "" if not found.
	 * This text will be copied when copy() is called.
     * @since 0.2.0
     */
		virtual std::string getEmoticonClipboardText(Image* emoticon);
		virtual void setText(const std::string &text);

		virtual void copy();
	/**
	 * Construct with optional HorizontalScrollBar ,
	 * VerticalScrollBar , and ScrollInset Widget.
     * @since 0.1.0
     */
		ExtendedTextBox(HScrollBar *hScroll = NULL, VScrollBar *vScroll = NULL, Widget* scrollInset = NULL);
	/**
     * Default destructor.
     * @since 0.1.0
     */
		virtual ~ExtendedTextBox(void);
	};
}
#endif
