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

#ifndef AGUI_TEXTFIELD_HPP
#define AGUI_TEXTFIELD_HPP

#include "Agui/Widget.hpp"
#include "Agui/Widgets/TextField/TextFieldListener.hpp"
#include "Agui/BlinkingEvent.hpp"
#include "Agui/Clipboard/Clipboard.hpp"
namespace agui {
	/**
	 * Class that represents a TextField.
	 *
	 * Its text can be highlighted (selected), it can contain a password,
	 * and its text can be aligned LEFT, CENTER or RIGHT.
	 * It can also filter keys such as only accepting numeric input.
	 *
	 * ActionEvent when:
	 *
	 * KEY_ENTER is pressed.
	 *
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC TextField : public Widget, 
		public BlinkingEvent
	{
		int maxCharacterSkip;
		int maxLength;
		int caretPosition;
		int caretLocation;
		int textOffset;
		int leftPadding;
		int rightPadding;
		std::string passText;
		bool showCaret;
		bool selfSetText;
		int internalSelStart;
		bool dragged;
		std::string passwordChar;
		std::string passwordText;
		bool selectable;
		bool readOnly;
		bool wantDecimal;
		bool wantNegetive;
		bool numeric;
		bool hideSelection;
		Color selectionBackColor;
		bool password;
		int alignOffset;
		AlignmentEnum textAlign;
		int tOffset;
		bool hotkeys;
    Color frameColor;
		

		int selStart;
		int selEnd;
		int selWidth;
		int selLength;
		int selPos;

		std::vector<TextFieldListener*> tFieldListeners;

	protected:
	 /**
	 * Used internally to ensure the caret moves a comfortable amount based on the size of
	 * the TextField if moving by maxCharacterSkip would cause the caret to go off screen.
     * @since 0.1.0
     */
		virtual int solveCaretRetPos(int initialAmount, int retOffset);
	 /**
	 * Used internally to set the text.
     * @since 0.1.0
     */
		virtual void setThisText(const std::string &text);
	/**
	 * @return WIDTH - LEFT_PADDING - RIGHT_PADDING.
     * @since 0.1.0
     */
		virtual int getAdjustedWidth() const;
	/**
	 * Used internally to set the text offset when ALIGN_CENTER or ALIGN_RIGHT are used.
     * @since 0.1.0
     */
		virtual void setTextOffset(int offset);
	/**
	 * @return The text offset when ALIGN_CENTER or ALIGN_RIGHT are used.
     * @since 0.1.0
     */
		virtual int getTextOffset() const;
	/**
	 * @return The location used to render the caret.
     * @since 0.1.0
     */
		virtual int getCaretLocation() const;
		/**
	 * Used internally to scroll to the caret. Negative change ensures
	 * the caret remains in its place (Delete key used). Reposition
	 * determines if this call is only to realign the text or actually to
	 * scroll to caret.
     * @since 0.1.0
     */
		virtual void scrollToCaret(bool negetiveChange, bool reposition);
		/**
	 * Actually relocates the caret.
     * @since 0.1.0
     */
		virtual void relocateCaret();

	/**
	 * Adds the UTF32 character, as UTF8, after the caret.
     * @since 0.1.0
     */
		virtual void addToNextCharacter(int unichar);
	/**
	 * Handles arrow key movement.
     * @since 0.1.0
     */
		virtual void handleKeyboard(KeyEvent &keyEvent);
	/**
	 * Handles hotkeys.
     * @since 0.1.1
     */
		virtual bool handleHotkeys(const KeyEvent &keyEvent);
	/**
	 * @return The number of UTF8 characters selected / highlighted.
     * @since 0.1.0
     */
		virtual int getSelectionLocation() const;

	/**
	 * Will position the caret and scroll to it if needed. SupressNegChange is used
	 * internally to suppress a negative change. The position is the zero based index 
	 * indicating which character the caret will be behind.
     * @since 0.1.0
     */
		virtual void positionCaret(int position, bool surpressNegChange);

		virtual void paintComponent(const PaintEvent &paintEvent);
		virtual void paintBackground(const PaintEvent &paintEvent);

	public:
	/**
	 * Copies the selected text to the clipboard and clears the selected text in the box
     * @since 0.1.1
     */

		virtual void cut();
	/**
	 * Copies the selected text to the clipboard
     * @since 0.1.1
     */

		virtual void copy();
	/**
	 * Pastes the contents of the clipboard at the selection start
     * @since 0.1.1
     */

		virtual void paste();
	/**
	 * Sets whether or not this TextField will respond to ctrl a, c, x, v.
     * @since 0.1.1
     */

		virtual void setWantHotkeys(bool hotkeysEnabled);
	/**
	 * @return True if this TextField will respond to ctrl a, c, x, v.
     * @since 0.1.1
     */
		virtual bool wantsHotkeys() const;

			/**
	 * Removes the character behind the caret.
     * @since 0.1.0
     */
		virtual void removeLastCharacter();
	/**
	 * Removes the character in front of the caret.
     * @since 0.1.0
     */
		virtual void removeNextCharacter();

	/**
	 * Sets whether or not this TextField will be used to store a password.
     * @since 0.1.0
     */

		virtual void setIsPassword(bool password);
	/**
	 * @return True if this TextField will be used to store a password.
     * @since 0.1.0
     */
		virtual bool isPassword() const;
	/**
	 * Sets the character that will be displayed in place of the password.
	 *
	 * Default is '*' . 
	 * 
	 * The number of the frequently used Black Circle is 9679.
     * @since 0.1.0
     */
		virtual void setPasswordCharacter(int unichar);
	/**
	 * @return The character that will be displayed in place of the password.
	 *
	 * Default is '*' . 
	 * 
	 * The number of the frequently used Black Circle is 9679.
     * @since 0.1.0
     */
		virtual const std::string& getPasswordCharacter() const;
	/**
	 * @return The UTF8 encoded string representing the password itself.
     * @since 0.1.0
     */
		virtual const std::string& getPassword() const; 
	/**
	 * Sets the back color used to paint the rectangle that represents the selection.
     * @since 0.1.0
     */
		virtual void setSelectionBackColor(const Color &color);
	/**
	 * @return The back color used to paint the rectangle that represents the selection.
     * @since 0.1.0
     */
		virtual const Color& getSelectionBackColor() const;
	/**
	 * Handles the blinking.
     * @since 0.1.0
     */
		virtual void logic(double timeElapsed);
	/**
	 * Sets the alignment of the text (LEFT, CENTER, RIGHT).
     * @since 0.1.0
     */
		void setTextAlignment(AlignmentEnum alignment);
			/**
	 * @return The alignment of the text (LEFT, CENTER, RIGHT).
     * @since 0.1.0
     */
		AlignmentEnum getTextAlignment() const;
	/**
	 * Adds the parameter TextFieldListener.
     * @since 0.1.0
     */
		virtual void addTextFieldListener(TextFieldListener* listener);
	/**
	 * Removes the parameter TextFieldListener.
     * @since 0.1.0
     */
		virtual void removeTextFieldListener(TextFieldListener* listener);
	/**
	 * @return True if setNumberic was set to true and wantDecimal was set to true.
	 *
	 * Indicates that one and only one (.) can be written in the TextField.
     * @since 0.1.0
     */
		virtual bool wantedDecimal() const;
			/**
	 * @return True if setNumberic was set to true and wantMinus was set to true.
	 *
	 * Indicates that one and only one (-) can be written 
	 * in the TextField in the first character position.
     * @since 0.1.0
     */
		virtual bool wantedMinus() const;
	/**
	 * Sets whether or not only numeric input is accepted 
	 * and if you want a decimal and or minus.
     * @since 0.1.0
     */
		virtual void setNumeric(bool numeric, bool wantDecimal = false,
			bool wantMinus = false);
	/**
	 * @return True if only numeric input is accepted (and optionally decimal and minus).
     * @since 0.1.0
     */
		virtual bool isNumeric() const;
	/**
	 * Sets whether or not characters can be written and removed via the keyboard.
	 * This does not stop you from calling setText.
     * @since 0.1.0
     */
		virtual void setReadOnly(bool readOny);
	/**
	 * @return True if characters cannot be written nor removed via the keyboard.
	 * This does not stop you from calling setText.
     * @since 0.1.0
     */
		virtual bool isReadOnly() const;
	/**
	 * Sets whether or not the text can be selected / highlighted via
	 * a mouse drag or shift + arrow.
     * @since 0.1.0
     */
		virtual void setSelectable(bool selectable);
	/**
	 * @return True if the text can be selected / highlighted via
	 * a mouse drag or shift + arrow.
     * @since 0.1.0
     */
		virtual bool isSelectable() const;
	/**
	 * Selects / highlights all text.
     * @since 0.1.0
     */
		virtual void selectAll();
	/**
	 * Sets whether or not the selection will be hidden 
	 * when the TextField is not focused.
     * @since 0.1.0
     */
		virtual void setHideSelection(bool hidden);
	/**
	 * @return The UTF8 encoded string representing the highlighted / selected text.
     * @since 0.1.0
     */
		virtual const std::string getSelectedText() const;
	/**
	 * @return True if the selection will be hidden 
	 * when the TextField is not focused.
     * @since 0.1.0
     */
		virtual bool isHidingSelection() const;
	/**
	 * Sets the selected / highlighted text given a zero based start index (in UTF8 characters)
	 * and a zero based end index (in UTF8 characters). (So to highlight the first character call with (0, 1) ).
     * @since 0.1.0
     */
		virtual void setSelection(int start, int end);
	/**
	 * @return The zero based index of the selection start.
     * @since 0.1.0
     */
		virtual int getSelectionStart() const;
	/**
	 * @return The zero based index of the selection end.
     * @since 0.1.0
     */
		virtual int getSelectionEnd() const;
	/**
	 * @return The width in pixels of the selection.
     * @since 0.1.0
     */
		virtual int getSelectionWidth() const;
	/**
	 * @return The length in UTF8 characters of the selection.
     * @since 0.1.0
     */
		virtual int getSelectionLength() const;
	/**
	 * Erases the selection.
     * @since 0.1.0
     */
		virtual void deleteSelection();
	/**
	 * Sets the height of the TextField to fit the text height nicely.
     * @since 0.1.0
     */
		virtual void resizeHeightToContents();
	/**
	 * Sets the width of the TextField to fit the text width nicely.
     * @since 0.1.0
     */
		virtual void resizeWidthToContents();
			/**
	 * Sets the width and height of the TextField to fit the text nicely.
     * @since 0.1.0
     */
		virtual void resizeToContents();
	/**
	 * Will position the caret and scroll to it if needed.
	 * The position is the zero based index 
	 * indicating which character the caret will be behind.
	 *
	 * Example: if the text is Hello and this is called with (1), the caret would be at H|ello.
     * @since 0.1.0
     */
		virtual void positionCaret(int position);

		virtual void setFont(const Font *font);
		virtual void focusGained();
		virtual void focusLost();
		virtual void setText(const std::string &text);
	/**
	 * Sets the maximum length in UTF8 characters. Calls to setText will be trimmed as well.
     * @since 0.1.0
     */
		virtual void setMaxLength(int length);
	/**
	 * @return The maximum length in UTF8 characters. Calls to setText will be trimmed as well.
     * @since 0.1.0
     */
		virtual int getMaxLength() const;
	/**
	 * Sets the left padding.
     * @since 0.1.0
     */
		virtual void setLeftPadding(int padding);
	/**
	 * Sets the right padding.
     * @since 0.1.0
     */
		virtual void setRightPadding(int padding);
	/**
	 * @return The right padding.
     * @since 0.1.0
     */
		virtual int getRightPadding() const;
	/**
	 * @return The left padding.
     * @since 0.1.0
     */
		virtual int getLeftPadding() const;

		virtual void mouseDown(MouseEvent &mouseEvent);
		virtual void mouseDrag(MouseEvent &mouseEvent);
		virtual void mouseUp(MouseEvent &mouseEvent);

		virtual void keyDown(KeyEvent &keyEvent);
		virtual void keyRepeat(KeyEvent &keyEvent);

	/**
	 * Sets the maximum number of characters that will be scrolled ahead 
	 * when the caret goes too far left or right.
     * @since 0.1.0
     */
		virtual void setMaxCharacterSkip(int val);
	/**
	 * @return The maximum number of characters that will be scrolled ahead 
	 * when the caret goes too far left or right.
     * @since 0.1.0
     */
		virtual int getMaxCharacterSkip() const;
	/**
	 * @return The position of the caret. The index of the character it is behind.
     * @since 0.1.0
     */
		virtual int getCaretPosition() const;
    
        virtual bool canAcceptKeyInput() const;
        virtual bool isTextField() const;

	/**
	 * Appends the text either at the current position or at the end of the string.
	 * Will delete selected text if any is selected,
     * @since 0.2.0
     */
		virtual void appendText(const std::string& text, bool atCurrentPosition = true);
		virtual void setSize(const Dimension& size);
		virtual void setSize(int width, int height);

	/**
	 * @return Tries to convert the text into an integer.
     * @since 0.1.0
     */
		virtual int parseInteger() const;
	/**
	 * @return Tries to convert the text into a float.
     * @since 0.1.0
     */
		virtual float parseFloat() const;
	/**
	 * @return Tries to convert the text into a double.
     * @since 0.1.0
     */
		virtual double parseDouble() const;

		virtual CursorProvider::CursorEnum getEnterCursor() const;
	/**
	 * Default constructor.
     * @since 0.1.0
     */
		TextField(void);
	/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~TextField(void);
	};
}
#endif
