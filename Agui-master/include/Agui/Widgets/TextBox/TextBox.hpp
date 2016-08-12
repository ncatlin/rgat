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

#ifndef AGUI_TEXTBOX_HPP
#define AGUI_TEXTBOX_HPP

#include "Agui/Widget.hpp"
#include "Agui/Widgets/ScrollBar/HScrollBar.hpp"
#include "Agui/Widgets/ScrollBar/VScrollBar.hpp"
#include "Agui/MouseListener.hpp"
#include "Agui/BlinkingEvent.hpp"
#include "Agui/Widgets/TextBox/TextBoxListener.hpp"
#include "Agui/Clipboard/Clipboard.hpp"

namespace agui {
	/**
	 * Class that represents a multi line TextBox.
	 *
	 * Its text can be highlighted (selected), it can be word wrapped or only parse new line characters,
	 * and its text can be aligned LEFT, CENTER or RIGHT.
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
	class AGUI_CORE_DECLSPEC TextBox : 
		public Widget,
		public BlinkingEvent,
		protected HScrollBarListener,
		protected VScrollBarListener
	{
	private:
		int topPadding;
		int leftPadding;
		int bottomPadding;
		int rightPadding;

		ScrollPolicy hScrollPolicy;
		ScrollPolicy vScrollPolicy;

		int horizontalOffset;
		int verticalOffset;

		int caretRow;
		int caretColumn;
		int caretRowLocation;
		int caretColumnLocation;
		int widestLine;

		bool wordWrap;
		bool readOnly;
		bool drawBorder;
		int maxSkip;
		int numSelLines;
		int mouseDownIndex;
		bool dragged;
		bool splittingWords;
		bool standardArrowKeyRules;
		AlignmentEnum textAlignment;
		Color selectionBackColor;
		Color frameColor;

		bool hideSelection;
		bool selfSetText;
		std::vector<std::string> textRows;
		std::vector<int> lineOffset;
		std::vector<std::pair<Point,Point> > selPts;
		std::vector<int> rowLengths;
		Point selectionIndexes;

		int maxLength;
		bool selectable;
		bool hotkeys;

		HScrollBar *pChildHScroll;
		VScrollBar *pChildVScroll;
		Widget *pChildInset;

		bool isMaintainingHScroll;
		bool isMaintainingVScroll;
		bool isMaintainingScrollInset;
		std::vector<TextBoxListener*> textBoxListeners;
		virtual void handleKeyboard(const KeyEvent &keyEvent);
	protected:
	 /**
	 * @return True if setThisText has been called and not returned yet.
     * @since 0.1.0
     */
		bool isSelfSettingText() const;
	/**
	 * Used internally to set the text.
     * @since 0.1.0
     */
		void setThisText(const std::string &text);
	 /**
	 * @return The width of the string. Modify this if you want to return
	 * custom widths for Image characters like emoticons for a chat box.
     * @since 0.1.0
     */
		virtual int getTextWidth(const std::string &text) const;
	 /**
	 * @return The number of UTF8 characters this row contains.
     * @since 0.1.0
     */
		virtual int getRowLength(int row) const;
	/**
	 * Handles arrow key functionality.
     * @since 0.1.0
     */
		virtual void handleArrowKey(const KeyEvent &keyEvent, int column, int row);
	/**
	 * @return The column that is actually below the column at the previous row.
	 * Not applicable for mono spaced fonts.
     * @since 0.1.0
     */
		virtual int columnFromPreviousRow(int row, int newRow, int column) const;
	/**
     * Enables or disables the ScrollBars based on the ScrollPolicy.
     * @since 0.1.0
     */
		virtual void checkScrollPolicy();
	/**
     * Will resize the ScrollBars based on the policy.
     * @since 0.1.0
     */
		virtual void resizeSBsToPolicy();
	/**
     * Will adjust the ScrollBar ranges based on the content width and content height.
     * @since 0.1.0
     */
		virtual void adjustSBRanges();
	/**
     * Checks the policy, resizes the scroll bars, and adjusts the ranges.
     * @since 0.1.0
     */
		virtual void updateScrollBars();
	/**
     * Updates the text by splitting it into lines and updates the text.
     * @since 0.1.0
     */
		virtual void updateText();
	/**
     * Splits the text into lines only when it finds a newline character.
     * @since 0.1.0
     */
		virtual void makeLinesFromNewline();
	/**
     * Splits the text into lines when the width of the line exceeds the width of the TextBox.
     * @since 0.1.0
     */
		virtual void makeLinesFromWordWrap();
	/**
     * @return Negative Vertical Scrollbar value + TOP_PADDING.
     * @since 0.1.0
     */
		virtual int getVerticalOffset() const;
	/**
     * @return Negative Horizontal Scrollbar value + LEFT_PADDING.
     * @since 0.1.0
     */
		virtual int getHorizontalOffset() const;
	/**
     * Updates the Horizontal offset.
     * @since 0.1.0
     */
		virtual void valueChanged(HScrollBar* source, int val);
			/**
     * Updates the Vertical offset.
     * @since 0.1.0
     */
		virtual void valueChanged(VScrollBar* source, int val);
		virtual void paintComponent(const PaintEvent &paintEvent);
		virtual void paintBackground(const PaintEvent &paintEvent);
	/**
     * Relocates the caret based on the Horizontal and Vertical offsets.
     * @since 0.1.0
     */
		virtual void relocateCaret();
	/**
     * Updates the text offsets based on the scrollbar values and padding.
     * @since 0.1.0
     */
		virtual void changeTextOffset();
	/**
     * Used to find which character the mouse is on.
     * @since 0.1.0
     */
		virtual Point columnRowFromRelPosition(const Point &pos) const;
	/**
     * @return The index in the text (in UTF8 characters) given a column and a row.
     * @since 0.1.0
     */
		virtual int indexFromColumnRow(int column, int row) const;
	/**
     * @return The column and row given a UTF8 index in the text.
     * @since 0.1.0
     */
		virtual Point columnRowFromIndex(int index) const;
	/**
     * Positions the caret at the specified column and row using mouse rules.
     * @since 0.1.0
     */
		virtual void mousePositionCaret(const Point& pos);
	/**
     * Positions the caret at the specified column and row using keyboard rules.
     * @since 0.1.0
     */
		virtual void keyPositionCaret(int column, int row);
	/**
     * Positions the caret at the specified column and row using resizing rules.
     * @since 0.1.0
     */
		virtual void sizePositionCaret(const Point& pos);
	/**
     * Updates the widest line if splitting by newline, but with WordWrap, sets to 0.
     * @since 0.1.0
     */
		virtual void updateWidestLine();
	/**
     * Adds the UTF32 character, as UTF8, in front of the caret.
     * @since 0.1.0
     */
		virtual int addToNextCharacter(int unichar);
	/**
     * @return The number of lines in the TextBox.
     * @since 0.1.0
     */
		virtual int getTextLineCount() const;
	/**
     * @return The UTF8 encoded string representing the parameter line.
     * @since 0.1.0
     */
		virtual const std::string& getTextLineAt(int line) const;
	/**
     * @return The Point, Point pair representing the Top Left, and Bottom Right points.
	 * needed to construct the selection rectangle for this line. It is not given as a rectangle
	 * for flexibility.
     * @since 0.1.0
     */
		virtual const std::pair<Point,Point>& getSelLineAt(int line) const;
	/**
     * @return The number of selection lines to query when rendering.
     * @since 0.1.0
     */
		virtual int getSelLineCount() const;
	/**
     * @return The index of the first line that is visible (Used for rendering).
     * @since 0.1.0
     */
		virtual int getVisibleLineStart() const;
/**
     * @return The number of lines that are visible (Used for rendering).
     * @since 0.1.0
     */
		virtual int getVisibleLineCount() const;
	/**
     * @return The line offset because of Text Alignment CENTER and RIGHT (Used for rendering).
     * @since 0.1.0
     */
		virtual int getLineOffset(int line) const;

	/**
	 * Handles hotkeys.
     * @since 0.1.1
     */
		virtual bool handleHotkeys(const KeyEvent &keyEvent);

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
    * Removes the UTF8 character behind the caret.
    * @since 0.1.0
    */
        virtual int removeLastCharacter();
    
    /**
    * Removes the UTF8 character in front of the caret.
    * @since 0.1.0
    */
        virtual int removeNextCharacter();
        
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
     * Sets whether or not the text can be selected / highlighted by dragging the mouse.
     * @since 0.1.0
     */
		virtual void setSelectable(bool select);
	/**
     * @return True if the text can be selected / highlighted by dragging the mouse.
     * @since 0.1.0
     */
		virtual bool isSelectable() const;
	/**
     * Adds the parameter TextBoxListener.
     * @since 0.1.0
     */
		virtual void addTextBoxListener(TextBoxListener* listener);
	/**
     * Removes the parameter TextBoxListener.
     * @since 0.1.0
     */
		virtual void removeTextBoxListener(TextBoxListener* listener);
	/**
	 * @return The maximum length in UTF8 characters. Calls to setText will be trimmed as well.
     * @since 0.1.0
     */
		virtual int getMaxLength() const;
	/**
	 * Sets the maximum length in UTF8 characters. Calls to setText will be trimmed as well.
     * @since 0.1.0
     */
		virtual void setMaxLength(int length);
	/**
	 * @return True if the selection will be hidden 
	 * when the TextBox is not focused.
     * @since 0.1.0
     */
		virtual bool isHidingSelection() const;
	/**
	 * Sets whether or not the selection will be hidden 
	 * when the TextBox is not focused.
     * @since 0.1.0
     */
		virtual void setHideSelection(bool hide);
	/**
	 * Sets the back color used to paint the rectangles that represent the selection.
     * @since 0.1.0
     */
		virtual void setSelectionBackColor(const Color &color);
	/**
	 * @return The back color used to paint the rectangles that represent the selection.
     * @since 0.1.0
     */
		virtual const Color& getSelectionBackColor() const;
    virtual void setFrameColor(const Color& color);
    virtual const Color& getFrameColor() const;
	/**
	 * Handles the blinking.
     * @since 0.1.0
     */
		virtual void logic(double timeElapsed);
		virtual bool intersectionWithPoint(const Point &p) const;
	/**
	 * Sets the text alignment (LEFT, CENTER, RIGHT). Only applicable when word wrap is on.
     * @since 0.1.0
     */
		void setTextAlignment(AlignmentEnum align);
	/**
	 * @return The text alignment (LEFT, CENTER, RIGHT). Only applicable when word wrap is on.
     * @since 0.1.0
     */
		AlignmentEnum getTextAlignment() const;
	/**
	 * @return The length in UTF8 characters of the selection.
     * @since 0.1.0
     */
		virtual int getSelectionLength() const;
		/**
	 * @return The UTF8 encoded string representing the selection.
     * @since 0.1.0
     */
		std::string getSelectedText() const;
	/**
	 * @return True if standard arrow key rules are in use.
	 *
	 * This skips characters at the end of a line or at the beginning in certain situations.
     * @since 0.1.0
     */
		bool isStandardArrowKeyRules() const;
	/**
	 * Sets whether or not standard arrow key rules are in use.
	 *
	 * This skips characters at the end of a line or at the beginning in certain situations.
     * @since 0.1.0
     */
		void setStandardArrowKeyRules(bool usingStandardRules);
	/**
	 * When using word wrap, sets whether the words are split by ' ' and '-'
	 * otherwise they are split like a console and a split can occur anywhere in the word.
     * @since 0.1.0
     */
		virtual void setSplittingWords(bool splitting);
	/**
	 * @return True if the words are split by ' ' and '-'
	 * otherwise they are split like a console and a split can occur anywhere in the word.
	 *
	 * Only when using word wrap.
     * @since 0.1.0
     */
		
		bool isSplittingWords() const;
	/**
	 * @return True if the Horizontal Scrollbar is visible.
     * @since 0.1.0
     */
		
		bool isHScrollVisible() const;
			/**
	 * @return True if the Vertical Scrollbar is visible.
     * @since 0.1.0
     */
		
		bool isVScrollVisible() const;
	/**
	 * Appends the parameter UTF8 encoded string to the TextBox.
	 * @param atCurrentPosition Determines if it should be appended starting
	 * at the caret position or at the end.
	 * @param repositionCaret Determines if the caret should be moved to the end of the appended text.
     * @since 0.1.0
     */
		
		virtual void appendText(const std::string &text,
			bool atCurrentPosition = true, bool repositionCaret = true);
	/**
	 * @return The size of the Horizontal Scrollbar.
     * @since 0.1.0
     */
		const Dimension& getHSrollSize() const;
			/**
	 * @return The size of the Vertical Scrollbar.
     * @since 0.1.0
     */
		const Dimension& getVScrollSize() const;
	/**
	 * @return The zero based index of the selection start.
     * @since 0.1.0
     */
		int getSelectionStart() const;
	/**
	 * @return The zero based index of the selection end.
     * @since 0.1.0
     */
		int getSelectionEnd() const;
	/**
	 * @return True if the selection start is the same as the selection end.
     * @since 0.1.0
     */
		virtual bool isSelectionEmpty() const;
	/**
	 * Erases the selected / highlighted text.
     * @since 0.1.0
     */
		virtual void deleteSelection();
			/**
	 * Sets the selected / highlighted text given a zero based start index (in UTF8 characters)
	 * and a zero based end index (in UTF8 characters). (So to highlight the first character call with (0, 1) ).
     * @since 0.1.0
     */
		virtual void setSelection(int startIndex, int endIndex);
	/**
	 * Sets the maximum number of characters that will be scrolled ahead 
	 * when the caret goes too far left or right.
	 *
	 * Not applicable if word wrap is on.
     * @since 0.1.0
     */
		virtual void setMaxCharacterSkip(int val);
	/**
	 * @return The maximum number of characters that will be scrolled ahead 
	 * when the caret goes too far left or right.
	 *
	 * Not applicable if word wrap is on.
     * @since 0.1.0
     */
		virtual int getMaxCharacterSkip() const;
	/**
	 * @return The height of a line. Change this to change line spacing.
     * @since 0.1.0
     */
		virtual int getLineHeight() const;
	/**
	 * @return True if characters cannot be written nor removed via the keyboard.
	 * This does not stop you from calling setText.
     * @since 0.1.0
     */
		bool isReadOnly() const;
	/**
	 * Sets whether or not characters can be written and removed via the keyboard.
	 * This does not stop you from calling setText.
     * @since 0.1.0
     */
		void setReadOnly(bool readOnly);
	/**
	 * @return True if the border will be drawn
     * @since 0.3.0
     */
		bool getDrawBorder() const;
	/**
	 * Sets whether or not border is drawn
     * @since 0.3.0
     */
		void setDrawBorder(bool drawBorder);
	/**
	 * @return True if the text will be split into lines that fit the width of the TextBox.
     * @since 0.1.0
     */
		bool isWordWrap() const;
	/**
	 * Sets whether or not the text will be split into lines that fit the width of the TextBox.
     * @since 0.1.0
     */
		void setWordWrap(bool wordWrap);
		virtual void mouseDrag(MouseEvent &mouseEvent);
		virtual void mouseUp(MouseEvent &mouseEvent);
		virtual void focusGained();
		virtual void setFont(const Font *font);
		virtual void mouseDown(MouseEvent &mouseEvent);
		virtual void keyDown(KeyEvent &keyEvent);
		virtual void keyRepeat(KeyEvent &keyEvent);
	/**
	 * Positions the caret given a column and a row.
     * @since 0.1.0
     */
		virtual void positionCaret(int column, int row);
		virtual void mouseWheelDown(MouseEvent &mouseEvent);
		virtual void mouseWheelUp(MouseEvent &mouseEvent);
	/**
	 * Sets how many values in addition to the actual delta mouse wheel, 
	 * the vertical scrollbar will be 
	 * moved when a mouse wheel event is triggered.
     * @since 0.1.0
     */
		void setWheelScrollRate(int rate);
	/**
	 * @return How many values in addition to the actual delta mouse wheel, 
	 * the vertical scrollbar will be 
	 * moved when a mouse wheel event is triggered.
     * @since 0.1.0
     */
		int getWheelScrollRate() const;
	/**
	 * Scrolls to the caret if needed.
     * @since 0.1.0
     */
		virtual void scrollToCaret();
		virtual void setText(const std::string &text);
		virtual void setSize(const Dimension &size );
		virtual void setSize(int width, int height);
	/**
	 * Sets the Horizontal Scrollbar's policy. (SHOW_ALWAYS, SHOW_AUTO, SHOW_NEVER).
     * @since 0.1.0
     */
		virtual void setHScrollPolicy(ScrollPolicy policy);
	/**
	 * Sets the Vertical Scrollbar's policy. (SHOW_ALWAYS, SHOW_AUTO, SHOW_NEVER).
     * @since 0.1.0
     */
		virtual void setVScrollPolicy(ScrollPolicy policy);
	/**
	 * @return The Horizontal Scrollbar's policy. (SHOW_ALWAYS, SHOW_AUTO, SHOW_NEVER).
     * @since 0.1.0
     */
		virtual ScrollPolicy getHScrollPolicy() const;
	/**
	 * @return The Vertical Scrollbar's policy. (SHOW_ALWAYS, SHOW_AUTO, SHOW_NEVER).
     * @since 0.1.0
     */
		virtual ScrollPolicy getVScrollPolicy() const;
	/**
	 * @return True if the Horizontal Scrollbar is needed (Does not consider policy).
     * @since 0.1.0
     */
		virtual bool isHScrollNeeded() const;
			/**
	 * @return True if the Vertical Scrollbar is needed (Does not consider policy).
     * @since 0.1.0
     */
		virtual bool isVScrollNeeded() const;
	/**
	 * @return The width of the content.
     * @since 0.1.0
     */
		virtual int getContentWidth() const;
	/**
	 * @return The height of the content.
     * @since 0.1.0
     */
		virtual int getContentHeight() const;
	/**
	 * @return The left padding.
     * @since 0.1.0
     */
		virtual int getLeftPadding() const;
	/**
	 * @return The right padding.
     * @since 0.1.0
     */
		virtual int getRightPadding() const;
	/**
	 * @return The top padding.
     * @since 0.1.0
     */
		virtual int getTopPadding() const;
	/**
	 * @return The bottom padding.
     * @since 0.1.0
     */
		virtual int getBottomPadding() const;
	/**
	 * Sets the top padding.
     * @since 0.1.0
     */
		virtual void setTopPadding(int padding);
	/**
	 * Sets the left padding.
     * @since 0.1.0
     */
		virtual void setLeftPadding(int padding);
	/**
	 * Sets the bottom padding.
     * @since 0.1.0
     */
		virtual void setBottomPadding(int padding);
	/**
	 * Sets the right padding.
     * @since 0.1.0
     */
		virtual void setRightPadding(int padding);
	/**
	 * @return WIDTH - LEFT_PADDING - RIGHT_PADDING.
     * @since 0.1.0
     */
		virtual int getAdjustedWidth() const;
	/**
	 * @return HEIGHT - TOP_PADDING - BOTTOM_PADDING.
     * @since 0.1.0
     */
		virtual int getAdjustedHeight() const;
	/**
	 * Selects / highlights all text.
     * @since 0.1.0
     */

		virtual void selectAll();
	/**
	 * Resizes to fit the height if word wrapped, otherwise resizes to fit the width and height.
     * @since 0.1.0
     */
		virtual void resizeToContents();
	/**
	 * @return The caret row.
     * @since 0.1.0
     */
		int getCaretRow() const;
	/**
	 * @return The caret column.
     * @since 0.1.0
     */
		int getCaretColumn() const;
	/**
	 * @return The caret location on the Y axis (Used for rendering).
     * @since 0.1.0
     */
        

        virtual bool isTextBox() const;
        virtual bool canAcceptKeyInput() const;
        
		int getCaretRowLocation() const;
		/**
	 * @return The caret location on the X axis (Used for rendering).
     * @since 0.1.0
     */
		int getCaretColumnLocation() const;

		virtual CursorProvider::CursorEnum getEnterCursor() const;
		/**
	 * Construct with optional HorizontalScrollBar ,
	 * VerticalScrollBar , and ScrollInset Widget.
     * @since 0.1.0
     */
		TextBox(HScrollBar *hScroll = NULL, VScrollBar *vScroll = NULL,
			Widget* scrollInset = NULL);
	/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~TextBox(void);
	};
}
#endif
