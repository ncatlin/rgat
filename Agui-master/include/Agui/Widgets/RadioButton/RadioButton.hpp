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

#ifndef AGUI_RADIO_BUTTON_HPP
#define AGUI_RADIO_BUTTON_HPP
#include "Agui/Widget.hpp"
namespace agui {
	class AGUI_CORE_DECLSPEC RadioButtonListener;
	/**
	 * Class that represents a RadioButton that can be CHECKED, UNCHECKED.
	 *
	 * Used with:
	 *
	 * RadioButtonGroup
	 *
	 * ActionEvent when:
	 *
	 * State becomes Checked.
	 *
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC RadioButton : public Widget
	{
	public:
		enum RadioButtonStateEnum {
			DEFAULT,
			HOVERED,
			CLICKED
		};

		enum RadioButtonCheckedEnum {
			UNCHECKED,
			CHECKED
		};

	private:
		int sidePadding;
		Rectangle wordWrapRect;
		std::vector<std::string> wordWrappedLines;
		std::vector<RadioButtonListener*> radioButtonListeners;
		bool autosizingCheckbox;
		int radioButtonRadius;
		Point radioButtonPosition;
		Rectangle radioButtonRect;
		AreaAlignmentEnum textAlignment;
		AreaAlignmentEnum radioButtonAlignment;
		RadioButton::RadioButtonStateEnum radioButtonState;
		RadioButton::RadioButtonCheckedEnum checkedState;
		bool mouseIsInside;
		bool mouseIsDown;
		bool isDoingKeyAction;
	protected:
		ResizableText textAreaMan;
			 /**
	 * @return std::vector of strings used to draw the text.
     * @since 0.1.0
     */
		virtual const std::vector<std::string>& getTextLines() const;

	 /**
	 * @return Rectangle provided when drawing the text.
     * @since 0.1.0
     */
		virtual const Rectangle& getWordWrapRect() const;

	/**
	 * Internally sets the widget size.
     * @since 0.1.0
     */
		void _setSizeInternal(const Dimension &size);
	 /**
	 * Internally changes the RadioButton's state.
     * @since 0.1.0
     */
		void changeRadioButtonState(RadioButton::RadioButtonStateEnum state);
	/**
	 * Internally changes the checked state.
     * @since 0.1.0
     */
		void changeCheckedState(RadioButton::RadioButtonCheckedEnum state);
	/**
	 * Internally modifies the RadioButton state.
     * @since 0.1.0
     */
		void modifyRadioButtonState();
	/**
	 * Internally changes to the next logical checked state.
     * @since 0.1.0
     */
		void nextCheckState();
	/**
	 * Generates the Rectangle used to draw the RadioButton and a position
	 * that can be used to draw a circle from its center to the radius.
     * @since 0.1.0
     */
		virtual void positionRadioButton();
	/**
	 * @return A position that can be used to draw a circle from its center to the radius.
     * @since 0.1.0
     */
		virtual const Point& getRadioButtonPosition() const;
	/**
	 * Internally resizes the caption text.
     * @since 0.1.0
     */
		virtual void resizeCaption();
	/**
	 * @return The Rectangle used to draw the RadioButton itself.
     * @since 0.1.0
     */
		virtual const Rectangle& getRadioButtonRectangle() const;

		virtual void paintComponent(const PaintEvent &paintEvent);
		virtual void paintBackground(const PaintEvent &paintEvent);
	public:
			/**
	 * @return The side padding. This pads symmetrically from left to right or 
	 * top to bottom depending on alignment.
     * @since 0.1.0
     */
		virtual int getSidePadding() const;
	/**
	 * Sets the side padding. This pads symmetrically from left to right or 
	 * top to bottom depending on alignment.
     * @since 0.1.0
     */
		virtual void setSidePadding(int padding);
		virtual void setLocation(const Point &location);
		virtual void setLocation(int x, int y);
		virtual void setFont(const Font *font);
		virtual void setSize(const Dimension &size);
		virtual void setSize(int width, int height);
		virtual void setText(const std::string &text);
		virtual void focusGained();
		virtual void focusLost();
		virtual void mouseEnter(MouseEvent &mouseEvent);
		virtual void mouseLeave(MouseEvent &mouseEvent);
		virtual void mouseDown(MouseEvent &mouseEvent);
		virtual void mouseUp(MouseEvent &mouseEvent);
		virtual void mouseClick(MouseEvent &mouseEvent);
		virtual void keyDown(KeyEvent &keyEvent);
		virtual void keyUp(KeyEvent &keyEvent);
	/**
	 * Sets whether or not the RadioButton is checked.
     * @since 0.1.0
     */
		virtual void setChecked(bool checked);
	/**
	 * @return True if the RadioButton is checked.
     * @since 0.1.0
     */
		virtual bool checked() const;
	/**
	 * @return True if the RadioButton is automatically sizing itself.
	 *
	 * If this is true, any calls to setSize will not do anything.
     * @since 0.1.0
     */
		virtual bool isAutosizing();
	/**
	 * Sets if the RadioButton is automatically sizing itself.
	 *
	 * If this is true, any calls to setSize will not do anything.
     * @since 0.1.0
     */
		virtual void setAutosizing(bool autosizing);
	/**
	 * Sets the radius of the actual RadioButton.
     * @since 0.1.0
     */
		virtual void setRadioButtonRadius(int size);
	/**
	 * @return The radius of the actual RadioButton.
     * @since 0.1.0
     */
		virtual int getRadioButtonRadius() const;
		virtual void setFontColor(const Color &color);
	/**
	 * Sets the alignment of the actual RadioButton.
     * @since 0.1.0
     */
		virtual void setRadioButtonAlignment(AreaAlignmentEnum alignment);
	/**
	 * @return The alignment of the actual RadioButton.
     * @since 0.1.0
     */
		virtual AreaAlignmentEnum getRadioButtonAlignment() const;
	/**
	 * Sets the alignment of the caption text.
     * @since 0.1.0
     */
		virtual void setTextAlignment(AreaAlignmentEnum alignment);
	/**
	 * @return The alignment of the caption text.
     * @since 0.1.0
     */
		virtual AreaAlignmentEnum getTextAlignment() const;
/**
	 * Resizes the RadioButton to a size that fits the caption nicely.
     * @since 0.1.0
     */
		virtual void resizeToContents();
	/**
	 * @return The state of the RadioButton (DEFAULT, HOVERED, CLICKED).
     * @since 0.1.0
     */
		RadioButton::RadioButtonStateEnum getRadioButtonState() const;
	/**
	 * @return The Checked state of the RadioButton (UNCHECKED, CHECKED).
     * @since 0.1.0
     */
		RadioButton::RadioButtonCheckedEnum getCheckedState() const;
	/**
	 * Default constructor.
     * @since 0.1.0
     */
		RadioButton();
	/**
	 * Adds the parameter RadioButtonListener.
     * @since 0.1.0
     */
		virtual void addRadioButtonListener(
			RadioButtonListener* listener);
	/**
	 * Removes the parameter RadioButtonListener.
     * @since 0.1.0
     */
		virtual void removeRadioButtonListener(
			RadioButtonListener* listener);
	/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~RadioButton(void);
	};
}
#endif
