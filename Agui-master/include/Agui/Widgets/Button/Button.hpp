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

#ifndef AGUI_BUTTON_HPP
#define AGUI_BUTTON_HPP

#include "Agui/Widget.hpp"
namespace agui {
	class AGUI_CORE_DECLSPEC ButtonListener;

	 /**
	 * Class that represents a Button that can be pushed or toggled.
	 *
	 * ActionEvent when:
	 *
	 * Clicked.
	 *
	 * Space key is released.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC Button : public Widget {
	public:
		enum ButtonStateEnum {
			DEFAULT,
			HOVERED,
			CLICKED
		};
	private:
		std::vector<std::string> wrappedText;
		std::vector<ButtonListener*> buttonListeners;
		AreaAlignmentEnum textAlignment;
		Button::ButtonStateEnum buttonState;
		bool mouseIsInside;
		bool mouseIsDown;
		bool isDoingKeyAction;
		bool isButtonToggleButton;
		bool toggled;
		bool autoUntoggle;
		Button::ButtonStateEnum mouseLeaveState;

	protected:
		ResizableText resizableText;
	 /**
	 * Internally changes the toggled value.
     * @since 0.1.0
     */
		void modifyIsToggled(bool toggled);
		virtual void paintComponent(const PaintEvent &paintEvent);
		virtual void paintBackground(const PaintEvent &paintEvent);
	 /**
	 * Changes the toggled value to NOT toggled value and changes the button state to reflect it.
     * @since 0.1.0
     */
		virtual void handleToggleClick();
	/**
	 * Internally changes the button's state.
     * @since 0.1.0
     */
		virtual void changeButtonState(Button::ButtonStateEnum state);
	/**
	 * Internally changes the button's state based on the mouse.
     * @since 0.1.0
     */
		virtual void modifyButtonState();
	/**
	 * @return The area text vector.
     * @since 0.1.0
     */
		virtual const std::vector<std::string>& getAreaText() const;
	public:
	/**
	 * Default constructor.
     * @since 0.1.0
     */
		Button();
	/**
	 * Resizes the button to fit the width and height of the text + margins.
     * @since 0.1.0
     */
		virtual void resizeToContents();
	/**
	 * Manually changes the toggle state.
     * @since 0.1.0
     */
		virtual void setToggleState(bool toggled);
	/**
	 * Determines the state of the button when the mouse leaves and the mouse is down.
     * @since 0.1.0
     */
		void setMouseLeaveState(Button::ButtonStateEnum state);
	/**
	 * @return The state of the button when the mouse leaves and the mouse is down.
     * @since 0.1.0
     */
		Button::ButtonStateEnum getMouseLeaveState() const;
	/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~Button(void);
	/**
	 * Sets the caption text on the button.
     * @since 0.1.0
     */
		virtual void setText(const std::string &text);
	/**
	 * Sets the alignment of the caption text.
     * @since 0.1.0
     */
		void setTextAlignment(AreaAlignmentEnum alignment);
	/**
	 * @return The alignment of the caption text.
     * @since 0.1.0
     */
		AreaAlignmentEnum getTextAlignment() const;
		/**
	 * @return The state of the button.
     * @since 0.1.0
     */
		Button::ButtonStateEnum getButtonState() const;
	/**
	 * @return True if this button can be toggled.
     * @since 0.1.0
     */
		bool isToggleButton() const;
			/**
	 * @return True if this button is toggled.
     * @since 0.1.0
     */
		bool isToggled() const;
	/**
	 * Sets whether or not this button is a toggle button.
     * @since 0.1.0
     */
		void setToggleButton(bool toggleButton);

	/**
	 * @return True if the button will untoggle itself when it is toggled and then clicked.
     * @since 0.2.0
     */
		bool isAutoUntoggling() const;
	/**
	 * Sets whether or not the button will untoggle itself when it is toggled and then clicked.
     * @since 0.2.0
     */
		void setAutoUntoggle(bool untoggle);
	/**
	 * @return True if mouse is inside the button.
     * @since 0.2.0
     */
		bool isMouseInside() const;
	/**
	 * Manually sets the current button state. Will be changed when the button gets an event.
     * @since 0.1.0
     */
		void setButtonState(ButtonStateEnum state);

		virtual void setSize(const Dimension &size);
		virtual void setSize(int width, int height);
		virtual void setFont(const Font *font);
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
	 * Adds the parameter button listener.
     * @since 0.1.0
     */
		void addButtonListener(
			ButtonListener* listener);
	/**
	 * Removes the parameter button listener.
     * @since 0.1.0
     */
		void removeButtonListener(
			ButtonListener* listener);


	};
}
#endif
