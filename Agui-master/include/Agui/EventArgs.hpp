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

#ifndef AGUI_EVENT_ARGS_HPP
#define AGUI_EVENT_ARGS_HPP

#include "Agui/BaseTypes.hpp"
namespace agui {
	class AGUI_CORE_DECLSPEC Widget;
	/**
     * Class for a mouse event.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC MouseEvent {
		Point position;
		int mouseWheelChange;
		MouseButtonEnum button;
		double timeStamp;
		float pressure; 
		bool handled;

		bool isAlt;
		bool isControl;
		bool isShift;
		Widget* source;
	public:
		enum MouseEventEnum{
			MOUSE_DOWN,
			MOUSE_UP,
			MOUSE_MOVE,
			MOUSE_CLICK,
			MOUSE_DOUBLE_CLICK,
			MOUSE_WHEEL_UP,
			MOUSE_WHEEL_DOWN,
			MOUSE_ENTER,
			MOUSE_LEAVE,
			MOUSE_HOVER,
			MOUSE_DRAG,
			MOUSE_MODAL_DOWN,
			MOUSE_MODAL_UP
		};
	/**
	 * This position is usually relative to the widget it is sent to.
     * @return The position of the mouse when the event occurred.
     * @since 0.1.0
     */
		Point getPosition() const;
	/**
     * @return The vertical mouse wheel change (Delta Z). It can be negative.
     * @since 0.1.0
     */
		int getMouseWheelChange() const;
	/**
     * @return The mouse button that was pressed down, or released.
     * @since 0.1.0
     */
		MouseButtonEnum getButton() const;
	/**
     * Not currently implemented by any back ends.
     * @since 0.1.0
     */
		float getPressure() const;
	/**
     * @return How much time the application had been running when the event occurred.
     * @since 0.1.0
     */
		double getTimeStamp() const;
	/**
     * @return The X position of the mouse relative to the source widget.
     * @since 0.1.0
     */
		int getX() const;
	/**
     * @return The Y position of the mouse relative to the source widget.
     * @since 0.1.0
     */
		int getY() const;
	/**
     * @return True if alt was pressed when the event occurred.
     * @since 0.1.0
     */
		bool alt() const;
	/**
     * @return True if control was pressed when the event occurred.
     * @since 0.1.0
     */
		bool control() const;
	/**
     * @return True if shift was pressed when the event occurred.
     * @since 0.1.0
     */
		bool shift() const;
	/**
     * @return True if meta was pressed when the event occurred.
     * @since 0.1.1
     */
		bool meta() const;
	/**
     * @return True if the event has been consumed.
     * @since 0.1.0
     */
		bool isConsumed() const;
	/**
     * Consumes the event. When an event is consumed, it allows the listeners to make decisions based on this.
     * @since 0.1.0
     */
		void consume();

	/**
     * @return The source widget.
     * @since 0.1.0
     */
		Widget* getSourceWidget() const;
	/**
     * Default constructor.
     * @since 0.1.0
     */
		MouseEvent();
	/**
     * Constructs the mouse event.
	 *
	 * The position must already be relative to the source.
     * @since 0.1.0
     */
		MouseEvent(const Point &position,
			int mouseWheelChange, MouseButtonEnum button, double timeStamp, float pressure, 
			bool isAlt, bool isControl, bool isShift, Widget* source = NULL, bool handled = false);
	};
	/**
     * Class for a key event.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC KeyEvent {
		UTF8 utf8Manager;
		int unichar;
		double timeStamp;
		int _key;
		int _modKey;
		ExtendedKeyEnum extKey;
		KeyEnum key;
		bool isAlt;
		bool isControl;
		bool isShift;
		bool isMeta;
		bool handled;

		Widget* source;
	public:
		enum KeyboardEventEnum {
			KEY_DOWN,
			KEY_UP,
			KEY_REPEAT
		};

	/**
     * @return True if alt was pressed when the event occurred.
     * @since 0.1.0
     */
		bool alt() const;
	/**
     * @return True if control was pressed when the event occurred.
     * @since 0.1.0
     */
		bool control() const;
	/**
     * @return True if shift was pressed when the event occurred.
     * @since 0.1.0
     */
		bool shift() const;
	/**
     * @return True if meta was pressed when the event occurred.
     * @since 0.1.0
     */
		bool meta() const;
	/**
     * Consumes the event. When an event is consumed, it allows the listeners to make decisions based on this.
     * @since 0.1.0
     */
		void consume();
	/**
     * @return True if the event has been consumed.
     * @since 0.1.0
     */
		bool isConsumed() const;
	/**
     * @return The number of bytes this character occupies (from 1 to 4 bytes).
     * @since 0.1.0
     */
		size_t getUtf8Length() const;
	/**
	* @return The character as a std::string since UTF8 characters can be more than 1 byte.
     * @since 0.1.0
     */
		std::string getUtf8String() const;
	/**
     * @return How much time the application had been running when the event occurred.
     * @since 0.1.0
     */
		double getTimeStamp() const;
	/**
     * @return The key code specific to the back end.
     * @since 0.1.0
     */
		int getBackendKeycode() const;
	/**
     * @return The UTF32 code point for this key event.
     * @since 0.1.0
     */
		unsigned int getUnichar() const;
	/**
     * @return The modifier flags specific to the back end.
     * @since 0.1.0
     */
		int getBackendModifierKeyFlags() const;
	/**
     * @return The extended key pressed or EXT_KEY_NONE if no extended key was pressed.
     * @since 0.1.0
     */
		ExtendedKeyEnum getExtendedKey() const;
	/**
     * @return The ascii key pressed or KEY_NONE if no ascii key was pressed.
     * @since 0.1.0
     */
		KeyEnum getKey() const;
	/**
     * Default constructor.
     * @since 0.1.0
     */
		KeyEvent();
	/**
     * Constructs the key event.
	 *
	 * The unichar is a UTF32 code point.
     * @since 0.1.0
     */
		KeyEvent(KeyEnum key, ExtendedKeyEnum extKey,
			int _key, int _modKey, 
			unsigned int unichar, double timeStamp, bool isAlt,
			bool isControl, bool isShift, bool isMeta,
			Widget* source = 0, bool handled = false);
	};

	/**
     * Class for a paint event.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC PaintEvent {
		bool enabled;
		Graphics *graphicsContext;
	public:
	
	/**
	* Although the widget itself may be enabled, 
	* if any of its parents are disabled, all the children are inherently disabled.
     * @return Whether the widget should be drawn with an enabled or disabled look.
     * @since 0.1.0
     */
		bool isEnabled() const;
	/**
     * @return The graphics context used to call drawing methods.
     * @since 0.1.0
     */
		Graphics* graphics() const;
	/**
     * Constructs the paint event.
     * @since 0.1.0
     */
		PaintEvent(bool enabled,Graphics *g);
	/**
     * Default constructor.
     * @since 0.1.0
     */
		PaintEvent();
	/**
     * Default destructor.
     * @since 0.1.0
     */
		virtual ~PaintEvent();

	};

	/**
     * Generic mouse input class generated by back ends when they receive a mouse event.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC MouseInput {
	public:
		MouseButtonEnum button;
		int x;
		int y;
		int wheel;
		float pressure;
		double timeStamp;
		MouseEvent::MouseEventEnum type;

		bool isAlt;
		bool isControl;
		bool isShift;

		MouseInput(MouseEvent::MouseEventEnum event,MouseButtonEnum button, int x, int y, int wheel, 
			float pressure, double timeStamp,bool isAlt,
		bool isShift,bool isControl)

		{
			this->button = button;
			this->x = x;
			this->y = y;
			this->wheel = wheel;
			this->pressure = pressure;
			this->timeStamp = timeStamp;

			this->isAlt = isAlt;
			this->isShift = isShift;
			this->isControl = isControl;
			this->type = event;
		}

	};

	/**
     * Generic keyboard input class generated by back ends when they receive a keyboard event.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC KeyboardInput {
	public:
		KeyEnum key;
		KeyEvent::KeyboardEventEnum type;
		ExtendedKeyEnum extKey;
		int _key;
		int _modifierKey;
		unsigned int unichar;
		double timeStamp;

		bool isAlt;
		bool isShift;
		bool isControl;
		bool isMeta;

		KeyboardInput(KeyEvent::KeyboardEventEnum event, KeyEnum key, ExtendedKeyEnum extKey,
			unsigned int unichar,
			double timeStamp, bool isAlt, bool isShift, bool isControl, bool isMeta,
			int _key = 0, 
			int _modifierKey = 0)
		{
			this->key = key;
			this->extKey = extKey;
			this->_key = _key;
			this->_modifierKey = _modifierKey;
			this->unichar = unichar;
			this->timeStamp = timeStamp;
			this->isAlt = isAlt;
			this->isShift = isShift;
			this->isControl = isControl;
			this->isMeta = isMeta;
			this->type = event;
		}

	};
}
#endif