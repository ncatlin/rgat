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

#include "Agui/EventArgs.hpp"
namespace agui {
	Point MouseEvent::getPosition() const
	{
		return position;
	}

	int MouseEvent::getMouseWheelChange() const
	{
		return mouseWheelChange;
	}

	MouseButtonEnum MouseEvent::getButton() const
	{
		return button;
	}

	int MouseEvent::getX() const
	{
		return position.getX();
	}

	int MouseEvent::getY() const
	{
		return position.getY();
	}

	MouseEvent::MouseEvent()
	{
		mouseWheelChange = 0;
		timeStamp = 0;
		pressure = 0;
		button = MOUSE_BUTTON_NONE;
	}


	MouseEvent::MouseEvent( const Point &position, 
										   int mouseWheelChange,
										   MouseButtonEnum button,
										   double timeStamp,
										   float pressure, 
										   bool isAlt, bool isControl,
										   bool isShift, 
										   Widget* source /*= 0*/,
										   bool handled /*= false*/ )
	{
		this->position = position;
		this->mouseWheelChange = mouseWheelChange;
		this->button = button;
		this->pressure = pressure;
		this->timeStamp = timeStamp;

		this->isAlt = isAlt;
		this->isControl = isControl;
		this->isShift = isShift;
		this->handled = handled;

		this->source = source;

	}

	float MouseEvent::getPressure() const
	{
		return pressure;
	}

	double MouseEvent::getTimeStamp() const
	{
		return timeStamp;
	}

	bool MouseEvent::alt() const
	{
		return isAlt;
	}

	bool MouseEvent::control() const
	{
		return isControl;
	}

	bool MouseEvent::shift() const
	{
		return isShift;
	}

	bool MouseEvent::isConsumed() const
	{
		return handled;
	}

	void MouseEvent::consume()
	{
		this->handled = true;
	}

	Widget* MouseEvent::getSourceWidget() const
	{
		return source;
	}

	bool KeyEvent::alt() const
	{
		return isAlt;
	}

	KeyEvent::KeyEvent()
	{
		isAlt = false;
		isControl = false;
		isShift = false;
		isMeta = false;
		timeStamp = 0;
		unichar = 0;

		_key = 0;
		_modKey = 0;
		this->handled = false;
	}



	KeyEvent::KeyEvent(KeyEnum key, ExtendedKeyEnum extKey,
									   int _key, int _modKey,
									   unsigned int unichar,
									   double timeStamp,
									   bool isAlt, bool isControl,
									   bool isShift, bool isMeta,
									   Widget* source /*= 0*/, 
									   bool handled /*= false*/ )
	{
		this->key = key;
		this->extKey = extKey;
		this->_key = _key;
		this->_modKey = _modKey;
		this->unichar = unichar;
		this->timeStamp = timeStamp;
		this->handled = handled;
		this->isAlt = isAlt;
		this->isControl = isControl;
		this->isShift = isShift;
		this->isMeta = isMeta;
		this->source = source;
	}



	bool KeyEvent::control() const
	{
		return isControl;
	}

	bool KeyEvent::shift() const
	{
		return isShift;
	}

	int KeyEvent::getBackendKeycode() const
	{
		return _key;
	}

	int KeyEvent::getBackendModifierKeyFlags() const
	{
		return _modKey;
	}

	void KeyEvent::consume()
	{
		this->handled = true;
	}

	bool KeyEvent::isConsumed() const
	{
		return handled;
	}

	double KeyEvent::getTimeStamp() const
	{
	return timeStamp;
	}

	size_t KeyEvent::getUtf8Length() const
	{
		return utf8Manager.getUnicharLength(unichar);
	}

	std::string KeyEvent::getUtf8String() const
	{
		char b[5];
		int sz = int(utf8Manager.encodeUtf8(b,unichar));
		b[sz] = 0;
		return std::string(b);
	}

	unsigned int KeyEvent::getUnichar() const
	{
		return unichar;
	}

	ExtendedKeyEnum KeyEvent::getExtendedKey() const
	{
		return extKey;
	}

	KeyEnum KeyEvent::getKey() const
	{
		return key;
	}

	bool KeyEvent::meta() const
	{
		return isMeta;
	}

	PaintEvent::PaintEvent()
	{
		enabled = true;
	}


	PaintEvent::PaintEvent( bool enabled,Graphics *g )
	{
		this->enabled = enabled;
		graphicsContext = g;
	}

	bool PaintEvent::isEnabled() const
	{
		return enabled;
	}

	Graphics* PaintEvent::graphics() const
	{
		return graphicsContext;
	}

	PaintEvent::~PaintEvent()
	{

	}

}
