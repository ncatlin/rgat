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

#include "Agui/Backends/Allegro5/Allegro5Input.hpp"

namespace agui
{

	Allegro5Input::Allegro5Input(void)
		: shift(false), control(false), alt(false), meta(false)
	{
	}

	Allegro5Input::~Allegro5Input(void)
	{
	}

	double Allegro5Input::getTime() const
	{
		return al_get_time();
	}

	void Allegro5Input::processEvent( const ALLEGRO_EVENT &event )
	{
		if(event.type == ALLEGRO_EVENT_MOUSE_LEAVE_DISPLAY)
		{
			al_set_system_mouse_cursor(al_get_current_display(),
				ALLEGRO_SYSTEM_MOUSE_CURSOR_DEFAULT);
		}

		switch (event.type)
		{
		case ALLEGRO_EVENT_MOUSE_AXES:
		case ALLEGRO_EVENT_MOUSE_BUTTON_DOWN:
		case ALLEGRO_EVENT_MOUSE_BUTTON_UP:
		case ALLEGRO_EVENT_MOUSE_LEAVE_DISPLAY:
			if(isMouseEnabled())
			{
				pushMouseEvent(createMouse(event));
			}
			break;
		case ALLEGRO_EVENT_KEY_DOWN:
		case ALLEGRO_EVENT_KEY_CHAR:
			{
				// this avoid duplicate events for key that generate down and char events
			
				if(event.keyboard.keycode == ALLEGRO_KEY_LSHIFT || 
					event.keyboard.keycode == ALLEGRO_KEY_RSHIFT)
				{
					shift = true;
				}

				if(event.keyboard.keycode == ALLEGRO_KEY_LCTRL || 
					event.keyboard.keycode == ALLEGRO_KEY_RCTRL)
				{
					control = true;
				}

				if(event.keyboard.keycode == ALLEGRO_KEY_ALT)
				{
					alt = true;
				}

                if(event.keyboard.keycode == ALLEGRO_KEY_COMMAND || event.keyboard.keycode == ALLEGRO_KEY_LWIN || event.keyboard.keycode == ALLEGRO_KEY_RWIN)
				{
					meta = true;
				}


				if(event.type == ALLEGRO_EVENT_KEY_DOWN && (
					!isModifierKey(event.keyboard.keycode) && event.keyboard.unichar == 0))
					break;
				if(isKeyboardEnabled())
				pushKeyboardEvent(createKeyboard(&event.keyboard,true,event.keyboard.repeat));
				break;
			}

		case ALLEGRO_EVENT_KEY_UP:		
				if(event.keyboard.keycode == ALLEGRO_KEY_LSHIFT || 
				event.keyboard.keycode == ALLEGRO_KEY_RSHIFT)
			{
				shift = false;
			}

			if(event.keyboard.keycode == ALLEGRO_KEY_LCTRL || 
				event.keyboard.keycode == ALLEGRO_KEY_RCTRL)
			{
				control = false;
			}

			if(event.keyboard.keycode == ALLEGRO_KEY_ALT)
			{
				alt = false;
			}

			if(event.keyboard.keycode == ALLEGRO_KEY_COMMAND || event.keyboard.keycode == ALLEGRO_KEY_LWIN || event.keyboard.keycode == ALLEGRO_KEY_RWIN)
			{
				meta = false;
			}

			if(isKeyboardEnabled())
				pushKeyboardEvent(createKeyboard(&event.keyboard,false,false));
				break;
		case ALLEGRO_EVENT_DISPLAY_SWITCH_IN:
			shift = false;
			alt = false;
			control = false;
			meta = false;
			break;
		default:
			break;
			}
	}

	MouseInput Allegro5Input::createMouse( const ALLEGRO_EVENT &event )
	{
		MouseEvent::MouseEventEnum type = MouseEvent::MOUSE_DOWN;

		switch(event.type)
		{
		case ALLEGRO_EVENT_MOUSE_AXES:
			if(event.mouse.dz > 0)
			{
				type = MouseEvent::MOUSE_WHEEL_UP;
			}
			else if(event.mouse.dz < 0)
			{
				type = MouseEvent::MOUSE_WHEEL_DOWN;
			}
			else
			{
				type = MouseEvent::MOUSE_MOVE;
			}

			break;
		case ALLEGRO_EVENT_MOUSE_BUTTON_DOWN:
			type = MouseEvent::MOUSE_DOWN;
			break;
		case ALLEGRO_EVENT_MOUSE_BUTTON_UP:
			type = MouseEvent::MOUSE_UP;
			break;
		case ALLEGRO_EVENT_MOUSE_LEAVE_DISPLAY:
			type = MouseEvent::MOUSE_MOVE;
			break;
		default:
			break;
		}
		MouseButtonEnum button;
		switch(event.mouse.button)
		{
		case 0:
			button = MOUSE_BUTTON_NONE;
			break;
		case 1:
			button = MOUSE_BUTTON_LEFT;
			break;
		case 2: 
			button = MOUSE_BUTTON_RIGHT;
			break;
		case 3:
			button = MOUSE_BUTTON_MIDDLE;
			break;
		default:
			button = MOUSE_BUTTON_NONE;
			break;
		}
		return MouseInput(type,
			button,
			event.mouse.x,
			event.mouse.y,
			event.mouse.dz,
			event.mouse.pressure,
			event.mouse.timestamp,
			alt, shift, control);
	}

	KeyboardInput Allegro5Input::createKeyboard( 
		const ALLEGRO_KEYBOARD_EVENT *event,
		bool isKeyDown,
		bool isRepeat )
	{
		if(isKeyDown)
		{
			keyEvents.push_back(*event);

			prevEvent = *event;
		}
		else
		{
			for(std::vector<ALLEGRO_KEYBOARD_EVENT>::iterator it =
				keyEvents.begin(); it != keyEvents.end(); it++)
			{
				if(it->keycode == event->keycode)
				{
					prevEvent = *it;
					if(!isRepeat)
					{
						it = keyEvents.erase(it);
						break;
					}

				}
			}
		}

		KeyEnum key = KEY_NONE;
		if(prevEvent.unichar < 128)
		{
			key = getKeyFromKeycode(prevEvent.keycode);

			if(key == KEY_NONE)
			{
				key = (KeyEnum)prevEvent.unichar;
			}
		}

		if(prevEvent.keycode == ALLEGRO_KEY_DELETE)
		{
			key = KEY_DELETE;
		}
		else if(prevEvent.keycode == ALLEGRO_KEY_BACKSPACE)
		{
			key = KEY_BACKSPACE;
		}
		else if(prevEvent.keycode == ALLEGRO_KEY_TAB)
		{
			key = KEY_TAB;
		}
		else if(prevEvent.keycode == ALLEGRO_KEY_ESCAPE)
		{
			key = KEY_ESCAPE;
		}
		else if(prevEvent.keycode == ALLEGRO_KEY_ENTER)
		{
			key = KEY_ENTER;
		}


		KeyEvent::KeyboardEventEnum type;
		if(isRepeat)
		{
			type = KeyEvent::KEY_REPEAT;
		}
		else if(isKeyDown)
		{
			type = KeyEvent::KEY_DOWN;
		}
		else
		{
			type = KeyEvent::KEY_UP;
		}
		return KeyboardInput(
			type,
			key,
			getExtendedKey(event->keycode),
			prevEvent.unichar,
			event->timestamp,
			alt,
			shift,
			control,
			meta,
			event->keycode,
			event->modifiers);
	}

	ExtendedKeyEnum Allegro5Input::getExtendedKey( int key ) const
	{
		ExtendedKeyEnum extKey = EXT_KEY_NONE;

		switch (key)
		{
		case ALLEGRO_KEY_ALT:
			extKey = EXT_KEY_ALT;
			break;
		case ALLEGRO_KEY_LSHIFT:
			extKey = EXT_KEY_LEFT_SHIFT;
			break;
		case ALLEGRO_KEY_RSHIFT:
			extKey = EXT_KEY_RIGHT_SHIFT;
			break;
		case ALLEGRO_KEY_LCTRL:
			extKey = EXT_KEY_LEFT_CONTROL;
			break;
		case ALLEGRO_KEY_RCTRL:
			extKey = EXT_KEY_RIGHT_CONTROL;
			break;
		case ALLEGRO_KEY_LWIN:
			extKey = EXT_KEY_LEFT_META;
			break;
		case ALLEGRO_KEY_RWIN:
			extKey = EXT_KEY_RIGHT_META;
			break;
		case ALLEGRO_KEY_HOME:
			extKey = EXT_KEY_HOME;
			break;
		case ALLEGRO_KEY_INSERT:
			extKey = EXT_KEY_INSERT;
			break;
		case ALLEGRO_KEY_PGDN:
			extKey = EXT_KEY_PAGE_DOWN;
			break;
		case ALLEGRO_KEY_PGUP:
			extKey = EXT_KEY_PAGE_UP;
			break;
		case ALLEGRO_KEY_END:
			extKey = EXT_KEY_END;
			break;
		case ALLEGRO_KEY_CAPSLOCK:
			extKey = EXT_KEY_CAPS_LOCK;
			break;
		case ALLEGRO_KEY_F1:
			extKey = EXT_KEY_F1;
			break;
		case ALLEGRO_KEY_F2:
			extKey = EXT_KEY_F2;
			break;
		case ALLEGRO_KEY_F3:
			extKey = EXT_KEY_F3;
			break;
		case ALLEGRO_KEY_F4:
			extKey = EXT_KEY_F4;
			break;
		case ALLEGRO_KEY_F5:
			extKey = EXT_KEY_F5;
			break;
		case ALLEGRO_KEY_F6:
			extKey = EXT_KEY_F6;
			break;
		case ALLEGRO_KEY_F7:
			extKey = EXT_KEY_F7;
			break;
		case ALLEGRO_KEY_F8:
			extKey = EXT_KEY_F8;
			break;
		case ALLEGRO_KEY_F9:
			extKey = EXT_KEY_F9;
			break;
		case ALLEGRO_KEY_F10:
			extKey = EXT_KEY_F10;
			break;
		case ALLEGRO_KEY_F11:
			extKey = EXT_KEY_F11;
			break;
		case ALLEGRO_KEY_F12:
			extKey = EXT_KEY_F12;
			break;
		case ALLEGRO_KEY_PRINTSCREEN:
			extKey = EXT_KEY_PRINT_SCREEN;
			break;
		case ALLEGRO_KEY_SCROLLLOCK:
			extKey = EXT_KEY_SCROLL_LOCK;
			break;
		case ALLEGRO_KEY_PAUSE:
			extKey = EXT_KEY_PAUSE;
			break;
		case ALLEGRO_KEY_NUMLOCK:
			extKey = EXT_KEY_NUM_LOCK;
			break;
		case ALLEGRO_KEY_ALTGR:
			extKey = EXT_KEY_ALTGR;
			break;
		case ALLEGRO_KEY_UP:
			extKey = EXT_KEY_UP;
			break;
		case ALLEGRO_KEY_DOWN:
			extKey = EXT_KEY_DOWN;
			break;
		case ALLEGRO_KEY_LEFT:
			extKey = EXT_KEY_LEFT;
			break;
		case ALLEGRO_KEY_RIGHT:
			extKey = EXT_KEY_RIGHT;
			break;

		default:
			break;
		}
		return extKey;
	}

	bool Allegro5Input::isModifierKey( int key )
	{
		switch(key)
		{
		case ALLEGRO_KEY_LSHIFT:
		case ALLEGRO_KEY_RSHIFT:
		case ALLEGRO_KEY_LCTRL:
		case ALLEGRO_KEY_RCTRL:
		case ALLEGRO_KEY_ALTGR:
		case ALLEGRO_KEY_ALT:
		case ALLEGRO_KEY_LWIN:
		case ALLEGRO_KEY_RWIN:
		case ALLEGRO_KEY_MENU:
		case ALLEGRO_KEY_COMMAND:
		case ALLEGRO_KEY_SCROLLLOCK:
		case ALLEGRO_KEY_CAPSLOCK:
		case ALLEGRO_KEY_NUMLOCK:
			return true;
		break;
		default:
			return false;
		break;
		}
	}

	KeyEnum Allegro5Input::getKeyFromKeycode( int keycode ) const
	{
		KeyEnum k = KEY_NONE;
		switch(keycode)
		{
		case ALLEGRO_KEY_TAB:
			k = KEY_TAB;
			break;
		case ALLEGRO_KEY_ENTER:
			k = KEY_ENTER;
			break;
		case ALLEGRO_KEY_ESCAPE:
			k = KEY_ESCAPE;
			break;
		case ALLEGRO_KEY_SPACE:
			k = KEY_SPACE;
			break;
		case ALLEGRO_KEY_TILDE:
			k = KEY_TIDLE;
			break;
		case ALLEGRO_KEY_MINUS:
			k = KEY_HYPHEN;
			break;
		case ALLEGRO_KEY_EQUALS:
			k = KEY_EQUALS;
			break;
		case ALLEGRO_KEY_FULLSTOP:
			k = KEY_PERIOD;
			break;
		case ALLEGRO_KEY_COMMA:
			k = KEY_COMMA;
			break;
		case ALLEGRO_KEY_QUOTE:
			k = KEY_SINGLE_QUOTATION;
			break;
		case ALLEGRO_KEY_SLASH:
			k = KEY_FORWARDSLASH;
			break;
		case ALLEGRO_KEY_BACKSLASH:
			k = KEY_BACKSLASH;
			break;
		case ALLEGRO_KEY_BACKSLASH2:
			k = KEY_BACKSLASH;
			break;
		case ALLEGRO_KEY_OPENBRACE:
			k = KEY_OPEN_BRACE;
			break;
		case ALLEGRO_KEY_CLOSEBRACE:
			k = KEY_CLOSING_BRACE;
			break;
		case ALLEGRO_KEY_A:
			k = KEY_A;
			break;
		case ALLEGRO_KEY_B:
			k = KEY_B;
			break;
		case ALLEGRO_KEY_C:
			k = KEY_C;
			break;
		case ALLEGRO_KEY_D:
			k = KEY_D;
			break;
		case ALLEGRO_KEY_E:
			k = KEY_E;
			break;
		case ALLEGRO_KEY_F:
			k = KEY_F;
			break;
		case ALLEGRO_KEY_G:
			k = KEY_G;
			break;
		case ALLEGRO_KEY_H:
			k = KEY_H;
			break;
		case ALLEGRO_KEY_I:
			k = KEY_I;
			break;
		case ALLEGRO_KEY_J:
			k = KEY_J;
			break;
		case ALLEGRO_KEY_K:
			k = KEY_K;
			break;
		case ALLEGRO_KEY_L:
			k = KEY_L;
			break;
		case ALLEGRO_KEY_M:
			k = KEY_M;
			break;
		case ALLEGRO_KEY_N:
			k = KEY_N;
			break;
		case ALLEGRO_KEY_O:
			k = KEY_O;
			break;
		case ALLEGRO_KEY_P:
			k = KEY_P;
			break;
		case ALLEGRO_KEY_Q:
			k = KEY_Q;
			break;
		case ALLEGRO_KEY_R:
			k = KEY_R;
			break;
		case ALLEGRO_KEY_S:
			k = KEY_S;
			break;
		case ALLEGRO_KEY_T:
			k = KEY_T;
			break;
		case ALLEGRO_KEY_U:
			k = KEY_U;
			break;
		case ALLEGRO_KEY_V:
			k = KEY_V;
			break;
		case ALLEGRO_KEY_W:
			k = KEY_W;
			break;
		case ALLEGRO_KEY_X:
			k = KEY_X;
			break;
		case ALLEGRO_KEY_Y:
			k = KEY_Y;
			break;
		case ALLEGRO_KEY_Z:
			k = KEY_Z;
			break;
		case ALLEGRO_KEY_0:
			k = KEY_0;
			break;
		case ALLEGRO_KEY_1:
			k = KEY_1;
			break;
		case ALLEGRO_KEY_2:
			k = KEY_2;
			break;
		case ALLEGRO_KEY_3:
			k = KEY_3;
			break;
		case ALLEGRO_KEY_4:
			k = KEY_4;
			break;
		case ALLEGRO_KEY_5:
			k = KEY_5;
			break;
		case ALLEGRO_KEY_6:
			k = KEY_6;
			break;
		case ALLEGRO_KEY_7:
			k = KEY_7;
			break;
		case ALLEGRO_KEY_8:
			k = KEY_8;
			break;
		case ALLEGRO_KEY_9:
			k = KEY_9;
			break;
		}

		return k;
	}

}