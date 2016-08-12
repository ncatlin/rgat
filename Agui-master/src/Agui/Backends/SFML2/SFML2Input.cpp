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

#include "Agui/Backends/SFML2/SFML2Input.hpp"
namespace agui
{
	SFML2Input::SFML2Input(void)
		: alt(false),shift(false),control(false),
		meta(false),
		lastMouseX(0),lastMouseY(0),lmbDown(false),
		rmbDown(false),mmbDown(false)
	{
	}

	SFML2Input::~SFML2Input(void)
	{
	}

	double SFML2Input::getTime() const
	{
		return (double)clock.getElapsedTime().asSeconds();
	}

	void SFML2Input::processEvent( const sf::Event &event )
	{
		MouseInput mi = MouseInput(
			MouseEvent::MOUSE_MOVE,MOUSE_BUTTON_NONE,0,0,0,0,0,false,false,false);
		bool success;
		switch(event.type)
		{
		case sf::Event::MouseWheelMoved:
		case sf::Event::MouseButtonPressed:
		case sf::Event::MouseButtonReleased:
		case sf::Event::MouseLeft:
		case sf::Event::MouseMoved:
			if(isMouseEnabled())
			{
				success = createMouse(event,mi);
				if(success)
					pushMouseEvent(mi);
			}
			break;
		case sf::Event::LostFocus:
			{
				control = false;
				alt = false;
				shift = false;
				meta = false;

				std::list<sf::Keyboard::Key>::iterator i = m_keys.begin();
				while (i != m_keys.end())
				{
					bool isActive = false;
					if (!isActive)
					{
						sf::Keyboard::Key k = (*i);
						bool down = false;
						unsigned int unichar = 0;
						KeyEnum key = getKeyFromKeycode(*i);
						ExtendedKeyEnum extkey = getExtendedKey(*i);
						if(isKeyboardEnabled())
						{
							pushKeyboardEvent(createKeyboard(key,extkey,unichar,down));
						}
						m_keys.erase(i++);  // alternatively, i = items.erase(i);
					}
					else
					{
						++i;
					}
				}
			}
			break;
		case sf::Event::TextEntered:
		case sf::Event::KeyPressed:
		case sf::Event::KeyReleased:
			{
				if(event.type != sf::Event::TextEntered)
				{
					control = event.key.control;
					alt = event.key.alt;
					shift = event.key.shift;
					meta = event.key.system;
				}
		
				if(isKeyboardEnabled())
				{
					if(event.type != sf::Event::TextEntered && event.key.code < 0)
						return;

					if(event.type == sf::Event::KeyPressed)
						m_prev = event.key.code;

					bool down = event.type != sf::Event::KeyReleased;
					unsigned int unichar = event.type == sf::Event::TextEntered ? event.text.unicode : 0;
					KeyEnum key = getKeyFromKeycode( event.type == sf::Event::TextEntered ? m_prev : event.key.code );
					ExtendedKeyEnum extkey = getExtendedKey( event.type == sf::Event::TextEntered ? m_prev : event.key.code );

					if ( control && down && event.key.code >= 'a' && event.key.code <= 'z' )
					{
						unichar = event.key.code;
					}
					if(event.type == sf::Event::KeyPressed && event.key.code != sf::Keyboard::Delete && !isModifierKey(event.key.code) && getExtendedKey(event.key.code) == EXT_KEY_NONE && unichar == 0)
						break;

						if(down)
							m_keys.push_back( event.type == sf::Event::TextEntered ? m_prev : event.key.code );
						else
							removeKeyFromList(event.key.code);

						pushKeyboardEvent(createKeyboard(key,extkey,unichar,down));
				}
			}
			break;

		default:
			break;
		}
	}

	bool SFML2Input::createMouse( const sf::Event &event, MouseInput& input )
	{
			MouseEvent::MouseEventEnum type = MouseEvent::MOUSE_DOWN;

			int mx = 0;
			int my = 0;
			int dz = 0;

			switch(event.type)
			{
			case sf::Event::MouseWheelMoved:
				if(event.mouseWheel.delta > 0)
					type = MouseEvent::MOUSE_WHEEL_UP;
				else
					type = MouseEvent::MOUSE_WHEEL_DOWN;
				mx = event.mouseWheel.x;
				my = event.mouseWheel.y;
				dz = event.mouseWheel.delta;
				lastMouseX = mx;
				lastMouseY = my;
				break;
			case sf::Event::MouseButtonPressed:
				type = MouseEvent::MOUSE_DOWN;
				mx = event.mouseButton.x;
				my = event.mouseButton.y;
				lastMouseX = mx;
				lastMouseY = my;
				break;
			case sf::Event::MouseButtonReleased:
				type = MouseEvent::MOUSE_UP;
				mx = event.mouseButton.x;
				my = event.mouseButton.y;
				lastMouseX = mx;
				lastMouseY = my;
				break;
			case sf::Event::MouseLeft:
				{
					type = MouseEvent::MOUSE_UP;
					if(lmbDown)
					{
						lmbDown = false;
						MouseInput mi = MouseInput(type,
							MOUSE_BUTTON_LEFT,
							lastMouseX,
							lastMouseY,
							0,
							0,
							getTime(),
							alt, shift, control);
						pushMouseEvent(mi);
					}

					if(rmbDown)
					{
						rmbDown = false;
						MouseInput mi = MouseInput(type,
							MOUSE_BUTTON_RIGHT,
							lastMouseX,
							lastMouseY,
							0,
							0,
							getTime(),
							alt, shift, control);
						pushMouseEvent(mi);
					}

					if(mmbDown)
					{
						mmbDown = false;
						MouseInput mi = MouseInput(type,
							MOUSE_BUTTON_MIDDLE,
							lastMouseX,
							lastMouseY,
							0,
							0,
							getTime(),
							alt, shift, control);
						pushMouseEvent(mi);
					}

					return false;
				}
				break;
			case sf::Event::MouseMoved:
				type = MouseEvent::MOUSE_MOVE;
				mx = event.mouseMove.x;
				my = event.mouseMove.y;
				lastMouseX = mx;
				lastMouseY = my;
				break;
			default:
				break;
			}
			MouseButtonEnum button = MOUSE_BUTTON_NONE;
			if(event.type == sf::Event::MouseButtonPressed || event.type == sf::Event::MouseButtonReleased)
			{
				switch(event.mouseButton.button)
				{
				case sf::Mouse::Left:
					button = MOUSE_BUTTON_LEFT;
					lmbDown = event.type == sf::Event::MouseButtonPressed;
					break;
				case sf::Mouse::Right: 
					button = MOUSE_BUTTON_RIGHT;
					rmbDown = event.type == sf::Event::MouseButtonPressed;
					break;
				case sf::Mouse::Middle:
					button = MOUSE_BUTTON_MIDDLE;
					mmbDown = event.type == sf::Event::MouseButtonPressed;
					break;
				default:
					button = MOUSE_BUTTON_NONE;
					return false;
					break;
				}
			}

			input = MouseInput(type,
				button,
				mx,
				my,
				dz,
				0,
				getTime(),
				alt, shift, control);

			return true;
	}

	agui::ExtendedKeyEnum SFML2Input::getExtendedKey( sf::Keyboard::Key key ) const
	{
		ExtendedKeyEnum extKey = EXT_KEY_NONE;

			switch (key)
			{
			case sf::Keyboard::LAlt:
			case sf::Keyboard::RAlt:
				extKey = EXT_KEY_ALT;
				break;
			case sf::Keyboard::LShift:
				extKey = EXT_KEY_LEFT_SHIFT;
				break;
			case sf::Keyboard::RShift:
				extKey = EXT_KEY_RIGHT_SHIFT;
				break;
			case sf::Keyboard::LControl:
				extKey = EXT_KEY_LEFT_CONTROL;
				break;
			case sf::Keyboard::RControl:
				extKey = EXT_KEY_RIGHT_CONTROL;
				break;
			case sf::Keyboard::LSystem:
				extKey = EXT_KEY_LEFT_META;
				break;
			case sf::Keyboard::RSystem:
				extKey = EXT_KEY_RIGHT_META;
				break;
			case sf::Keyboard::Home:
				extKey = EXT_KEY_HOME;
				break;
			case sf::Keyboard::Insert:
				extKey = EXT_KEY_INSERT;
				break;
			case sf::Keyboard::PageDown:
				extKey = EXT_KEY_PAGE_DOWN;
				break;
			case sf::Keyboard::PageUp:
				extKey = EXT_KEY_PAGE_UP;
				break;
			case sf::Keyboard::End:
				extKey = EXT_KEY_END;
				break;
				//case sf::Keyboard::
				//extKey = EXT_KEY_CAPS_LOCK;
				//break;
			case sf::Keyboard::F1:
				extKey = EXT_KEY_F1;
				break;
			case sf::Keyboard::F2:
				extKey = EXT_KEY_F2;
				break;
			case sf::Keyboard::F3:
				extKey = EXT_KEY_F3;
				break;
			case sf::Keyboard::F4:
				extKey = EXT_KEY_F4;
				break;
			case sf::Keyboard::F5:
				extKey = EXT_KEY_F5;
				break;
			case sf::Keyboard::F6:
				extKey = EXT_KEY_F6;
				break;
			case sf::Keyboard::F7:
				extKey = EXT_KEY_F7;
				break;
			case sf::Keyboard::F8:
				extKey = EXT_KEY_F8;
				break;
			case sf::Keyboard::F9:
				extKey = EXT_KEY_F9;
				break;
			case sf::Keyboard::F10:
				extKey = EXT_KEY_F10;
				break;
			case sf::Keyboard::F11:
				extKey = EXT_KEY_F11;
				break;
			case sf::Keyboard::F12:
				extKey = EXT_KEY_F12;
				break;
			//case sf::Keyboard::p:
			//	extKey = EXT_KEY_PRINT_SCREEN;
			//	break;
			//case sf::Keyboard::sc:
			//	extKey = EXT_KEY_SCROLL_LOCK;
			//	break;
			case sf::Keyboard::Pause:
				extKey = EXT_KEY_PAUSE;
				break;
			//case sf::Keyboard::num:
			//	extKey = EXT_KEY_NUM_LOCK;
			//	break;
			//case sf::Keyboard::g:
			//	extKey = EXT_KEY_ALTGR;
			//	break;
			case sf::Keyboard::Up:
				extKey = EXT_KEY_UP;
				break;
			case sf::Keyboard::Down:
				extKey = EXT_KEY_DOWN;
				break;
			case sf::Keyboard::Left:
				extKey = EXT_KEY_LEFT;
				break;
			case sf::Keyboard::Right:
				extKey = EXT_KEY_RIGHT;
				break;
			default:
				break;
			}

		return extKey;
	}

	bool SFML2Input::isModifierKey( sf::Keyboard::Key key )
	{
		switch(key)
		{
		case sf::Keyboard::LAlt:
		case sf::Keyboard::RAlt:
		case sf::Keyboard::LShift:
		case sf::Keyboard::RShift:
		case sf::Keyboard::LControl:
		case sf::Keyboard::RControl:
		case sf::Keyboard::LSystem:
		case sf::Keyboard::RSystem:
		case sf::Keyboard::Menu:
			return true;
			break;
		default:
			return false;
			break;
		}
	}

	agui::KeyEnum SFML2Input::getKeyFromKeycode( sf::Keyboard::Key key ) const
	{
		KeyEnum k = KEY_NONE;
		switch(key)
		{
		case sf::Keyboard::Tab:
			k = KEY_TAB;
			break;
		case sf::Keyboard::Return:
			k = KEY_ENTER;
			break;
		case sf::Keyboard::Escape:
			k = KEY_ESCAPE;
			break;
		case sf::Keyboard::Space:
			k = KEY_SPACE;
			break;
		case sf::Keyboard::Tilde:
			k = KEY_TIDLE;
			break;
		case sf::Keyboard::Dash:
			k = KEY_HYPHEN;
			break;
		case sf::Keyboard::Equal:
			k = KEY_EQUALS;
			break;
		case sf::Keyboard::Period:
			k = KEY_PERIOD;
			break;
		case sf::Keyboard::Comma:
			k = KEY_COMMA;
			break;
		case sf::Keyboard::Quote:
			k = KEY_SINGLE_QUOTATION;
			break;
		case sf::Keyboard::Slash:
			k = KEY_FORWARDSLASH;
			break;
		case sf::Keyboard::BackSlash:
			k = KEY_BACKSLASH;
			break;
		//case sf::Keyboard::bac:
		//	k = KEY_BACKSLASH;
		//	break;
		case sf::Keyboard::LBracket:
			k = KEY_OPEN_BRACE;
			break;
		case sf::Keyboard::RBracket:
			k = KEY_CLOSING_BRACE;
			break;
		case sf::Keyboard::A:
			k = KEY_A;
			break;
		case sf::Keyboard::B:
			k = KEY_B;
			break;
		case sf::Keyboard::C:
			k = KEY_C;
			break;
		case sf::Keyboard::D:
			k = KEY_D;
			break;
		case sf::Keyboard::E:
			k = KEY_E;
			break;
		case sf::Keyboard::F:
			k = KEY_F;
			break;
		case sf::Keyboard::G:
			k = KEY_G;
			break;
		case sf::Keyboard::H:
			k = KEY_H;
			break;
		case sf::Keyboard::I:
			k = KEY_I;
			break;
		case sf::Keyboard::J:
			k = KEY_J;
			break;
		case sf::Keyboard::K:
			k = KEY_K;
			break;
		case sf::Keyboard::L:
			k = KEY_L;
			break;
		case sf::Keyboard::M:
			k = KEY_M;
			break;
		case sf::Keyboard::N:
			k = KEY_N;
			break;
		case sf::Keyboard::O:
			k = KEY_O;
			break;
		case sf::Keyboard::P:
			k = KEY_P;
			break;
		case sf::Keyboard::Q:
			k = KEY_Q;
			break;
		case sf::Keyboard::R:
			k = KEY_R;
			break;
		case sf::Keyboard::S:
			k = KEY_S;
			break;
		case sf::Keyboard::T:
			k = KEY_T;
			break;
		case sf::Keyboard::U:
			k = KEY_U;
			break;
		case sf::Keyboard::V:
			k = KEY_V;
			break;
		case sf::Keyboard::W:
			k = KEY_W;
			break;
		case sf::Keyboard::X:
			k = KEY_X;
			break;
		case sf::Keyboard::Y:
			k = KEY_Y;
			break;
		case sf::Keyboard::Z:
			k = KEY_Z;
			break;
		case sf::Keyboard::Num0:
			k = KEY_0;
			break;
		case sf::Keyboard::Num1:
			k = KEY_1;
			break;
		case sf::Keyboard::Num2:
			k = KEY_2;
			break;
		case sf::Keyboard::Num3:
			k = KEY_3;
			break;
		case sf::Keyboard::Num4:
			k = KEY_4;
			break;
		case sf::Keyboard::Num5:
			k = KEY_5;
			break;
		case sf::Keyboard::Num6:
			k = KEY_6;
			break;
		case sf::Keyboard::Num7:
			k = KEY_7;
			break;
		case sf::Keyboard::Num8:
			k = KEY_8;
			break;
		case sf::Keyboard::Num9:
			k = KEY_9;
			break;
		case sf::Keyboard::Delete:
			k = KEY_DELETE;
			break;
		case sf::Keyboard::BackSpace:
			k = KEY_BACKSPACE;
			break;
		}
		return k;
	}

	agui::KeyboardInput SFML2Input::createKeyboard( KeyEnum key,ExtendedKeyEnum extKey,unsigned int unichar, bool down )
	{
		return KeyboardInput(down ? KeyEvent::KEY_DOWN : KeyEvent::KEY_UP,key,extKey,unichar,getTime(),alt,shift,control,meta);
	}

	void SFML2Input::removeKeyFromList( sf::Keyboard::Key key )
	{
		std::list<sf::Keyboard::Key>::iterator i = m_keys.begin();
		while (i != m_keys.end())
		{
			bool isActive = (*i) == key;
			if (!isActive)
			{
				m_keys.erase(i++);  // alternatively, i = items.erase(i);
			}
			else
			{
				++i;
			}
		}
	}
}
