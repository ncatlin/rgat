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

#ifndef AGUI_SFML2_INPUT_HPP
#define AGUI_SFML2_INPUT_HPP
#include "Agui/Input.hpp"
#include <SFML/Graphics.hpp>
#include <list>
namespace agui
{
	class AGUI_BACKEND_DECLSPEC SFML2Input : public Input
	{
		sf::Clock clock; // starts the clock
		bool alt;
		bool shift;
		bool control;
		bool meta;

		bool lmbDown;
		bool rmbDown;
		bool mmbDown;
		int lastMouseX;
		int lastMouseY;
		std::list<sf::Keyboard::Key> m_keys;
		sf::Keyboard::Key m_prev;
		ExtendedKeyEnum getExtendedKey(sf::Keyboard::Key key) const;
		bool isModifierKey(sf::Keyboard::Key key);
		KeyEnum getKeyFromKeycode(sf::Keyboard::Key key) const;
		bool createMouse(const sf::Event &event, MouseInput& input);
		KeyboardInput createKeyboard(KeyEnum key,ExtendedKeyEnum extKey,unsigned int unichar, bool down);
		void removeKeyFromList(sf::Keyboard::Key key);
	public:
		SFML2Input(void);
		virtual double getTime() const;
		virtual void processEvent(const sf::Event &event);
		virtual ~SFML2Input(void);
	};
}
#endif
