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

#ifndef AGUI_ALLEGRO5_INPUT
#define AGUI_ALLEGRO5_INPUT
#include "Agui/Input.hpp"
#include <vector>

#include <allegro5/allegro.h>
#include <allegro5/allegro5.h>
namespace agui
{
	class AGUI_BACKEND_DECLSPEC Allegro5Input :
		public Input
	{
		bool shift;
		bool control;
		bool alt;
		bool meta;

		ALLEGRO_KEYBOARD_EVENT prevEvent;
		std::vector<ALLEGRO_KEYBOARD_EVENT> keyEvents;

	 MouseInput createMouse(const ALLEGRO_EVENT &event);
	 KeyboardInput createKeyboard(const ALLEGRO_KEYBOARD_EVENT *event,
		 bool isKeyDown, bool isRepeat );

	 ExtendedKeyEnum getExtendedKey(int key) const;
	 bool isModifierKey(int key);
	 KeyEnum getKeyFromKeycode(int keycode) const;
	public:
		Allegro5Input(void);
		virtual double getTime() const;
		virtual void processEvent(const ALLEGRO_EVENT &event);
		virtual ~Allegro5Input(void);
	};
}
#endif
