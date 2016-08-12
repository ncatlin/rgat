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

#include "Agui/Input.hpp"
#include <stdio.h>
#include <ctime>
namespace agui
{
	Input::Input(void)
		: startTime( std::clock() / 1000),
        mouseEnabled(true), keyboardEnabled(true),
        touchCompatibility(false), wheelOnDrag(false),
        wantIneria(false)
	{
	}

	Input::~Input(void)
	{
	}

	double Input::getTime() const
	{
		return (std::clock() / 1000.0f) - startTime;
	}

	void Input::pushMouseEvent( const MouseInput &input )
	{
		mouseEvents.push(input);
	}

	void Input::pushKeyboardEvent( const KeyboardInput &input )
	{
		keyboardEvents.push(input);
	}

	bool Input::isMouseQueueEmpty() const
	{
		return mouseEvents.empty();
	}

	bool Input::isKeyboardQueueEmpty() const
	{
		return keyboardEvents.empty();
	}

	const KeyboardInput Input::dequeueKeyboardInput()
	{
		if(isKeyboardQueueEmpty())
		{
			throw Exception("Keyboard queue is empty!");
		}


		KeyboardInput currentKeyInput = keyboardEvents.front();
		keyboardEvents.pop();
		return currentKeyInput;
	}

	const MouseInput Input::dequeueMouseInput()
	{
		if(isMouseQueueEmpty())
		{
			throw Exception("Mouse queue is empty!");
		}

		MouseInput currentMouseInput = mouseEvents.front();
		mouseEvents.pop();
		return currentMouseInput;
	}

	void Input::setKeyboardEnabled( bool enabled )
	{
		keyboardEnabled = enabled;
	}

	void Input::setMouseEnabled( bool enabled )
	{
		mouseEnabled = enabled;
	}

	bool Input::isMouseEnabled() const
	{
		return mouseEnabled;
	}
    
    void Input::setTouchCompatibility( bool enabled )
    {
        touchCompatibility = enabled;
    }
    
    bool Input::isUsingTouchCompatibility() const
    {
        return touchCompatibility;
    }
    
    void Input::setMouseWheelOnDrag( bool enabled )
    {
        wheelOnDrag = enabled;
    }
    
    bool Input::wantMouseWheelOnDrag() const
    {
        return wheelOnDrag;
    }

	bool Input::isKeyboardEnabled() const
	{
		return keyboardEnabled;
	}

	void Input::pollInput()
	{

	}
    
    /**
     * Set whether or not touch inertia will be simulated as mousewheel events.
     */
    void Input::setInertiaScrolling(bool enabled) {
        wantIneria = enabled;
    }
    /**
     * @return True if inertia scrolling will be simulated as mousewheel events.
     */
    bool Input::wantInertiaScrolling() const {
        return wantIneria;
    }

}

