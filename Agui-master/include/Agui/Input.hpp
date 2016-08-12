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

#ifndef AGUI_INPUT_HPP
#define AGUI_INPUT_HPP
#include "Agui/Platform.hpp"
#include "Agui/EventArgs.hpp"
#include <queue>

namespace agui
{

	/**
     * Abstract class for Input.
	 *
	 * Should implement:
	 *
	 * A method to receive a back end specific event and convert it
	 * to MouseInput or KeyboardInput.
	 *
	 * getTime (default uses std::clock)
	 *
	 * Should respect:
	 *
	 * isMouseEnabled
	 *
	 * isKeyboardEnabled
     * @author Joshua Larouche
     * @since 0.1.0
     */

	class AGUI_CORE_DECLSPEC Input
	{
		double startTime;
		std::queue<MouseInput> mouseEvents;
		std::queue<KeyboardInput> keyboardEvents;
		bool mouseEnabled;
		bool keyboardEnabled;
        bool touchCompatibility;
        bool wheelOnDrag;
        bool wantIneria;
	protected:
	/**
	 * Default constructor.
     */
		Input(void);
	public:
	/**
	 * Called by the Gui in its logic loop. Used for non event driven back ends.
     */
		virtual void pollInput();
	/**
	 * Pushes a mouse event which will be dequeued and processed in the next logic loop.
     */
		void pushMouseEvent(const MouseInput &input);
	/**
	 * Pushes a keyboard event which will be dequeued and processed in the next logic loop.
     */
		void pushKeyboardEvent(const KeyboardInput &input);
	/**
	 * @return True if no mouse events are queued.
     */
		bool isMouseQueueEmpty() const;
	/**
	 * @return True if no keyboard events are queued.
     */
		bool isKeyboardQueueEmpty() const;
	/**
	 * Called by the Gui to process the event.
	 * @return The keyboard event information and removes it from the queue.
     */
		const KeyboardInput dequeueKeyboardInput();
	/**
	 * Called by the Gui to process the event.
	 * @return The mouse event information and removes it from the queue.
     */
		const MouseInput dequeueMouseInput();
	/**
	 * @return The amount of time the application has been running in seconds.
     */
		virtual double getTime() const;
	/**
	 * Set whether or not keyboard input is enabled for the Gui.
     */
		void setKeyboardEnabled(bool enabled);
	/**
	 * Set whether or not mouse input is enabled for the Gui.
     */
		void setMouseEnabled(bool enabled);
	/**
	 * @return True if mouse input is enabled for the Gui.
     */
		bool isMouseEnabled() const;
	/**
	 * @return True if keyboard input is enabled for the Gui.
     */
		bool isKeyboardEnabled() const;
   /**
   * Set whether or not mouse events will be injected for touch compatibility.
   */
   void setTouchCompatibility(bool enabled);
   /**
   * @return True if mouse events will be injected for touch compatibility.
   */
    bool isUsingTouchCompatibility() const;
        
    /**
    * Set whether or not a mouse wheel event will be sent on drag.
    */
    void setMouseWheelOnDrag(bool enabled);
    /**
    * @return True if a mouse wheel event will be sent on drag.
    */
    bool wantMouseWheelOnDrag() const;
        
    /**
    * Set whether or not touch inertia will be simulated as mousewheel events.
    */
    void setInertiaScrolling(bool enabled);
    /**
    * @return True if inertia scrolling will be simulated as mousewheel events.
    */
    bool wantInertiaScrolling() const;
            
	/**
	 * Default destructor.
     */
		virtual ~Input(void);
	};
}

#endif
