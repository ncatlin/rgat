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

#ifndef AGUI_BLINKING_EVENT_HPP
#define AGUI_BLINKING_EVENT_HPP
#include "Agui/Platform.hpp"
namespace agui
{
	
	 /**
	 * Class for anything that blinks. Used by TextBox and TextField.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC BlinkingEvent
	{
		double blinkInterval;
		double lastBlinkTime;
		bool blinking;
		bool blinkNeedsInvalidation;

	public:
	/**
     * Default constructor.
     * @since 0.1.0
     */
		BlinkingEvent(void);
	/**
     * Used to determine if isBlinking should return true.
	 *
	 * Should be called in a widget's logic method.
	 * @param elapsedTime The Amount of time the application has been running.
     * @since 0.1.0
     */
		void processBlinkEvent(double elapsedTime);
		/**
	 * When this method returns true, a TextBox's caret is visible.
     * @return A boolean determining if the object should be seen.
     * @since 0.1.0
     */
		bool isBlinking() const;
		/**
     * Sets isBlinking to true and resets the amount of time before isBinking returns false.
	 *
	 * When a delay between the next blink is needed, call this method.
     * @since 0.1.0
     */
		void invalidateBlink();
	/**
     * This will explicitly make isBlinking return the parameter boolean.
	 *
	 * Should be called in a widget's logic method.
	 * @param blinking The boolean isBlinking will return until the blink interval elapses.
     * @since 0.1.0
     */
		void setBlinking(bool blinking);
	/**
     * Determines how much time needs to elapse before isBlinking's return value changes.
	 *
	 * Default is 0.5 (half of a second).
	 * @param interval The time in seconds between each blink.
     * @since 0.1.0
     */
		void setBlinkingInverval(double interval);
		virtual ~BlinkingEvent(void);
	};
}
#endif
