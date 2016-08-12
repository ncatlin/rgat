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

#ifndef AGUI_COLOR_HPP
#define AGUI_COLOR_HPP
#include "Agui/Platform.hpp"
namespace agui
{
	/**
     * Class used for colors.
	 *
	 * Uses floating point precision.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC Color {
		float r;
		float g;
		float b;
		float a;
		static bool premultiplyAlpha;
	/**
     * Ensures that colors are in the correct range.
     * @since 0.1.0
     */
		void verifyColorBounds();
	public:
	/**
     * @return A boolean indicating if the RGB components of the color should be multiplied by the A component.
     * @since 0.1.0
     */
		static bool isAlphaPremultiplied();
	/**
     * Sets if the RGB components of the color should be multiplied by the A component.
     * @since 0.1.0
     */
		static void setPremultiplyAlpha(bool premultiply);
		/**
     * Construct a color using, Red, Green, Blue, Alpha values ranging from 0 to 255.
     * @since 0.1.0
     */
		Color(int r, int g, int b, int a);
	/**
     * Construct a color using, Red, Green, Blue values ranging from 0 to 255.
     * @since 0.1.0
     */
		Color(int r, int g, int b);
	/**
     * Construct a color using, Red, Green, Blue, Alpha values ranging from 0.0 to 1.0.
     * @since 0.1.0
     */
		Color(float r, float g, float b, float a);
	/**
     * Construct a color using, Red, Green, Blue values ranging from 0.0 to 1.0.
     * @since 0.1.0
     */
		Color(float r, float g, float b);
	/**
     * Default constructor
	 *
	 * Will result in black.
     * @since 0.1.0
     */
		Color();
	/**
     * @return The Red component from 0.0 to 1.0.
     * @since 0.1.0
     */
		float getR() const;
	/**
     * @return The Green component from 0.0 to 1.0.
     * @since 0.1.0
     */
		float getG() const;
	/**
     * @return The Blue component from 0.0 to 1.0.
     * @since 0.1.0
     */
		float getB() const;
	/**
     * @return The Alpha component from 0.0 to 1.0.
     * @since 0.1.0
     */
		float getA() const;
	/**
     * @return True if the two colors have the same RGBA values.
     * @since 0.1.0
     */
		bool operator==(const Color &refCol);
	/**
     * @return True if the two colors do not have the same RGBA values.
     * @since 0.1.0
     */
		bool operator!=(const Color &refCol);
	};
}
#endif
