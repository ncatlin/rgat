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

#ifndef AGUI_DIMENSION_HPP
#define AGUI_DIMENSION_HPP
#include "Agui/Platform.hpp"
#include <stdlib.h>
#include <string>
#include <sstream>
namespace agui
{
	/**
     * Class used for the size / dimensions of widgets and other objects.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC Dimension {
		int width;
		int height;
	public:
	/**
     * @return The width.
     * @since 0.1.0
     */
		int getWidth() const;
	/**
     * @return The height.
     * @since 0.1.0
     */
		int getHeight() const;
	/**
     * Sets the width.
	 * @param width The desired width.
     * @since 0.1.0
     */
		void setWidth(int width);
	/**
     * Sets the height.
	 * @param height The desired height.
     * @since 0.1.0
     */
		void setHeight(int height);
	/**
     * Sets the width and height.
	 * @param width The desired width.
	 * @param height The desired height.
     * @since 0.1.0
     */
		void set(int width, int height);
	/**
     * Sets the width and height, floats will be interpreted as ints.
	 * @param width The desired width.
	 * @param height The desired height.
     * @since 0.1.0
     */
		void set(float width, float height);
	/**
     * Constructs to the desired width and height.
	 * @param width The desired width.
	 * @param height The desired height.
     * @since 0.1.0
     */
		Dimension(int width, int height);
	/**
     * Default constructor, initializes to 0,0.
     * @since 0.1.0
     */
		Dimension();
	/**
     * @return "{WIDTH,HEIGHT}".
     * @since 0.1.0
     */
		std::string toString() const;
	/**
     * @return "WIDTH".
     * @since 0.1.0
     */
		std::string widthToString() const;
			/**
     * @return "HEIGHT".
     * @since 0.1.0
     */
		std::string heightToString() const;

	};

}

#endif