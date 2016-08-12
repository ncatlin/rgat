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

#ifndef AGUI_RECTANGLE_HPP
#define AGUI_RECTANGLE_HPP
#include "Agui/Platform.hpp"
#include "Agui/Point.hpp"
#include "Agui/Dimension.hpp"
#include "Agui/Color.hpp"
#include <stdlib.h>
#include <string>
#include <sstream>
namespace agui
{
	/**
     * Class used to represent an integer Rectangle. Also used for clipping rectangles.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC Rectangle {
		int x;
		int y;
		int width;
		int height;
	public:
	/**
     * @return True if the point is inside the rectangle.
     * @since 0.1.0
     */
		bool pointInside(const Point &p) const;
	/**
     * @return True if the width and height are 0.
     * @since 0.1.0
     */
		bool isEmpty() const;
	/**
     * @return The X coordinate of the rectangle.
     * @since 0.1.0
     */
		int getX() const;
	/**
     * @return The Y coordinate of the rectangle.
     * @since 0.1.0
     */
		int getY() const;
	/**
     * @return The width of the rectangle.
     * @since 0.1.0
     */
		int getWidth() const;
	/**
     * @return The height of the rectangle.
     * @since 0.1.0
     */
		int getHeight() const;
	/**
     * @return The Y coordinate of the rectangle.
     * @since 0.1.0
     */
		int getTop() const;
	/**
     * @return The X coordinate of the rectangle.
     * @since 0.1.0
     */
		int getLeft() const;
	/**
     * @return The Y coordinate + the height of the rectangle.
     * @since 0.1.0
     */
		int getBottom() const;
	/**
     * @return The X coordinate + the width of the rectangle.
     * @since 0.1.0
     */
		int getRight() const;
	/**
     * @return The size of the rectangle.
     * @since 0.1.0
     */
		Dimension getSize() const;
	/**
     * @return A Rectangle made from TLBR.
     * @since 0.1.0
     */
		static Rectangle fromTLBR(int top, int left, 
			int bottom, int right) ;
	/**
     * @return The top left Point.
     * @since 0.1.0
     */
		Point getLeftTop() const;
	/**
     * @return The top right Point.
     * @since 0.1.0
     */
		Point getTopRight() const;
	/**
     * @return The bottom left Point.
     * @since 0.1.0
     */
		Point getBottomLeft() const;
	/**
     * @return The bottom right Point.
     * @since 0.1.0
     */
		Point getRightBottom() const;
	/**
     * Default constructor.
     * @since 0.1.0
     */
		Rectangle();
	/**
     * Constructs a Rectangle with an x , y coordinate, a width, and height.
     * @since 0.1.0
     */
		Rectangle(int x, int y, int width, int height);
	/**
     * Constructs a Rectangle with an Point and Dimension.
     * @since 0.1.0
     */
		Rectangle(Point location,Dimension size);
	};

}
#endif
