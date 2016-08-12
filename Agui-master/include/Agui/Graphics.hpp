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

#ifndef AGUI_GRAPHICS_HPP
#define AGUI_GRAPHICS_HPP


#include "Agui/BaseTypes.hpp"
#include <stack>
namespace agui {
	/**
     * Abstract class for Graphics and drawing methods.
	 *
	 * Must implement:
	 *
	 * _beginPaint
	 *
	 * _endPaint
	 *
	 * setClippingRectangle
	 *
	 * getDisplaySize
	 *
	 * getClippingRectangle
	 *
	 * drawImage
	 *
	 * drawScaledImage
	 *
	 * drawText
	 *
	 * drawRectangle
	 *
	 * drawFilledRectangle
	 *
	 * drawImage
	 *
	 * drawCircle
	 *
	 * drawFilledCircle
	 *
	 * drawPixel
	 *
	 * drawLine
	 *
	 * setTargetImage
	 *
	 * resetTargetImage
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC Graphics {
	private:
		std::stack<Rectangle> clipStack;
		Rectangle clipRect;
		int T, L, B, R;
		Rectangle workingRect;
		Point offset;
		float globalOpacity;
	protected:
		virtual void setClippingRectangle(const Rectangle &rect) = 0;

	public:
	/**
	 * Called before a widget is painted.
     */
		virtual void _beginPaint() = 0;
	/**
	 * Called after a widget is painted.
     */
		virtual void _endPaint() = 0;
	/**
	 * @return The offset used internally to simulate relative painting.
	 *
	 * All drawing coordinates must be added to this value.
     */
		const Point& getOffset() const;
     /**
	 * Sets the offset used internally to simulate relative painting.
	 *
	 * All drawing coordinates must be added to this value.
     */
		void setOffset(const Point &offset);
	/**
	 * Default constructor.
     */
		Graphics() : globalOpacity(1.0f) {}
	/**
	 * Default destructor.
     */
		virtual ~Graphics() {};
	/**
	 * @return The size of the native display / window.
     */
		virtual Dimension getDisplaySize() = 0;
	/**
	 * @return The clipping rectangle.
     */
		virtual Rectangle getClippingRectangle() = 0;
	/**
	 * Pushes the parameter rectangle onto the clipping stack.
	 *
	 * The resulting clipping rectangle will be an intersection of all the clipping rectangles.
     */
		void pushClippingRect(const Rectangle &rect);
	/**
	 * Pops a clipping rectangle off the clipping rectangle stack.
	 *
	 * The resulting clipping rectangle will be an intersection of all the clipping rectangles.
     */
		void popClippingRect();
	/**
	 * @return A reference to the clipping stack.
     */
		const std::stack<Rectangle>& getClippingStack() const;
	/**
	 * Sets the parameter stack as the clipping stack and sets the current offset.
     */
		void setClippingStack(const std::stack<Rectangle> &clippingStack, const Point &offset);
	/**
	 * @return The number of rectangles in the clipping stack.
     */
		size_t getClippingRectCount() const;
	/**
	 * Clears the clipping stack. The clipping rectangle is now the display size.
     */
		void clearClippingStack();
	/**
	 * Draws an image.
	 * @param bmp The image to draw.
	 * @param position Where to draw the image's top left pixel.
	 * @param regionStart Which pixel on the image will be drawn at position.
	 * @param regionSize How much of the image, starting at regionStart, will be drawn.
	 * @param opacity How opaque the image will be drawn.
     */
		virtual void drawImage(const Image *bmp,
			const Point &position,const Point &regionStart,
			const Dimension &regionSize, const float &opacity = 1.0f) = 0;
		/**
	 * Draws an image.
	 * @param bmp The image to draw.
	 * @param position Where to draw the image's top left pixel.
	 * @param opacity How opaque the image will be drawn.
     */
		virtual void drawImage(const Image *bmp,const Point &position,
			const float &opacity = 1.0f) = 0;
	/**
	 * Draws a scaled image.
	 * @param bmp The image to draw.
	 * @param position Where to draw the image's top left pixel.
	 * @param regionStart Which pixel on the image will be drawn at position.
	 * @param regionScale How much of the image, starting at regionStart, will be drawn.
	 * @param scale The size that the specified region will be stretched to.
	 * @param opacity How opaque the image will be drawn.
     */
		virtual void drawScaledImage(const Image *bmp,
			const Point &position,
			const Point &regionStart,
			const Dimension &regionScale,
			const Dimension &scale,
			const float &opacity = 1.0f) = 0;
	/**
	 * Draws a dynamically scalable image.
	 *
	 * It will use the Image's margins to determine which regions should be stretched and which should not.
	 * NinePatches are very useful for drawing buttons and other variable sized widgets.
	 * @param bmp The image to draw.
	 * @param position Where to draw the image's top left pixel.
	 * @param scale The size that the image will be intelligently stretched to.
	 * @param opacity How opaque the image will be drawn.
     */
		virtual void drawNinePatchImage(const Image *bmp,
			const Point &position,const Dimension &scale,
			float opacity = 1.0f);
	/**
	 * Draws a UTF8 encoded string.
	 *
	 * @param position Where to text's top left pixel will be.
	 * It may also be the center or end of the text depending on the alignment.
	 * @param text The UTF8 encoded string to draw.
	 * @param color The color of the text that will be drawn.
	 * @param font The font used to draw the text.
	 * @param align The alignment of the text.
     */
		virtual void drawText(const Point &position,const char* text,
			const Color &color, const Font *font,
			AlignmentEnum align = ALIGN_LEFT) = 0;
	/**
	 * Draws the outline of a rectangle with a width of 1 pixel.
     */
		virtual void drawRectangle(const Rectangle &rect,
			const Color &color) = 0;
	/**
	 * Draws a filled rectangle.
     */
		virtual void drawFilledRectangle(const Rectangle &rect,
			const Color &color) = 0;
	/**
	 * Draws the outline of a circle with a width of 1 pixel.
	 *
	 * The position is the center of the circle.
     */
		virtual void drawCircle(const Point &center,
			float radius, const Color &color) = 0;
	/**
	 * Draws a filled circle.
	 *
	 * The position is the center of the circle.
     */
		virtual void drawFilledCircle(const Point &center,
			float radius,const Color &color) = 0;
	/**
	 * Draws a single pixel.
     */
		virtual void drawPixel(const Point &point,
			const Color &color) = 0;
	/**
	 * Draws a line.
     */
		virtual void drawLine(const Point &start,
			const Point &end, const Color &color) = 0;
	/**
	 * Sets the image that the drawing operations will draw into.
	 *
	 * By default this is the back buffer.
     */
		virtual void setTargetImage(const Image *target) = 0;
	/**
	 * Sets the image that the drawing operations will draw into to the default backbuffer.
     */
		virtual void resetTargetImage() = 0;

		void setGlobalOpacity(float o);
		float getGlobalOpacity() const;

	};
}

#endif