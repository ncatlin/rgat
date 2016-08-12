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

#ifndef AGUI_IMAGE_HPP
#define AGUI_IMAGE_HPP
#include "Agui/Platform.hpp"
#include "Agui/Color.hpp"
#include "Agui/Point.hpp"
#include "Agui/Enumerations.hpp"
namespace agui
{

	class AGUI_CORE_DECLSPEC ImageLoader;
		/**
     * Abstract class for Images.
	 *
	 * Must implement:
	 *
	 * getPixel
	 *
	 * setPixel
	 *
	 * getWidth
	 *
	 * getHeight
	 *
	 * isAutoFreeing
	 *
	 * free
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC Image {
		Point leftTop;
		Point rightBottom;
		static ImageLoader* loader;

	public:
	/**
	 * Sets the margins for a NinePatch image. The rectangle formed by the parameters
	 * determines the area that will not be stretched. The center rectangle that remains will be stretched.
	 @see drawNinePatchImage
     * @since 0.1.0
     */
		void setMargins(int top, int left, int bottom, int right);
	/**
	 * Sets the margins for a NinePatch image. The rectangle formed by the parameters
	 * determines the area that will not be stretched. The center rectangle that remains will be stretched.
	 @see drawNinePatchImage
     * @since 0.1.0
     */
		void setMargins(int top, int left);
	/**
	 * @return The top left margin point.
     * @since 0.1.0
     */
		const Point& getLeftTopMargin() const;
	/**
	 * @return The bottom right margin point.
     * @since 0.1.0
     */
		const Point& getRightBottomMargin() const;
	/**
	 * @return The margin of the parameter side.
     * @since 0.1.0
     */
		int getMargin(SideEnum side) const;
	/**
	 * Sets the loader which will load a back end specific Image.
     * @since 0.1.0
     */
		static void setImageLoader(ImageLoader* manager);
	/**
	 * @return The width of the image in pixels.
     * @since 0.1.0
     */
		virtual int getWidth() const = 0;
	/**
	 * @return The height of the image in pixels.
     * @since 0.1.0
     */
		virtual int getHeight() const = 0;
	/**
	 * @return The Color of the pixel at x , y. (May be very slow).
     * @since 0.1.0
     */
		virtual Color getPixel(int x, int y) const = 0;
	/**
	 * Sets the pixel at x , y to the parameter color. (May be very slow).
     * @since 0.1.0
     */
		virtual void  setPixel(int x, int y, const Color& color) = 0;
	/**
	 * Determines if the Image will destroy the back end specific image when
	 * the image is changed or deleted.
     * @since 0.1.0
     */
		virtual bool isAutoFreeing() const = 0;
	/**
	 * Frees the back end specific image.
     * @since 0.1.0
     */
		virtual void free() = 0;
	/**
	 * @return A back end specific Image or NULL.
	 * @param fileName The path to the image.
	 * @param convertMask Determines if the color (255, 0, 255) should be converted to (0,0,0,0).
	 * @param convertToDisplayFormat Determines if the image should be converted to display format. 
	 * Not applicable in most situations.
     * @since 0.1.0
     */
		static Image* load(const std::string& fileName, bool convertMask = false,
			bool convertToDisplayFormat = false);
	/**
	 * Default constructor.
     * @since 0.1.0
     */
		Image();
	/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~Image();
	};

}
#endif
