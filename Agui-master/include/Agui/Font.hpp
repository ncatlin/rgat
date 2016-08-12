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

#ifndef AGUI_FONT_HPP
#define AGUI_FONT_HPP
#include "Agui/Platform.hpp"
#include "Agui/UTF8.hpp"
#include "Agui/Color.hpp"
#include "Agui/BaseTypes.hpp"
namespace agui
{

	class AGUI_CORE_DECLSPEC FontLoader;

	/**
     * Abstract base class for all Fonts in Agui.
	 *
	 * Certain classes such as the ExtendedTextBox cause Agui not to be with Kerning.
	 * Please disable Kerning for optimal results.
	 *
	 * Must implement:
	 *
	 * free
	 *
	 * getLineHeight
	 *
	 * getHeight
     *
	 * getTextWidth
	 *
	 * getPath
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC Font
	{
		static FontLoader* loader;
	public:
	/**
	 * Should free the underlying font.
     * @since 0.1.0
     */
		virtual void free() = 0;
	/**
	 * @return The font's line height which is usually the height of the highest glyph.
     * @since 0.1.0
     */
		virtual int getLineHeight() const = 0;
	/**
	 * @return The glyph that parameter 'x' is inside of.
	 *
	 * If 'x' is before half of the glyph it returns the index of the previous glyph.
	 *
	 * Otherwise if 'x' is past half of the glyph it returns the index of the glyph.
	 * @param str The UTF8 string to verify.
	 * @param x The relative x-axis line.
     * @since 0.1.0
     */
		int getStringIndexFromPosition(const std::string &str, int x) const;
	/**
	 * @return The height specified by the user. This is usually in pixels. It may not be the line height.
     * @since 0.1.0
     */
		virtual int getHeight() const = 0;
	/**
	 * @return The width of the parameter UTF-8 string.
     * @since 0.1.0
     */
		virtual int getTextWidth(const std::string &text) const = 0;
	/**
	 * Sets the font loader for the back end. This will influence the load method.
     * @since 0.1.0
     */
		static void setFontLoader(FontLoader* manager);
	/**
	 * @return A pointer to the back end specific font or NULL if failed and no exception was thrown.
	 * @param fileName The path of the font. Must be compatible with the back end loader.
	 * @param height The height of the font in pixels.
     * @since 0.1.0
     */
		static Font* load(const std::string &fileName, int height, FontFlags fontFlags = FONT_DEFAULT_FLAGS, float borderWidth = 0, agui::Color borderColor = agui::Color());
    static Font* loadEmpty();
    virtual void reload(const std::string &fileName, int height, FontFlags fontFlags = FONT_DEFAULT_FLAGS, float borderWidth = 0, agui::Color borderColor = agui::Color()) = 0;
	/**
	 * @return The path of the font.
     * @since 0.1.0
     */
		virtual const std::string& getPath() const = 0;
	/**
	 * Default constructor.
     * @since 0.1.0
     */
		Font();
	/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~Font();

	};
}

#endif
