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

#ifndef AGUI_ENUMERATIONS_HPP
#define AGUI_ENUMERATIONS_HPP
namespace agui
{

	enum OrientationEnum
	{
		HORIZONTAL,
		VERTICAL
	};
	enum ScrollPolicy {
		SHOW_NEVER,
		SHOW_ALWAYS,
		SHOW_AUTO
	};

	enum MouseButtonEnum {
		MOUSE_BUTTON_NONE,
		MOUSE_BUTTON_LEFT,
		MOUSE_BUTTON_RIGHT,
		MOUSE_BUTTON_MIDDLE
	};

	enum AlignmentEnum {
		ALIGN_LEFT,
		ALIGN_CENTER,
		ALIGN_RIGHT
	};

	enum AreaAlignmentEnum {
		ALIGN_TOP_LEFT,
		ALIGN_MIDDLE_LEFT,
		ALIGN_BOTTOM_LEFT,
		ALIGN_TOP_CENTER,
		ALIGN_MIDDLE_CENTER,
		ALIGN_BOTTOM_CENTER,
		ALIGN_TOP_RIGHT,
		ALIGN_MIDDLE_RIGHT,
		ALIGN_BOTTOM_RIGHT,
		ALIGN_NONE
	};

	enum SideEnum {
		SIDE_TOP,
		SIDE_LEFT,
		SIDE_BOTTOM,
		SIDE_RIGHT
	};

	enum ExtendedKeyEnum {
		EXT_KEY_NONE = 0,
		EXT_KEY_ALT,
		EXT_KEY_RIGHT_SHIFT,
		EXT_KEY_LEFT_SHIFT,
		EXT_KEY_RIGHT_CONTROL,
		EXT_KEY_LEFT_CONTROL,
		EXT_KEY_LEFT_META,
		EXT_KEY_RIGHT_META,
		EXT_KEY_HOME,
		EXT_KEY_INSERT,
		EXT_KEY_PAGE_UP,
		EXT_KEY_PAGE_DOWN,
		EXT_KEY_END,
		EXT_KEY_CAPS_LOCK,
		EXT_KEY_F1,
		EXT_KEY_F2,
		EXT_KEY_F3,
		EXT_KEY_F4,
		EXT_KEY_F5,
		EXT_KEY_F6,
		EXT_KEY_F7,
		EXT_KEY_F8,
		EXT_KEY_F9,
		EXT_KEY_F10,
		EXT_KEY_F11,
		EXT_KEY_F12,
		EXT_KEY_PRINT_SCREEN,
		EXT_KEY_SCROLL_LOCK,
		EXT_KEY_PAUSE,
		EXT_KEY_NUM_LOCK,
		EXT_KEY_ALTGR,
		EXT_KEY_UP,
		EXT_KEY_DOWN,
		EXT_KEY_LEFT,
		EXT_KEY_RIGHT
	};

	enum KeyEnum {
		KEY_NONE = 0,
		KEY_BACKSPACE = 8,
		KEY_TAB = 9,
		KEY_NEWLINE = 10,
		KEY_ENTER = 13,
		KEY_ESCAPE = 27,
		KEY_SPACE = 32,
		KEY_EXCLAMATION_MARK = 33,
		KEY_DOUBLE_QUOTATION = 34,
		KEY_POUND = 35,
		KEY_DOLLAR = 36,
		KEY_PERCENT = 37,
		KEY_AMPERSAND = 38,
		KEY_SINGLE_QUOTATION = 39,
		KEY_OPEN_PARENTHESIS = 40,
		KEY_CLOSE_PARENTHESIS = 41,
		KEY_ASTERISK = 42,
		KEY_PLUS = 43,
		KEY_COMMA = 44,
		KEY_HYPHEN = 45,
		KEY_PERIOD = 46,
		KEY_FORWARDSLASH = 47,
		KEY_0 = 48,
		KEY_1 = 49,
		KEY_2 = 50,
		KEY_3 = 51,
		KEY_4 = 52,
		KEY_5 = 53,
		KEY_6 = 54,
		KEY_7 = 55,
		KEY_8 = 56,
		KEY_9 = 57,
		KEY_COLON = 58,
		KEY_SEMI_COLON = 59,
		KEY_LESS_THAN = 60,
		KEY_EQUALS = 61,
		KEY_GREATER_THAN = 62,
		KEY_QUESTION_MARK = 63,
		KEY_AT = 64,
		KEY_A = 65,
		KEY_B = 66,
		KEY_C = 67,
		KEY_D = 68,
		KEY_E = 69,
		KEY_F = 70,
		KEY_G = 71,
		KEY_H = 72,
		KEY_I = 73,
		KEY_J = 74,
		KEY_K = 75,
		KEY_L = 76,
		KEY_M = 77,
		KEY_N = 78,
		KEY_O = 79,
		KEY_P = 80,
		KEY_Q = 81,
		KEY_R = 82,
		KEY_S = 83,
		KEY_T = 84,
		KEY_U = 85,
		KEY_V = 86,
		KEY_W = 87,
		KEY_X = 88,
		KEY_Y = 89,
		KEY_Z = 90,
		KEY_OPEN_SQUARE_BRACKET = 91,
		KEY_BACKSLASH = 92,
		KEY_CLOSE_SQUARE_BRACKET = 93,
		KEY_CARET = 94,
		KEY_UNDERSCORE = 95,
		KEY_ACUTE_ACCENT = 96,
		KEY_OPEN_BRACE = 123,
		KEY_BAR = 124,
		KEY_CLOSING_BRACE = 125,
		KEY_TIDLE = 126,
		KEY_DELETE = 127
	};

	enum FontFlags
	{
		FONT_DEFAULT_FLAGS = 0,
		FONT_NO_KERNING = 1,
		FONT_NO_ANTIALIASING = 2,
		FONT_NO_HINTING = 4
	};
}
#endif