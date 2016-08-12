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

#ifndef AGUI_CURSOR_PROVIDER
#define AGUI_CURSOR_PROVIDER
#include "Agui/Platform.hpp"
namespace agui
{
	 /**
     * Interface for changing the cursor.
	 *
	 * Must be implemented by a back end.
     * @author Joshua Larouche
     * @since 0.2.0
     */
	class AGUI_CORE_DECLSPEC CursorProvider {
	public:
		enum CursorEnum
		{
			DEFAULT_CURSOR,
			ARROW_CURSOR,
			BUSY_CURSOR,
			QUESTION_CURSOR,
			EDIT_CURSOR,
			MOVE_CURSOR,
			RESIZE_N_CURSOR,
			RESIZE_W_CURSOR,
			RESIZE_S_CURSOR,
			RESIZE_E_CURSOR,
			RESIZE_NW_CURSOR,
			RESIZE_SW_CURSOR,
			RESIZE_SE_CURSOR,
			RESIZE_NE_CURSOR,
			LINK_CURSOR,
		};

	/**
     * Attempts to set the cursor to the requested cursor. 
	 * @return True if the cursor was changed.
     * @since 0.2.0
     */
	virtual bool setCursor(CursorEnum cursor) = 0;
	/**
     * Default constructor.
     * @since 0.2.0
     */
	CursorProvider() {}

	/**
     * Default destructor.
     * @since 0.2.0
     */
	virtual ~CursorProvider() {}
	};
}

#endif
