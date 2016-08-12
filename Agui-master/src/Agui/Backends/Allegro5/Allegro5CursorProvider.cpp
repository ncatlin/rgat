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

#include "Agui/Backends/Allegro5/Allegro5CursorProvider.hpp"

namespace agui
{

	bool Allegro5CursorProvider::setCursor( CursorEnum cursor )
	{
		ALLEGRO_SYSTEM_MOUSE_CURSOR alCursor = ALLEGRO_SYSTEM_MOUSE_CURSOR_DEFAULT;
		switch(cursor)
		{
		case DEFAULT_CURSOR:
			alCursor = ALLEGRO_SYSTEM_MOUSE_CURSOR_DEFAULT;
			break;
		case ARROW_CURSOR:
			alCursor = ALLEGRO_SYSTEM_MOUSE_CURSOR_ARROW;
			break;
		case BUSY_CURSOR:
			alCursor = ALLEGRO_SYSTEM_MOUSE_CURSOR_BUSY;
			break;
		case  QUESTION_CURSOR:
			alCursor = ALLEGRO_SYSTEM_MOUSE_CURSOR_QUESTION;
			break;
		case EDIT_CURSOR:
			alCursor = ALLEGRO_SYSTEM_MOUSE_CURSOR_EDIT;
			break;
		case MOVE_CURSOR:
			alCursor = ALLEGRO_SYSTEM_MOUSE_CURSOR_MOVE;
			break;
		case RESIZE_N_CURSOR:
			alCursor = ALLEGRO_SYSTEM_MOUSE_CURSOR_RESIZE_N;
			break;
		case RESIZE_W_CURSOR:
			alCursor = ALLEGRO_SYSTEM_MOUSE_CURSOR_RESIZE_W;
			break;
		case RESIZE_S_CURSOR:
			alCursor = ALLEGRO_SYSTEM_MOUSE_CURSOR_RESIZE_S;
			break;
		case RESIZE_E_CURSOR:
			alCursor = ALLEGRO_SYSTEM_MOUSE_CURSOR_RESIZE_E;
			break;
		case RESIZE_NW_CURSOR:
			alCursor = ALLEGRO_SYSTEM_MOUSE_CURSOR_RESIZE_NW;
			break;
		case RESIZE_SW_CURSOR:
			alCursor = ALLEGRO_SYSTEM_MOUSE_CURSOR_RESIZE_SW;
			break;
		case RESIZE_SE_CURSOR:
			alCursor = ALLEGRO_SYSTEM_MOUSE_CURSOR_RESIZE_SE;
			break;
		case RESIZE_NE_CURSOR:
			alCursor = ALLEGRO_SYSTEM_MOUSE_CURSOR_RESIZE_NE;
			break;
		case LINK_CURSOR:
			alCursor = ALLEGRO_SYSTEM_MOUSE_CURSOR_LINK;
			break;
		}

		return al_set_system_mouse_cursor(al_get_current_display(),alCursor);
	}

}