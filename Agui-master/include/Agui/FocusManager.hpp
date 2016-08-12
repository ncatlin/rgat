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

#ifndef AGUI_FOCUS_MANAGER
#define AGUI_FOCUS_MANAGER
#include "Agui/Platform.hpp"

namespace agui
{
	class AGUI_CORE_DECLSPEC Widget;
	/**
     * Class used to manage focus in a Gui.
	 *
	 * Keeps track of focus and modal focus widget.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC FocusManager
	{
		Widget* focusedWidget;
		Widget* modalWidget;
	/**
	 * @return True if the parameter widget is a public or private child of the modal widget.
     * @since 0.1.0
     */
		bool widgetIsModalChild(Widget* widget);
	public:
		/**
	 * Default constructor.
     * @since 0.1.0
     */
		FocusManager(void);
	/**
	 * Gives this widget input focus.
     * @since 0.1.0
     */
		void setFocusedWidget(Widget* widget);
	/**
	 * @return True if the parameter widget gained the modal focus.
     * @since 0.1.0
     */
		bool requestModalFocus(Widget* widget);
	/**
	 * Only the modal widget or one of its children can release the modal focus.
	 * @return True if the parameter widget released the modal focus.
     * @since 0.1.0
     */
		bool releaseModalFocus(Widget* widget);
	/**
	 * @return The focused widget or NULL if no widget is focused.
     * @since 0.1.0
     */
		Widget* getFocusedWidget() const;
	/**
	 * @return The modal focused widget or NULL if no widget is modal focused.
     * @since 0.1.0
     */
		Widget* getModalWidget() const;
		virtual ~FocusManager(void);
	};
}
#endif
