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

#ifndef AGUI_TABBED_PANE_LISTENER_HPP
#define  AGUI_TABBED_PANE_LISTENER_HPP

#include "Agui/Platform.hpp"

namespace agui {
	class AGUI_CORE_DECLSPEC Widget;
	class AGUI_CORE_DECLSPEC TabbedPane;
	class AGUI_CORE_DECLSPEC Tab;
		/**
     * Abstract class for TabbedPane Listeners.
	 *
	 * Any derived TabbedPane Listeners should inherit from this class.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC TabbedPaneListener
	{
	public:
		TabbedPaneListener(void);
		virtual void selectedTabChanged(TabbedPane* source, Tab *tab) { (void)(source); (void)(tab); }
		virtual void resizingTabContentChanged(TabbedPane* source, bool resizing) { (void)(source); (void)(resizing); }
		virtual void tabAdded(TabbedPane* source, Tab *tab, Widget* tabContent) { (void)(source); (void)(tab); (void)(tabContent); }
		virtual void tabRemoved(TabbedPane* source, Tab* tab) { (void)(source); (void)(tab); }
		virtual void death(TabbedPane* source) { (void)(source); }
		

		virtual ~TabbedPaneListener(void);
	};
}
#endif
