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

#ifndef AGUI_LISTBOX_LISTENER_HPP
#define AGUI_LISTBOX_LISTENER_HPP
#include "Agui/Platform.hpp"
#include <stdlib.h>
#include <string>
namespace agui {
	class AGUI_CORE_DECLSPEC ListBox;
		/**
     * Abstract class for ListBox Listeners.
	 *
	 * Any derived ListBox Listeners should inherit from this class.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC ListBoxListener
	{
	protected:
		virtual ~ListBoxListener(void);
	public:
		ListBoxListener(void);
		virtual void itemAdded(ListBox*, const std::string&) {}
		virtual void itemRemoved(ListBox*, const std::string&) {}
		virtual void sortedChanged(ListBox* source, bool sorted)
		{(void)source; (void)sorted;}
		virtual void rSortedChanged(ListBox* source, bool rSorted)
		{(void)source; (void)rSorted;}
		virtual void hoverIndexChanged(ListBox* source, int index)
		{(void)source; (void)index;}
		virtual void multiselectChanged(ListBox* source, bool multiselect)
		{(void)source; (void)multiselect;}
		virtual void multiselectExtendedChanged(ListBox* source, bool multiselect)
		{(void)source; (void)multiselect;}
		void wrappingChanged(ListBox* source, bool wrapping)
		{(void)source; (void)wrapping;}
		virtual void itemHeightChanged(ListBox* source, int height)
		{(void)source; (void)height;}
		virtual void mouseWheelSelectionChanged(ListBox* source, bool mWSelection)
		{(void)source; (void)mWSelection;}
		virtual void death(ListBox* source)
		{(void)source;}

	};

}

#endif
