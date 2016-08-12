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

#ifndef AGUI_DROPDOWN_LISTENER_HPP
#define AGUI_DROPDOWN_LISTENER_HPP
#include "Agui/Platform.hpp"
#include <stdio.h>
#include <string>
namespace agui
{
	class AGUI_CORE_DECLSPEC Widget;
	class AGUI_CORE_DECLSPEC DropDown;
	/**
     * Abstract class for DropDown Listeners.
	 *
	 * Any derived DropDown Listeners should inherit from this class.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC DropDownListener
	{
	public:
		virtual void death(DropDown* source) { (void)(source); }
		virtual void dropDownShown(DropDown* source) { (void)(source); }
		virtual void dropDownHidden(DropDown* source) { (void)(source); }
		virtual void resizeToWidestItemChanged(DropDown* source, bool resize) { (void)(source); (void)(resize); }
		virtual void maxDropDownHeightChanged(DropDown* source, int height) { (void)(source);  (void)(height); }
		virtual void itemAdded(DropDown* source, const std::string& item) { (void)(source);  (void)(item); }
		virtual void itemRemoved(DropDown* source, const std::string& item) { (void)(source);  (void)(item); }
		DropDownListener(void);
		virtual ~DropDownListener(void);
	};
}
#endif