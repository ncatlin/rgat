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

#ifndef AGUI_TEXTBOX_LISTENER_HPP
#define AGUI_TEXTBOX_LISTENER_HPP
#include "Agui/Platform.hpp"
#include <stdlib.h>
#include <string>
namespace agui
{
	class AGUI_CORE_DECLSPEC Widget;
	class AGUI_CORE_DECLSPEC TextBox;
	class AGUI_CORE_DECLSPEC TextBoxListener
	{
	public:
		virtual void death(TextBox* source) { (void)(source); }
		virtual void maxLengthChanged(TextBox* source, int maxLength) { (void)(source); (void)(maxLength); }
		virtual void hidingSelectionChanged(TextBox* source, bool hiding) { (void)(source); (void)(hiding); }
		virtual void standardArrowKeyRulesChanged(TextBox* source, bool usingStandard) { (void)(source);(void)(usingStandard); }
		virtual void splittingWordsChanged(TextBox* source, bool splittingWords) { (void)(source); (void)(splittingWords); }
		virtual void textAppended(TextBox* source, const std::string &appendedText) { (void)(source); (void)(appendedText); }
		virtual void selectionChanged(TextBox* source,int startIndex, int endIndex) { (void)(source); (void)(startIndex); (void)(endIndex); }
		virtual void selectionDeleted(TextBox* source) { (void)(source); }
		virtual void maxCharacterSkippedChanged(TextBox* source, int maxSkip) { (void)(source); maxSkip++; }
		virtual void readOnlyChanged(TextBox* source, bool readOnly) { (void)(source); (void)(readOnly); }
		virtual void wordWrappedChanged(TextBox* source, bool wordWrapped) { (void)(source); (void)(wordWrapped);}
		TextBoxListener(void);
		virtual ~TextBoxListener(void);
	};
}
#endif
