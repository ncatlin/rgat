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

#include "Agui/FocusManager.hpp"
#include "Agui/Widget.hpp"
namespace agui
{

FocusManager::FocusManager(void)
: focusedWidget(NULL), modalWidget(NULL)
{
}

FocusManager::~FocusManager(void)
{
}

bool FocusManager::widgetIsModalChild( Widget* widget )
{
		if(!modalWidget)
		{
			return false;
		}

		if(widget == modalWidget)
		{
			return true;
		}
		Widget* currentParent = widget;
		if(widget)
		{
			while (currentParent)
			{
				if(currentParent == modalWidget)
				{
					return true;
				}
				if(!currentParent->getParent())
				{
					return false;
				}
				currentParent = currentParent->getParent();
			}

		}
		return false;
	}

	void FocusManager::setFocusedWidget( Widget* widget )
	{
		//changes the focused widget

		if(focusedWidget)
			if(focusedWidget != widget)
				focusedWidget->focusLost();

		focusedWidget = widget;

		if(widget)
			if(widget->isFocusable() && widget->isVisible() 
				&& widget->isEnabled())
				widget->focusGained();
	}

	bool FocusManager::requestModalFocus( Widget* widget )
	{
		if(modalWidget == NULL && widget)
		{
			if(focusedWidget != widget)
			{
				widget->focus();
			}
			modalWidget = widget;
			widget->modalFocusGained();
			return true;
		}
		return false;
	}

	bool FocusManager::releaseModalFocus( Widget* widget )
	{
		if(widgetIsModalChild(widget))
		{
			modalWidget->modalFocusLost();
			modalWidget = NULL;
			return true;
		}
		else
		{
			return false;
		}
	}

	Widget* FocusManager::getFocusedWidget() const
	{
		return focusedWidget;
	}

	Widget* FocusManager::getModalWidget() const
	{
		return modalWidget;
	}

}

