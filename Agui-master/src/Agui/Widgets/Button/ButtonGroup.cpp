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

#include "Agui/Widgets/Button/ButtonGroup.hpp"
namespace agui {
	ButtonGroup::ButtonGroup(void)
	{
		selectedRButton = NULL;
	}

	ButtonGroup::ButtonGroup( const std::string &id )
	{
		selectedRButton = NULL;
		groupId = id;
	}

	ButtonGroup::~ButtonGroup(void)
	{
		for(std::vector<Button*>::iterator	it = buttons.begin();
			it != buttons.end(); ++it)
		{
			(*it)->removeButtonListener(this);
		}
	}

	const std::string& ButtonGroup::getGroupId() const
	{
		return groupId;
	}

	void ButtonGroup::add( Button* button )
	{
		if(!button)
		{
			return;
		}
		for(std::vector<Button*>::iterator	it = buttons.begin();
			it != buttons.end(); ++it)
		{
			if((*it) == button)
			{
				return;
			}
		}

		buttons.push_back(button);
		button->addButtonListener(this);
		button->setToggleButton(true);
		button->setAutoUntoggle(false);
		button->setToggleState(false);

	}

	void ButtonGroup::remove( Button* button )
	{
		button->removeButtonListener(this);

		buttons.erase(
			std::remove(buttons.begin(),
			buttons.end(), button),
			buttons.end());
	}

	void ButtonGroup::addActionListener( ActionListener *listener)
	{
		if(!listener)
		{
			return;
		}
		for(std::vector<ActionListener*>::iterator it = 
			actionListeners.begin();
			it != actionListeners.end(); ++it)
		{
			if((*it) == listener)
				return;
		}

		actionListeners.push_back(listener);
	}

	void ButtonGroup::removeActionListener( ActionListener *listener )
	{
		actionListeners.erase(
			std::remove(actionListeners.begin(),
			actionListeners.end(), listener),
			actionListeners.end());
	}

	void ButtonGroup::dispatchActionEvent( const ActionEvent &evt )
	{
		for(std::vector<ActionListener*>::iterator it = actionListeners.begin();
			it != actionListeners.end(); ++it)
		{
			(*it)->actionPerformed(evt);
		}
	}

	Button* ButtonGroup::getSelected() const
	{
		return selectedRButton;
	}

	void ButtonGroup::death( Button* source )
	{
		buttons.erase(
			std::remove(buttons.begin(),
			buttons.end(), source),
			buttons.end());
	}

	void ButtonGroup::toggleStateChanged( Button *source, bool state )
	{
		//it is the checked button, no change
		if(source == selectedRButton && state)
		{
			return;
		}

		//this could happen with multiple groups for 1 Button
		if(source == selectedRButton && !state)
		{
			setSelected(NULL);
		}
		else if(source != selectedRButton && state)
		{
			if(selectedRButton)
			{
				selectedRButton->setToggleState(false);
			}

			setSelected(source);
		}
	}

	void ButtonGroup::setSelected( Button* button )
	{
		if( button != selectedRButton)
		{
			if(button)
			{
				dispatchActionEvent(ActionEvent(button,groupId));
			}
			selectedRButton = button;
		}
	}

}
