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

#include "Agui/Widgets/RadioButton/RadioButtonGroup.hpp"
namespace agui {
	RadioButtonGroup::RadioButtonGroup(void)
	{
		selectedRButton = NULL;
	}

	RadioButtonGroup::RadioButtonGroup( const std::string &id )
	{
		selectedRButton = NULL;
		groupId = id;
	}

	RadioButtonGroup::~RadioButtonGroup(void)
	{
		for(std::vector<RadioButton*>::iterator	it = radioButtons.begin();
			it != radioButtons.end(); ++it)
		{
			(*it)->removeRadioButtonListener(this);
		}
	}

	const std::string& RadioButtonGroup::getGroupId() const
	{
		return groupId;
	}

	void RadioButtonGroup::add( RadioButton* radioButton )
	{
		if(!radioButton)
		{
			return;
		}
		for(std::vector<RadioButton*>::iterator	it = radioButtons.begin();
			it != radioButtons.end(); ++it)
		{
			if((*it) == radioButton)
			{
				return;
			}
		}

		radioButtons.push_back(radioButton);
		radioButton->addRadioButtonListener(this);
		radioButton->setChecked(false);

	}

	void RadioButtonGroup::remove( RadioButton* radioButton )
	{
		radioButton->removeRadioButtonListener(this);

		radioButtons.erase(
			std::remove(radioButtons.begin(),
			radioButtons.end(), radioButton),
			radioButtons.end());
	}

	void RadioButtonGroup::checkedStateChanged( RadioButton* source,
												   RadioButton::RadioButtonCheckedEnum state )
	{
		//it is the checked button, no change
		if(source == selectedRButton && state ==
			RadioButton::CHECKED)
		{
			return;
		}

		//this could happen with multiple groups for 1 RadioButton
		if(source == selectedRButton && state == 
			RadioButton::UNCHECKED)
		{
			selectedRButton = NULL;
		}
		else if(source != selectedRButton && state == 
			RadioButton::CHECKED)
		{
			if(selectedRButton)
			{
				selectedRButton->setChecked(false);
			}
			
			selectedRButton = source;
		}
		
	}

	RadioButton* RadioButtonGroup::getSelected() const
	{
		return selectedRButton;
	}

	void RadioButtonGroup::death( RadioButton* source )
	{
		radioButtons.erase(
			std::remove(radioButtons.begin(),
			radioButtons.end(), source),
			radioButtons.end());
	}

}
