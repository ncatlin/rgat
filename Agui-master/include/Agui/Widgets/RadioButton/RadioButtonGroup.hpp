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

#ifndef AGUI_RADIO_BUTTON_GROUP_HPP
#define AGUI_RADIO_BUTTON_GROUP_HPP

#include "Agui/Widgets/RadioButton/RadioButtonListener.hpp"
#include "Agui/Widgets/RadioButton/RadioButton.hpp"

namespace agui {
	/**
     * Class to group RadioButtons. Will manage them and ensure only 1 is selected.
	 *
	 * A RadioButton can be part of multiple groups.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC RadioButtonGroup : public RadioButtonListener
	{
		std::string groupId;
		std::vector<RadioButton*> radioButtons;
		RadioButton* selectedRButton;
	protected:
	/**
     * Manages which RadioButton will be selected when one of them is clicked.
     * @since 0.1.0
     */
	virtual void checkedStateChanged(RadioButton* source, 
									 RadioButton::RadioButtonCheckedEnum state);
	protected:
	/**
     * Removes the RadioButton from itself when the RadioButton dies.
     * @since 0.1.0
     */
		virtual void death(RadioButton* source);
	public:
	/**
     * Default constructor.
     * @since 0.1.0
     */
		RadioButtonGroup(void);
	/**
     * Constructs with a group id string.
     * @since 0.1.0
     */
		RadioButtonGroup(const std::string &id);
	/**
     * @return The group id string.
     * @since 0.1.0
     */
		const std::string& getGroupId() const;
	/**
     * Adds the parameter RadioButton to the group.
     * @since 0.1.0
     */
		void add(RadioButton* radioButton);
	/**
     * Removes the parameter RadioButton to the group.
     * @since 0.1.0
     */
		void remove(RadioButton* radioButton);
	/**
     * @return The selected RadioButton.
     * @since 0.1.0
     */
		RadioButton* getSelected() const;
	/**
     * Default destructor.
     * @since 0.1.0
     */
		virtual ~RadioButtonGroup(void);
	};
}
#endif
