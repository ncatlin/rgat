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

#ifndef AGUI_BUTTON_GROUP_HPP
#define AGUI_BUTTON_GROUP_HPP

#include "Agui/Widgets/Button/ButtonListener.hpp"
#include "Agui/Widgets/Button/Button.hpp"
#include "Agui/ActionListener.hpp"


namespace agui {
	/**
     * Class to group Buttons. Will manage them and ensure only 1 is selected.
	 *
	 * A Button can be part of multiple groups.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC ButtonGroup : public ButtonListener
	{
		std::string groupId;
		std::vector<Button*> buttons;
		std::vector<ActionListener*> actionListeners;
		Button* selectedRButton;

		void setSelected(Button* button);
	protected:
	/**
     * Used internally to dispatch an action event.
     * @since 0.1.0
     */
	void dispatchActionEvent( const ActionEvent &evt );
	/**
     * Manages which Button will be selected when one of them is clicked.
     * @since 0.1.0
     */
	virtual void toggleStateChanged(Button *source, bool state);
	protected:
	/**
     * Removes the Button from itself when the Button dies.
     * @since 0.1.0
     */
		virtual void death(Button* source);
	public:
	/**
     * Default constructor.
     * @since 0.1.0
     */
		ButtonGroup(void);
	/**
     * Constructs with a group id string.
     * @since 0.1.0
     */
		ButtonGroup(const std::string &id);
	/**
     * @return The group id string.
     * @since 0.1.0
     */
		const std::string& getGroupId() const;
	/**
     * Adds the parameter Button to the group.
     * @since 0.1.0
     */
		void add(Button* button);
	/**
     * Removes the parameter Button to the group.
     * @since 0.1.0
     */
		void remove(Button* button);
	/**
     * @return The selected Button.
     * @since 0.1.0
     */
		Button* getSelected() const;

	/**
     * Add an action listener. When the selected button changes, 
	 * will send an action event with the selected button and group id as string.
     * @since 0.1.0
     */
		void addActionListener( ActionListener *listener);

		/**
     * Remove an action listener.
     * @since 0.1.0
     */
		void removeActionListener( ActionListener *listener);


	/**
     * Default destructor.
     * @since 0.1.0
     */
		virtual ~ButtonGroup(void);
	};
}
#endif
