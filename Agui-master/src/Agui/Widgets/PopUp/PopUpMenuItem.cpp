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

#include "Agui/Widgets/PopUp/PopUpMenuItem.hpp"
#include "Agui/Widgets/PopUp/PopUpMenu.hpp"

namespace agui {


	void PopUpMenuItem::setItemType( MenuItemTypeEnum itemType )
	{
		this->itemType = itemType;
	}

	PopUpMenuItem::MenuItemTypeEnum PopUpMenuItem::getItemType() const
	{
		return itemType;
	}

	PopUpMenuItem::PopUpMenuItem()
		: itemType(ITEM), icon(NULL),
		subMenu(NULL),parentMenu(NULL)
	{
	}

	PopUpMenuItem::PopUpMenuItem( const std::string& text, Image* image /*= NULL*/ )
		: itemType(ITEM), icon(image),
		subMenu(NULL),parentMenu(NULL)
	{
		setText(text);
	}

	PopUpMenuItem::PopUpMenuItem( const std::string& text, const std::string& shortcutText, Image* image /*= NULL*/ )
		: itemType(ITEM), icon(image),
		subMenu(NULL),parentMenu(NULL)
	{
		setText(text);
		setShortcutText(shortcutText);
	}

	PopUpMenuItem::PopUpMenuItem( MenuItemTypeEnum type )
		: itemType(type), icon(NULL),
		subMenu(NULL),parentMenu(NULL)
	{
	}

	PopUpMenuItem::PopUpMenuItem( PopUpMenu* menu )
		: itemType(SUB_MENU), icon(NULL),
		subMenu(menu),parentMenu(NULL)
	{
	}

	PopUpMenuItem::PopUpMenuItem( PopUpMenu* menu,const std::string&text )
		: itemType(SUB_MENU), icon(NULL),
		subMenu(menu),parentMenu(NULL)
	{
		setText(text);
	}

	Image* PopUpMenuItem::getIcon() const
	{
		return icon;
	}

	void PopUpMenuItem::setIcon( Image* image )
	{
		icon = image;
	}

	void PopUpMenuItem::setShortcutText( const std::string& text )
	{
		shortcutText = text;
	}

	const std::string& PopUpMenuItem::getShortcutText() const
	{
		return shortcutText;
	}

	void PopUpMenuItem::setSubMenu( PopUpMenu* menu )
	{
		subMenu = menu;
	}

	PopUpMenu* PopUpMenuItem::getSubMenu() const
	{
		return subMenu;
	}

	void PopUpMenuItem::paintBackground( const PaintEvent &paintEvent )
	{

	}

	void PopUpMenuItem::paintComponent( const PaintEvent &paintEvent )
	{

	}

	bool PopUpMenuItem::isSeparator() const
	{
		return getItemType() == SEPARATOR;
	}

	bool PopUpMenuItem::isSubMenu() const
	{
		return getItemType() == SUB_MENU;
	}

	PopUpMenu* PopUpMenuItem::getParentMenu() const
	{
		return parentMenu;
	}

	void PopUpMenuItem::setParentMenu( PopUpMenu* menu )
	{
		parentMenu = menu;
	}

	PopUpMenuItem::~PopUpMenuItem()
	{
		if(parentMenu)
		{
			parentMenu->removeItem(this);
		}
	}

}



