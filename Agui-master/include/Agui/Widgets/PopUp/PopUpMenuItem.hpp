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

#ifndef AGUI_POPUP_MENU_ITEM_HPP
#define AGUI_POPUP_MENU_ITEM_HPP
#include "Agui/Widget.hpp"
namespace agui {
	class AGUI_CORE_DECLSPEC PopUpMenu;
	 /**
	 * Class that represents a PopUpMenuItem
	 *
     * @author Joshua Larouche
     * @since 0.2.0
     */
	class AGUI_CORE_DECLSPEC PopUpMenuItem : public Widget {
	public:
		enum MenuItemTypeEnum
		{
			ITEM,
			SUB_MENU,
			SEPARATOR
		};
	private:
		MenuItemTypeEnum itemType;
		Image* icon;
		std::string shortcutText;
		PopUpMenu* subMenu;
		PopUpMenu* parentMenu;
		virtual void paintBackground(const PaintEvent &paintEvent);
		virtual void paintComponent(const PaintEvent &paintEvent);
	public:
		PopUpMenuItem();
		PopUpMenuItem(const std::string& text, Image* image = NULL);
		PopUpMenuItem(const std::string& text, 
			const std::string& shortcutText, Image* image = NULL);
		PopUpMenuItem(MenuItemTypeEnum type);
		PopUpMenuItem(PopUpMenu* menu);
		PopUpMenuItem(PopUpMenu* menu,const std::string&text);
		virtual ~PopUpMenuItem();
		virtual void setItemType(MenuItemTypeEnum itemType );
		virtual MenuItemTypeEnum getItemType() const;
		virtual void setIcon(Image* image);
		virtual Image* getIcon() const;
		virtual void setShortcutText(const std::string& text);
		virtual const std::string& getShortcutText() const;
		virtual void setSubMenu(PopUpMenu* menu);
		virtual PopUpMenu* getSubMenu() const;
		virtual bool isSeparator() const;
		virtual bool isSubMenu() const;
		virtual void setParentMenu(PopUpMenu* menu);
		virtual PopUpMenu* getParentMenu() const;

	};
}
#endif
