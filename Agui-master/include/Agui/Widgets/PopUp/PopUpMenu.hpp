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

#ifndef AGUI_POPUP_MENU_HPP
#define AGUI_POPUP_MENU_HPP

#include "Agui/Widget.hpp"
#include "Agui/Widgets/Button/Button.hpp"
#include "Agui/Widgets/PopUp/PopUpMenuItem.hpp"
#include "Agui/MouseListener.hpp"
namespace agui {

	 /**
	 * Class that represents a PopUpMenu.
	 *
	 * ActionEvent when:
	 *
	 * PopUpMenuItemClicked
     * @author Joshua Larouche
     * @since 0.2.0
     */
	class AGUI_CORE_DECLSPEC PopUpMenu : public Widget, MouseListener{
		std::vector<PopUpMenuItem*> items;
		int itemHeight;
		bool showIcon;
		int startTextGap;
		int middleTextGap;
		int endTextGap;
		int iconWidth;
		int separatorHeight;
		int selectedIndex;
		PopUpMenu* parentMenu;
		PopUpMenu* childMenu;
		Widget* invoker;
		bool mouseInside;
		bool needsClosure;
		Point childOffset;
		bool needsToMakeSelecton;
		agui::Button* m_invokeButton;

		virtual void makeSelection();
	protected:
		virtual void paintBackground(const PaintEvent &paintEvent);
		virtual void paintComponent(const PaintEvent &paintEvent);

		virtual void handleKeyboard(KeyEvent& keyEvent);
	public:
		PopUpMenu();
		virtual ~PopUpMenu();
		virtual void keyDown(KeyEvent &keyEvent);
		virtual void keyRepeat(KeyEvent &keyEvent);
		virtual void logic(double timeElapsed);
		virtual void showChildMenu();
		virtual void hideChildMenu();
		virtual void selectedIndexChanged();
		virtual int getNextIndex() const;
		virtual int getPreviousIndex() const;
		virtual void requestShowChildMenu();
		virtual void presentChildMenu();
		virtual PopUpMenuItem* getItemAt(int index) const;

		virtual void mouseLeave(MouseEvent &mouseEvent);
		virtual void mouseMove(MouseEvent &mouseEvent);
		virtual void mouseUp(MouseEvent &mouseEvent);
		virtual void mouseClick(MouseEvent &mouseEvent);
		virtual void focusLost();

		virtual void mouseDownCB(MouseEvent &mouseEvent);

		virtual PopUpMenu* getParentPopUp();
		virtual PopUpMenu* getRootPopUp();
		virtual void closePopUp();
		virtual void closeRootPopUp();
		virtual Point alignString(const std::string& text, AreaAlignmentEnum align);
		virtual int getItemWidth(PopUpMenuItem* item) const;
		virtual void addItem(PopUpMenuItem* item);
		virtual void insertItem(PopUpMenuItem* item, int index);
		virtual void addItems(const std::vector<PopUpMenuItem*>& itemVec);
		virtual void removeItem(PopUpMenuItem* item);
		virtual void clearItems();
		virtual Point getIconPosition(int index, int distanceY) const;
		virtual int getLength() const;
		virtual int getItemHeight(PopUpMenuItem* item) const;
		virtual bool itemExists(PopUpMenuItem* item) const;
		virtual int getTextCenter() const;
		virtual bool indexExists(int index) const;
		virtual void setItemHeight(int height);
		virtual int getItemHeight() const;
		virtual void setSeparatorHeight(int height);
		virtual int getSeparatorHeight() const;
		virtual void setShowIcon(bool show);
		virtual bool isShowingIcon() const;
		virtual void setMiddleTextGap(int gap);
		virtual int getMiddleTextGap() const;
		virtual void setStartTextGap(int gap);
		virtual int getStartTextGap() const;
		virtual void setEndTextGap(int gap);
		virtual int getEndTextGap() const;
		virtual void setTextGaps(int start, int middle, int end);
		virtual void setIconWidth(int width);
		virtual int getIconWidth() const;
		virtual void resizeHeightToContents();
		virtual void resizeWidthToContents();
		virtual void resizeToContents();
		virtual int getIndexAtPoint(const Point& p) const;
		virtual void setSelectedIndex(int index);
		virtual int getSelectedIndex() const;
		virtual Point getChildShowPosition() const;
		virtual PopUpMenu* getChildPopUp();
		virtual void setChildOffset(const Point& offset);
		virtual const Point& getChildOffset() const;
		virtual void setFont(const Font *font);
		virtual void setInvokeButton(Button* button);
		virtual void showPopUp(Widget* invoker, int x, int y, PopUpMenu* parentPopUp = NULL);
	};
}
#endif
