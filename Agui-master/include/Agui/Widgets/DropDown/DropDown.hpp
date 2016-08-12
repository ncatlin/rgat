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

#ifndef AGUI_DROPDOWN_HPP
#define AGUI_DROPDOWN_HPP
#include "Agui/Widget.hpp"
#include "Agui/Widgets/ListBox/ListBox.hpp"
#include "Agui/Widgets/DropDown/DropDownListener.hpp"
namespace agui {
		/**
	 * Class that represents a DropDown.
	 *
	 * ActionEvent when:
	 *
	 * Selected item changes.
	 *
	 * Optional constructor widget:
	 *
	 * ListBox
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class DropDown :
		public Widget,
		protected MouseListener, protected KeyboardListener,
		protected ListBoxListener
	{
	private:
		Point listPosOffset;
		Dimension listSizeIncrease;
		int selIndex;
		bool isMaintainingListBox;
		ListBox *pChildListBox;
		int listBoxHeight;
		bool resizeToWidestItem;
		bool mouseInside;
		std::vector<SelectionListener*> selectionListeners;
		std::vector<DropDownListener*> dropDownListeners;
		std::string noSelectionText;
    static int dropDownArrowWidth;
	protected:
	/**
     * Called when the internal ListBox adds an item.
     * @since 0.1.0
     */
		virtual void itemAdded(ListBox* source, const std::string& item);
	/**
     * Called when the internal ListBox removes an item.
     * @since 0.1.0
     */
		virtual void itemRemoved(ListBox* source, const std::string& item);
	/**
     * Called to dispatch a selection event to the selection listeners.
     * @since 0.1.0
     */
		virtual void dispatchSelectionEvent();
	/**
     * Prepares the internal ListBox to be used.
     * @since 0.1.0
     */
		virtual void setupListBox();
	/**
     * Positions the internal ListBox when it is shown.
     * @since 0.1.0
     */
		virtual void positionListBox();
	/**
     * Resizes the internal ListBox when it is shown.
     * @since 0.1.0
     */
		virtual void resizeListBox();
	/**
     * Shows the internal ListBox.
     * @since 0.1.0
     */
		virtual void showDropDown();
	/**
     * Hides the internal ListBox.
     * @since 0.1.0
     */
		virtual void hideDropDown();
		virtual void modalMouseDownCB(MouseEvent &mouseEvent);
		virtual void modalMouseUpCB(MouseEvent &mouseEvent);
		virtual void paintBackground(const PaintEvent &paintEvent);
		virtual void paintComponent(const PaintEvent &paintEvent);
		virtual void keyDownCB(KeyEvent &keyEvent);
		virtual void keyRepeatCB(KeyEvent &keyEvent);
		virtual void keyUpCB(KeyEvent &keyEvent);
		virtual void handleKeyboard(KeyEvent &keyEvent);
	public:
		/**
     * Adds the parameter DropDownListener.
     * @since 0.1.0
     */
		virtual void addDropDownListener(DropDownListener* listener);
	/**
     * Removes the parameter DropDownListener.
     * @since 0.1.0
     */
		virtual void removeDropDownListener(DropDownListener* listener);
	/**
     * Adds the parameter SelectionListener.
     * @since 0.1.0
     */
		virtual void addSelectionListener(SelectionListener* listener);
	/**
     * Removes the parameter SelectionListener.
     * @since 0.1.0
     */
		virtual void removeSelectionListener(SelectionListener* listener);
		virtual void setFont(const Font *font);
	/**
     * Adds an item to the internal ListBox.
     * @since 0.1.0
     */
		virtual void addItem(const std::string &item);
	/**
     * Adds an item to the internal ListBox at the specified index.
     * @since 0.1.0
     */
		virtual void addItemAt(const std::string& item, int index);
    /**
     * @return The string at the specified index
     */
    virtual std::string getItemAt(int index) const;
	/**
     * @return The index of the first found instance of the parameter string in the internal ListBox, or -1 if not found.
     */
    virtual int getIndexOf(const std::string &item) const;
	/**
     * Removes an item from the internal ListBox.
     * @since 0.1.0
     */
	virtual void removeItem(const std::string& item);
	/**
     * Removes an item from the internal ListBox at the specified index.
     * @since 0.1.0
     */

	virtual void clearItems();
	/**
     * Removes all items from the internal ListBox.
     * @since 0.2.0
     */

	virtual int getItemCount() const;
	/**
     * @return Number of items in DropDown.
     * @since 0.2.0
     */

		virtual void removeItemAt(int index);
	/**
     * @return True if the internal ListBox is visible.
     * @since 0.1.0
     */
		virtual bool isDropDownShowing() const;
	/**
     * If true, the internal ListBox will be as wide as the widest item in the ListBox.
	 * Otherwise it will be the width of the DropDown.
     * @since 0.1.0
     */
		void setResizeToWidestItem(bool resize);
	/**
     * @return True, the internal ListBox will be as wide as the widest item in the ListBox.
	 * Otherwise it will be the width of the DropDown.
     * @since 0.1.0
     */
		bool isResizingToWidestItem() const;
		virtual void keyDown(KeyEvent &keyEvent);
		virtual void keyRepeat(KeyEvent &keyEvent);
	/**
     * Sets the selected index. The caption will change to accommodate.
     * @since 0.1.0
     */
		virtual void setSelectedIndex(int index);
	/**
     * @return The selected index.
     * @since 0.1.0
     */
		virtual int getSelectedIndex() const;
		virtual void mouseDown(MouseEvent &mouseEvent);
        virtual void mouseClick(MouseEvent &mouseEvent);
		virtual void mouseClickCB(MouseEvent &mouseEvent);
		virtual void setSize(const Dimension &size);
		virtual void setSize(int width, int height);
		virtual void setLocation(const Point &location);
		virtual void setLocation(int width,int height);
	/**
     * Sets the maximum height of the internal ListBox. If the ListBox overflows its
	 * vertical scroll bar will appear.
     * @since 0.1.0
     */
		void setMaxDropDownHeight(int height);
	/**
     * @return The maximum height of the internal ListBox.
     * @since 0.1.0
     */
		int getMaxDropDownHeight() const;

		/**
     * Sets the offset for the position of the ListBox when it is shown.
     * @since 0.1.0
     */void setListPositionOffset(const Point& offset);
	/**
     * @return The text that will be presented when no item is selected.
     * @since 0.2.1
     */
		const std::string& getNoSelectionText() const;

				/**
     * Sets the text that will be presented when no item is selected.
     * @since 0.2.1
	 */void setNoSelectionText(const std::string& text);
	/**
     * @return The offset for the position of the ListBox when it is shown.
     * @since 0.1.0
     */
		const Point& getListPositionOffset() const;

	/**
     * Sets the offset for the position of the ListBox when it is shown.
     * @since 0.1.0
     */void setListSizePadding(const Dimension& padding);
	/**
     * @return The offset for the position of the ListBox when it is shown.
     * @since 0.1.0
     */
		const Dimension& getListSizePadding() const;

		virtual void mouseEnter(MouseEvent &mouseEvent);
		virtual void mouseLeave(MouseEvent &mouseEvent);

	/**
     * @return True if mouse is currently in the Widget.
     * @since 0.2.0
     */
		virtual bool isMouseInside() const;
    virtual void resizeToContents();
	/**
     * Construct with optional ListBox.
     * @since 0.1.0
     */
		DropDown(ListBox *listbox = NULL);
	/**
     * Default destructor.
     * @since 0.1.0
     */
		virtual ~DropDown(void);
	};
}
#endif
