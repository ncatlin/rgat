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

#ifndef AGUI_LISTBOX_HPP
#define AGUI_LISTBOX_HPP
#include "Agui/Widget.hpp"
#include "Agui/Widgets/ScrollBar/HScrollBar.hpp"
#include "Agui/Widgets/ScrollBar/VScrollBar.hpp"
#include "Agui/MouseListener.hpp"
#include "Agui/SelectionListener.hpp"
#include "Agui/Widgets/ListBox/ListBoxListener.hpp"
namespace agui {
		/**
	 * Class that represents ListBox.
	 *
	 * Supports three types of selections, Single selection, Multi selection and Extended multi selection
	 *
	 * Optional constructor widget:
	 *
	 * HScrollBar (Horizontal Scroll Bar)
	 *
	 * VScrollBar (Vertical Scroll Bar)
	 *
	 * Widget (Scroll Inset)
     * @author Joshua Larouche
     * @since 0.1.0
     */
	struct ListBoxItem
	{
		agui::Color color;
		std::string text;
		std::string tooltip;
		void* tag;
		ListBoxItem(const std::string& txt,const agui::Color& col)
			: color(col),text(txt),tag(NULL)
		{

		}
	};

	typedef std::vector<std::pair<ListBoxItem,bool> > ListItem;

	class AGUI_CORE_DECLSPEC ListBox : public Widget,
		protected HScrollBarListener, 
		protected VScrollBarListener
	{
	private:
		int firstSelIndex;
		int lastSelIndex;
		int lastMouseY;
		int verticalOffset;
		int horizontalOffset;
		bool sorted;
		bool rsorted;
		bool multiselect;
		bool multiselectExtended;
		bool hoverSelection;
		int itemHeight;
		int hoveredIndex;
		int hKeyScrollRate;
		int vKeyScrollRate;
		int widestItem;
		bool wrapping;
		bool mouseWheelSelection;
		bool allowRightClick;

		ScrollPolicy hScrollPolicy;
		ScrollPolicy vScrollPolicy;
		ListItem items;

		std::vector<ListBoxListener*> listboxListeners;
		std::vector<SelectionListener*> selectionListeners;

		HScrollBar *pChildHScroll;
		VScrollBar *pChildVScroll;
		Widget *pChildInset;

		bool isMaintainingHScroll;
		bool isMaintainingVScroll;
		bool isMaintainingScrollInset;

		agui::Color newItemColor;
		

	protected:
			 /**
	 * Used by subclasses to set widest item.
     * @since 0.2.0
     */
		void _setWidestItem(int widest);
	 /**
	 * Used to dispatch a selection event to the selection listeners.
     * @since 0.1.0
     */
		virtual void displatchSelectionEvent(int index, bool selected);

	/**
	 * Used internally to sort the items.
     * @since 0.1.0
     */
		virtual void sort();

/**
     * Enables or disables the ScrollBars based on the ScrollPolicy.
     * @since 0.1.0
     */
		virtual void checkScrollPolicy();
	/**
     * Will resize the ScrollBars based on the policy.
     * @since 0.1.0
     */
		virtual void resizeSBsToPolicy();
	/**
     * Will adjust the ScrollBar ranges based on the content width and content height.
     * @since 0.1.0
     */
		virtual void adjustSBRanges();
	/**
     * Checks the policy, resizes the scroll bars, and adjusts the ranges.
     * @since 0.1.0
     */
		virtual void updateScrollBars();
/**
     * @return Negative Vertical Scrollbar value.
     * @since 0.1.0
     */
		virtual int getVerticalOffset() const;
	/**
     * @return Negative Horizontal Scrollbar value.
     * @since 0.1.0
     */
		virtual int getHorizontalOffset() const;

	/**
     * Handles keyboard actions like arrow keys.
     * @since 0.1.0
     */
		virtual void keyAction(ExtendedKeyEnum key, bool shift);

		virtual void valueChanged(HScrollBar* source, int val);
		virtual void valueChanged(VScrollBar* source,int val);
	/**
     * Used internally to set the hover index.
     * @since 0.1.0
     */
		virtual void setHoverIndex(int index);
	/**
     * Sets the widest item. (In terms of text width).
     * @since 0.1.0
     */
		virtual void setWidestItem();
	/**
     * Used internally to make a selection.
     * @since 0.1.0
     */
		virtual void makeSelection(int selection, bool controlKey, bool shiftKey);

		virtual void paintComponent(const PaintEvent &paintEvent);
		virtual void paintBackground(const PaintEvent &paintEvent);
	public:
		virtual bool intersectionWithPoint(const Point &p) const;
	/**
     * @return The zero based index of the item at this point.
     * @since 0.1.0
     */
		virtual int getIndexAtPoint(const Point &p) const;
	/**
     * Will scroll / move to the parameter index.
     * @since 0.1.0
     */
		virtual void moveToSelection(int selection);
	/**
     * @return The size of the Horizontal Scrollbar.
     * @since 0.1.0
     */
		const Dimension& getHSrollSize() const;
	/**
     * @return The size of the Vertical Scrollbar.
     * @since 0.1.0
     */
		const Dimension& getVScrollSize() const;
	/**
     * @return The index of the first item that is visible (Used for rendering).
     * @since 0.1.0
     */
		virtual int getVisibleItemStart() const;
		/**
     * @return The number of items that are visible (Used for rendering).
     * @since 0.1.0
     */
		virtual int getVisibleItemCount() const;
	/**
     * Sets whether or not the hover index is set as the selected index. (Used in DropDown ).
     * @since 0.1.0
     */
		void setHoverSelection(bool selecting);
			/**
     * @return True if the hover index is set as the selected index. (Used in DropDown ).
     * @since 0.1.0
     */
		bool isHoverSelection() const;
		virtual void mouseWheelDown(MouseEvent &mouseEvent);
		virtual void mouseDrag(MouseEvent &mouseEvent);
		virtual void mouseWheelUp(MouseEvent &mouseEvent);
		virtual void mouseLeave(MouseEvent &mouseEvent);

		virtual void mouseDown(MouseEvent &mouseEvent);
		virtual void mouseUp(MouseEvent &mouseEvent);
		virtual void mouseMove(MouseEvent &mouseEvent);

		virtual void keyDown(KeyEvent &keyEvent);
		virtual void keyRepeat(KeyEvent &keyEvent);
		virtual void keyUp(KeyEvent &keyEvent);
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
	/**
     * Adds the parameter ListBoxListener.
     * @since 0.1.0
     */
		virtual void addListBoxListener(ListBoxListener* listener);
	/**
     * Removes the parameter ListBoxListener.
     * @since 0.1.0
     */
		virtual void removeListBoxListener(ListBoxListener* listener);

	/**
     * @return The widest item.
     * @since 0.1.0
     */
		virtual int getContentWidth() const;
	/**
     * @return Item height * number of items.
     * @since 0.1.0
     */
		virtual int getContentHeight() const;
	/**
	 * @return True if the Horizontal Scrollbar is needed (Does not consider policy).
     * @since 0.1.0
     */
		bool isHScrollNeeded() const;
			/**
	 * @return True if the Vertical Scrollbar is needed (Does not consider policy).
     * @since 0.1.0
     */
		bool isVScrollNeeded() const;
	/**
	 * Sets the Horizontal Scrollbar's policy. (SHOW_ALWAYS, SHOW_AUTO, SHOW_NEVER).
     * @since 0.1.0
     */
		void setHScrollPolicy(ScrollPolicy policy);
	/**
	 * Sets the Vertical Scrollbar's policy. (SHOW_ALWAYS, SHOW_AUTO, SHOW_NEVER).
     * @since 0.1.0
     */
		void setVScrollPolicy(ScrollPolicy policy);
	/**
	 * #return The Horizontal Scrollbar's policy. (SHOW_ALWAYS, SHOW_AUTO, SHOW_NEVER).
     * @since 0.1.0
     */
		ScrollPolicy getHScrollPolicy() const;
	/**
	 * @return The Vertical Scrollbar's policy. (SHOW_ALWAYS, SHOW_AUTO, SHOW_NEVER).
     * @since 0.1.0
     */
		ScrollPolicy getVScrollPolicy() const;
	/**
	 * @return True if the ListBox will wrap to the first or last item when the bottom or top is reached.
	 *
	 * Does not work with Multiselect, and works with MultiselectExtended if only one item is selected.
     * @since 0.1.0
     */
		virtual bool isWrapping() const;
	/**
	 * Sets whether or not the ListBox will wrap to the first or last item when the bottom or top is reached.
	 *
	 * Does not work with Multiselect, and works with MultiselectExtended if only one item is selected.
     * @since 0.1.0
     */
		virtual void setWrapping(bool wrapping);
	/**
	 * @return The hover index or -1 if the mouse is not under anything.
     * @since 0.1.0
     */
		virtual int getHoverIndex() const;
	/**
	 * @return The bottommost selected index.
     * @since 0.1.0
     */
		virtual int getBottomSelectedIndex() const;
	/**
	 * Used to select a range of items. Each item will raise a selection event.
     * @since 0.1.0
     */
		virtual void selectRange(int startIndex, int endIndex);
		virtual void setSize(const Dimension &size);
		virtual void setSize(int width, int height);

	/**
	 * Sets how many values the left and right keys will move the Horizontal Scrollbar.
     * @since 0.1.0
     */
		virtual void setHKeyScrollRate(int rate);
	/**
	 * @return How many values the left and right keys will move the Horizontal Scrollbar.
     * @since 0.1.0
     */
		virtual int getHKeyScrollRate() const;
			/**
	 * Sets how many values the up and down keys will move the Vertical Scrollbar.
     * @since 0.1.0
     */
		virtual void setVKeyScrollRate(int rate);
	/**
	 * @return How many values the up and down keys will move the Vertical Scrollbar.
     * @since 0.1.0
     */
		virtual int getVKeyScrollRate() const;

	/**
	 * Sets how many values in addition to the actual delta mouse wheel, 
	 * the vertical scrollbar will be 
	 * moved when a mouse wheel event is triggered.
	 *
	 * The widget under the mouse has priority. 
	 * If a widget like a ListBox consumes the event, it will scroll instead.
	 *
     * @since 0.1.0
     */
		virtual void setWheelScrollRate(int rate);
		
	/**
	 * @return How many values in addition to the actual delta mouse wheel, 
	 * the vertical scrollbar will be 
	 * moved when a mouse wheel event is triggered.
	 *
	 * The widget under the mouse has priority. 
	 * If a widget like a ListBox consumes the event, it will scroll instead.
     * @since 0.1.0
     */
		virtual int getWheelScrollRate() const;
	/**
	 * Sets the height of an item.
     * @since 0.1.0
     */
		virtual void setItemHeight(int height);
	/**
	 * @return The height of an item.
     * @since 0.1.0
     */
		virtual int getItemHeight() const;
		virtual void setFont(const Font *font);
	/**
	 * @return True if the parameter index exists.
     * @since 0.1.0
     */
		virtual bool indexExists(int index) const;
	/**
	 * Adds a single item.
     * @since 0.1.0
     */
		virtual void addItem(const std::string &item);
	/**
	 * Adds multiple items by parsing newline characters.
     * @since 0.1.0
     */
		virtual void addItems(const std::string &items);
	/**
	 * Adds multiple items by retrieving them from the parameter std::vector.
     * @since 0.1.0
     */
		virtual void addItems(const std::vector<std::string> &items);
	/**
	 * Removes the first instance of this item.
     * @since 0.1.0
     */
		virtual void removeItem(const std::string &item);
	/**
	 * Removes the item at the parameter index.
     * @since 0.1.0
     */
		virtual void removeItemAt(int index);
	/**
	 * Inserts the item at the parameter index.
     * @since 0.1.0
     */
		virtual void addItemAt(const std::string &item, int index);
	/**
	 * @return the number of items in the ListBox.
     * @since 0.1.0
     */
		virtual int  getLength() const;
	/**
	 * @return The index of the first found instance of the parameter string or -1 if not found.
     * @since 0.1.0
     */
		virtual int getIndexOf(const std::string &item) const; 
	/**
	 * @return The string of the first found instance of the parameter string or "" if not found.
     * @since 0.1.0
     */
		virtual std::string getItemAt(int index) const;
	/**
	 * @return The topmost selected index or -1 if nothing is selected.
     * @since 0.1.0
     */
		virtual int getSelectedIndex() const;
	/**
	 * Sets the selected index. This will be the only selected index.
     * @since 0.1.0
     */
		virtual void setSelectedIndex(int index);
	/**
	 * @return A std::vector containing all selected indexes.
     * @since 0.1.0
     */
		virtual std::vector<int> getSelectedIndexes() const;
	/**
	 * Selects all the indexes in the parameter std::vector.
     * @since 0.1.0
     */
		virtual void setSelectedIndexes(const std::vector<int> &indexes);
	/**
	 * Erases and removes all items and sends a selection event of -1.
     * @since 0.1.0
     */
		virtual void clearItems();

		/**
	 * @return Number of items in ListBox.
     * @since 0.2.0
     */
		virtual int getItemCount() const;
	/**
	 * Sets the selected index to -1. No item will be selected.
     * @since 0.1.0
     */
		virtual void clearSelectedIndexes();
	/**
	 * @return True if the items are sorted. If this is true, adding items will cause them to get sorted.
     * @since 0.1.0
     */
		virtual bool isSorted() const;
			/**
	 * @return True if the items are reverse sorted. If this is true, adding items will cause them to get sorted.
     * @since 0.1.0
     */
		virtual bool isReverseSorted() const;
	/**
	 * Sets whether or not the items will be sorted. If this is true, adding items will cause them to get sorted.
     * @since 0.1.0
     */
		virtual void setSorted(bool sorted);
	/**
	 * Sets whether or not the items will be reverse sorted. If this is true, adding items will cause them to get sorted.
     * @since 0.1.0
     */
		virtual void setReverseSorted(bool reverse);
	/**
	 * @return True if: when an item is clicked, if it was selected, it is no longer selected, if it was not, it will be selected.
     * @since 0.1.0
     */
		virtual bool isMultiselect() const;
	/**
	 * Sets whether or not: when an item is clicked, if it was selected, it is no longer selected, if it was not, it will be selected.
     * @since 0.1.0
     */
		virtual void setMultiselect(bool multiselect);

	/**
	 * @return True if: when an item is clicked or arrow key pressed, if shift or control are pressed, will behave differently.
     * @since 0.1.0
     */
		virtual bool isMultiselectExtended() const;
		/**
	 * Sets whether or not: when an item is clicked or arrow key pressed, if shift or control are pressed, will behave differently.
     * @since 0.1.0
     */
		virtual void setMultiselectExtended(bool multiselect);
	/**
	 * @return True if mouse wheel events cause selections.
     * @since 0.1.0
     */
		virtual bool isMouseWheelSelection() const;
	/**
	 * Sets whether or not mouse wheel events cause selections.
     * @since 0.1.0
     */
		virtual void setMouseWheelSelection(bool mWSelsection);
	/**
	 * Sets that only one item at a time may be selected (Default).
     * @since 0.1.0
     */
		virtual void setSingleSelection();
	/**
	 * @return True if only one item at a time may be selected (Default).
     * @since 0.1.0
     */
		virtual bool isSingleSelection() const;
	/**
	 * Resizes the width to the widest item.
     * @since 0.1.0
     */
		virtual void resizeWidthToContents();
	/**
	 * Resizes the height to the number of items * item height.
     * @since 0.1.0
     */
		virtual void resizeHeightToContents();
			/**
	 * Resizes the width to the widest item and the height to the number of items * item height.
     * @since 0.1.0
     */
		virtual void resizeToContents();

	/**
	 * Sets the text color for a newly added item.
     * @since 0.2.0
     */
		virtual void setNewItemColor(const agui::Color& color);

	/**
	 * @Return The text color for a newly added item.
     * @since 0.2.0
     */
		virtual const agui::Color& getNewItemColor() const;

	/**
	 * @Return the actual ListBoxItem at index.
     * @since 0.2.0
     */
		const ListBoxItem& getListItemAt(int index) const;

	/**
	 * Sets the tooltip text for the specified item.
     * @since 0.2.0
     */
		void setItemToolTipText(const std::string& text, int index);

	/**
	 * Sets the text color for the specified item.
     * @since 0.2.0
     */
		void setItemTextColor(const agui::Color& color, int index);

	/**
	 * @Return The ToolTip text of the hover index or the usual if no hover index.
     * @since 0.2.0
     */
		virtual std::string getToolTipText();

	/**
	 * Sets whether or not right clicking will make a selection.
     * @since 0.2.0
     */
		void setAllowRightClickSelection(bool allow);

		/**
	 * @return True if right clicking will make a selection.
     * @since 0.2.0
     */
		bool isRightClickSelectionAllowed() const;

			/**
	 * @return Begin iterator to the pair of items 
	 * representing the text of the item and if it is selected.
     * @since 0.1.0
     */
		ListItem::iterator getItemsBegin();
			/**
	 * @return Const begin iterator to the pair of items 
	 * representing the text of the item and if it is selected.
     * @since 0.1.0
     */
		ListItem::const_iterator getItemsBegin() const;
			/**
	 * @return End iterator to the pair of items 
	 * representing the text of the item and if it is selected.
     * @since 0.1.0
     */
		ListItem::iterator getItemsEnd();
	/**
	 * @return Const end iterator to the pair of items 
	 * representing the text of the item and if it is selected.
     * @since 0.1.0
     */
		ListItem ::const_iterator getItemsEnd() const;
	/**
	 * @return Reverse begin iterator to the pair of items 
	 * representing the text of the item and if it is selected.
     * @since 0.1.0
     */
		ListItem::reverse_iterator getItemsRBegin();
	/**
	 * @return Const reverse begin iterator to the pair of items 
	 * representing the text of the item and if it is selected.
     * @since 0.1.0
     */
		ListItem::const_reverse_iterator getItemsRBegin() const;
	/**
	 * @return Reverse end iterator to the pair of items 
	 * representing the text of the item and if it is selected.
     * @since 0.1.0
     */
		ListItem::reverse_iterator getItemsREnd();
			/**
	 * @return Const reverse end iterator to the pair of items 
	 * representing the text of the item and if it is selected.
     * @since 0.1.0
     */
		ListItem ::const_reverse_iterator getItemsREnd() const;
		

	virtual void setFontColor(const Color &color);

	/**
	 * Construct with optional HorizontalScrollBar ,
	 * VerticalScrollBar , and ScrollInset Widget.
     * @since 0.1.0
     */
		ListBox(HScrollBar *hScroll = NULL, VScrollBar *vScroll = NULL,
			Widget* scrollInset = NULL);
			/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~ListBox(void);
	};
}
#endif
