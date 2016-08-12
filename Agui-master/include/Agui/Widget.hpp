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

#ifndef AGUI_WIDGET_HPP
#define AGUI_WIDGET_HPP

#include "Agui/BaseTypes.hpp"
#include "Agui/EventArgs.hpp"
#include "Agui/Gui.hpp"
#include "Agui/KeyboardListener.hpp"
#include "Agui/MouseListener.hpp"
#include "Agui/FocusListener.hpp"
#include "Agui/WidgetListener.hpp"
#include "Agui/ActionListener.hpp"
#include "Agui/Graphics.hpp"
#include "Agui/FocusManager.hpp"
#include "Agui/CursorProvider.hpp"
#include <list>


namespace agui {
	typedef std::list<Widget*> WidgetArray;
	class AGUI_CORE_DECLSPEC Gui;

	 /**
     * Abstract base class for all widgets in Agui.
	 *
	 * Must implement:
	 *
	 * paintBackground
	 *
	 * paintComponent
     *
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC Widget
	{

	private:
		std::vector<Widget*> rects;
		static Font* globalFont;
		static int globalFontID;
		bool flaggedForDestruction;
		Color fontColor;
		Font *font;
		int textLen;
		float opacity;
		Color backColor;
		Point location;
		Dimension maxSize;
		Dimension minSize;
		Dimension size;
		Dimension innerSize;
		int tMargin;
		int lMargin;
		int bMargin;
		int rMargin;
		bool isWidgetEnabled;
		bool isWidgetVisible;
		bool isWidgetFocusable;
		bool isWidgetTabable;
		bool usingGlobalFont;
		bool paintingChildren;
		std::string text;
		int previousFontNum;
		std::stack<Rectangle> stackRects;
		Point stackOffset;
		WidgetArray children;
		WidgetArray privateChildren;
		std::string toolTipText;
		bool handlesChildLogic;
		bool prevTabable;
		bool layoutWidget;
		float globalOpacity;
        bool causesLocationChange;


		std::vector<MouseListener*> mouseListeners;
		std::vector<KeyboardListener*> keyboardListeners;

		std::vector<FocusListener*>focusListeners;

		std::vector<WidgetListener*>widgetListeners;

		std::vector<ActionListener*>actionListeners;

	 /**
     * Generates a new mouse event where the source is the widget.
	 *
	 * Used when dispatching mouse listener events.
     * @since 0.1.0
     */
		MouseEvent addSourceToMouseEvent(const MouseEvent &mouseEvent);

	 /**
     * Generates a new keyboard event where the source is the widget.
	 *
	 * Used when dispatching keyboard listener events.
     * @since 0.1.0
     */

		KeyEvent addSourceToKeyEvent(const KeyEvent &keyEvent);

	 /**
     * Brings this child widget to the front.
	 *
	 * This affects render order of children and private children.
     * @since 0.1.0
     */
		void setFrontWidget(Widget* widget);

	 /**
     * Sends this child widget to the back.
	 *
	 * This affects render order of children and private children.
     * @since 0.1.0
     */
		void setBackWidget(Widget* widget);

	/**
     * Sets the inner size.
     * @since 0.1.0
     */

		void _setInnerSize();
	/**
     * Dispatches the event.
     * @since 0.2.0
     */

		void _parentSizeChangedEvent();

		Widget *parentWidget;

	protected: 
		FocusManager* _focusManager;
		Gui* _container;

	/**
     * Paints the interior of the widget after the background has been painted.
	 * painting is relative to the top left margins.
	 *
	 * This means drawing at 0,0 will draw at LEFT_MARGIN, TOP_MARGIN
	 * relative to where the widget's 0,0 is.
	 *
	 * The clipping rectangle does not permit you to draw outside of the
	 * margins, and you should not do so, although if you insist,
	 * you can call paintEvent.graphics()->popClippingRect().
	 *
	 * Must be implemented.
	 * @param  paintEvent Object to paint with.
     * @since 0.1.0
     */
		virtual void paintComponent				(const PaintEvent 
	                                          		&paintEvent) = 0;
			/**
     * Paints the background of the widget.
	 * painting is relative to the widget's top left corner.
	 *
	 * This means drawing at 0,0 will draw
	 * relative to where the widget's 0,0 is.
	 *
	 * The clipping rectangle does not permit you to draw outside of the
	 * widget's area, and you should not do so, although if you insist,
	 * you can call paintEvent.graphics()->popClippingRect().
	 *
	 * Must be implemented.
	 * @param  paintEvent Object to paint with.
     * @since 0.1.0
     */
		virtual void paintBackground			(const PaintEvent 
			&paintEvent) = 0;

	/**
	 * @return The Gui's focused widget or NULL if this widget is not part of a Gui.
     * @since 0.1.0
     */
		Widget*	getFocusedWidget		() const;

	/**
	 * Will recursively paint all this widget's public and private children.
	 *
	 * Only call this if you want to manually paint the children.
	 * @param  paintEvent Object to paint with.
     * @since 0.1.0
     */
		virtual void paintChildren(const PaintEvent &paintEvent);

	/**
	 * @return A boolean indicating if the parameter widget is a child of this widget.
	 * @param  widget The widget you would like to check for.
     * @since 0.1.0
     */
		virtual bool containsPrivateChild(Widget *widget) const;
	/**
	* @return The index of the private child in the internal private widget std::vector.
	*
	* @return -1 if not found.
	* @param  widget The widget you would like to get the index of.
	* @since 0.1.0
	*/
		virtual int getPrivateChildIndex(Widget *widget) const;

	/**
	* Adds this widget as a private widget.
	*
	* Private widgets are intended to help make 
	* a more complex widget. For example, a scroll bar has 3 private
	* widgets. 
	*
	* It is also convenient if the user wants to clear the children.
	*
	* Private children are rendered before children.
	* @param  widget The widget to be added.
	* @since 0.1.0
	*/
		virtual void addPrivateChild(Widget *widget);
	/**
	* Removes this private widget.
	* @param  widget The widget to be removed.
	* @since 0.1.0
	*/
		virtual void removePrivateChild(Widget *widget);

	/**
	* Dispatches the Action Event to all of the widget's action listeners.
	*
	* You should call this when you feel an ActionEvent has occurred.
	* @param  evt The ActionEvent to be distributed.
	* @since 0.1.0
	*/
		virtual void dispatchActionEvent(const ActionEvent &evt);
	/**
	*Instance of the UTF8 class, contains useful UTF8 functions.
	* @since 0.1.0
	*/
		UTF8 unicodeFunctions;

	/**
	* Sets whether of not this widget is responsible for painting its children.
	* @param  painting Boolean indicating if you will be painting the children.
	* @see paintChildren
	* @since 0.1.0
	*/
		void setPaintingChildren(bool painting);

	/**
	*Called by the parent and sent to all of its private and public children when it resizes.
	* @since 0.1.0
	*/
		virtual void parentSizeChanged();

	/**
	* @return An anchor position for a given alignment.
	* @since 0.1.0
	*/
		Point createAlignedPosition(AreaAlignmentEnum alignment,
			const Rectangle &parentRect,const Dimension &childSize) const;

	/**
	* @return The rounded parameter value. Ex: 1.3f returns 1 and 1.8f returns 2.
	* @since 0.1.0
	*/
		int _round(float val) const;

	public:

	/**
	* Default constructor.
	*
	* Initializes the member variables.
	*
	* Widgets are not tabbable nor focusable by default.
	* @since 0.1.0
	*/
		Widget(void);
			/**
	* Default destructor.
	*
	* Frees the memory and removes all children.
	* @since 0.1.0
	*/
		virtual ~Widget(void);

				/**
	* Dispatches the keyboard event to the listeners.
	* @since 0.1.0
	*/
		bool _dispatchKeyboardListenerEvent(KeyEvent::KeyboardEventEnum event,
			const KeyEvent & keyEvent);
				/**
	* Dispatches the mouse event to the listeners.
	* @since 0.1.0
	*/
		bool _dispatchMouseListenerEvent(MouseEvent::MouseEventEnum event,
			MouseEvent & mouseEvent);

	/**
	*Called by the Gui to paint all the widgets.
	* @since 0.1.0
	*/
		void _recursivePaintChildren(Widget *root, bool enabled, float globalOpacity, Graphics *graphicsContext);
	/**
	* If it is flagged, the Gui it belongs to will delete it in the next logic loop
	* unless it was not part of a Gui when it was flagged or a flag in the Gui
	* has been set indicating that the Gui's stack of flagged widgets must be manually popped.
	* @return A boolean indicating if this widget is flagged for destruction.
	* @since 0.1.0
	*/
		virtual bool isFlaggedForDestruction() const;
	/**
	* Will flag this widget for destruction on next logic loop.
	* @since 0.1.0
	*/
		virtual void flagForDestruction();
	/**
	* Will flag this widget's public children for destruction.
	*
	* Will not flag its private children for destruction.
	* @since 0.1.0
	*/
		virtual void flagChildrenForDestruction();
	/**
	* Will flag this widget's public children for destruction and recursively all of their public children.
	*
	* Will not flag its private children for destruction nor those of the children.
	* @since 0.1.0
	*/
		virtual void flagAllChildrenForDestruction();
	/**
	* If the top most widget can be found, this widget will be added as a child of the top.
	* @since 0.1.0
	*/
		virtual void sendToTop();

	/**
	* Clears and removes all public children from this widget.
	* @since 0.1.0
	*/
		virtual void clear();

			/**
	* Allows you to set the margins of the widget.
	*
	* Painting inside these margins in paintBackground can be used to paint borders.
	* @param t The top margin.
	* @param l The left margin.
	* @param b The bottom margin.
	* @param r The right margin.
	* @since 0.1.0
	*/
		void setMargins(int t, int l, int b, int r);


	/**
	* @return A begin iterator to the public children std::list.
	* @since 0.1.0
	*/
		WidgetArray::iterator			getChildBegin();

	/**
	* @return A reverse begin iterator to the public children std::list.
	* @since 0.1.0
	*/
		WidgetArray::reverse_iterator	getChildRBegin();

	/**
	* @return An end iterator to the public children std::list.
	* @since 0.1.0
	*/

		WidgetArray::iterator			getChildEnd();

	/**
	* @return A reverse end iterator to the public children std::list.
	* @since 0.1.0
	*/

		WidgetArray::reverse_iterator	getChildREnd();

	/**
	* @return Const iterator.
	* @since 0.1.0
	*/
		WidgetArray::const_iterator			getChildBegin() const;
	/**
	* @return Const iterator.
	* @since 0.1.0
	*/
		WidgetArray::const_reverse_iterator	getChildRBegin() const;
	/**
	* @return Const iterator.
	* @since 0.1.0
	*/
		WidgetArray::const_iterator			getChildEnd() const;
	/**
	* @return Const iterator.
	* @since 0.1.0
	*/
		WidgetArray::const_reverse_iterator	getChildREnd() const;

			/**
	* @return A begin iterator to the private children std::vector.
	* @since 0.1.0
	*/
		WidgetArray::iterator			getPrivateChildBegin();
		/**
	* @return A reverse begin iterator to the private children std::vector.
	* @since 0.1.0
	*/
		WidgetArray::reverse_iterator	getPrivateChildRBegin();
			/**
	* @return An end iterator to the private children std::vector.
	* @since 0.1.0
	*/
		WidgetArray::iterator			getPrivateChildEnd();
	/**
	* @return A reverse end iterator to the private children std::vector.
	* @since 0.1.0
	*/
		WidgetArray::reverse_iterator	getPrivateChildREnd();

	/**
	* @return Const iterator.
	* @since 0.1.0
	*/
		WidgetArray::const_iterator			getPrivateChildBegin() const;
	/**
	* @return Const iterator.
	* @since 0.1.0
	*/
		WidgetArray::const_reverse_iterator	getPrvateChildRBegin() const;
	/**
	* @return Const iterator.
	* @since 0.1.0
	*/
		WidgetArray::const_iterator			getPrivateChildEnd() const;
	/**
	* @return Const iterator.
	* @since 0.1.0
	*/
		WidgetArray::const_reverse_iterator	getPrivateChildREnd() const;

	/**
	* @return Number of private children.
	* @since 0.2.0
	*/
		int	getPrivateChildCount() const;

	/**
	* @return Private child at parameter index.
	* @since 0.2.0
	*/
		Widget*	getPrivateChildAt(int index) const;

				/**
	* @return A boolean indicating if the widget is responsible for painting its children.
	* @since 0.1.0
	*/
		virtual bool isPaintingChildren() const;
	/**
	* Used to clip drawing to the widget area.
	* @param paintEvent Object used to clip the graphics context.
	* @since 0.1.0
	*/
		virtual void clip(const PaintEvent &paintEvent);

	/**
	* Adds the parameter widget to this widget's children.
	* @param widget Widget to add.
	* @since 0.1.0
	*/
		virtual void	add		(Widget *widget);

	/**
	* Removes the parameter widget from this widget's children.
	* @param widget Widget to remove.
	* @since 0.1.0
	*/
		virtual void	remove	(Widget *widget);

	/**
	* @return A boolean indicating if the parameter widget is a child of this widget.
	* @param widget Widget to check for.
	* @since 0.1.0
	*/
		bool	containsChildWidget(Widget *widget) const;
	/**
	* @return The index of the parameter widget in this widget's public children std::vector.
	*
	* @return -1 if not found.
	* @param widget Widget to get the index of.
	* @since 0.1.0
	*/
		int		getChildWidgetIndex(const Widget *widget) const;
	/**
	* @return The number of public children this widget has.
	* @since 0.1.0
	*/
		int		getChildCount()const;
	/**
	* @return The margin of the side specified by the parameter.
	* @param side The side to get the margin of.
	* @since 0.1.0
	*/
		int getMargin(SideEnum side) const;

	/**
	* @return A boolean indicating if a given mouse button being pressed should keep the mouse locked. 	* For example, if you do not want a subsequent right click to unlock a locked widget, override this method.

	* @param button The button in question.
	* @since 0.1.0
	*/
		virtual bool    keepMouseLock(MouseButtonEnum button) const;
	/**
	* Called when the mouse is clicked.
	*
	* This means that the mouse was pressed down on the same widget that it was pressed up on.
	* @param mouseEvent Information about the mouse event.
	* @since 0.1.0
	*/
		virtual void	mouseClick		(MouseEvent &mouseEvent);
	/**
	* Called when a key has been pressed down.
	* @param keyEvent Information about the keyboard event.
	* @since 0.1.0
	*/
		virtual void	keyDown			(KeyEvent &keyEvent);
	/**
	* Called when a key press is repeated.
	* @param keyEvent Information about the keyboard event.
	* @since 0.1.0
	*/
		virtual void	keyRepeat		(KeyEvent &keyEvent);
	/**
	* Called when a key is released.
	* @param keyEvent Information about the keyboard event.
	* @since 0.1.0
	*/
		virtual void	keyUp			(KeyEvent &keyEvent);
	/**
	* Called when the mouse is pressed down.
	* @param mouseEvent Information about the mouse event.
	* @since 0.1.0
	*/
		virtual void	mouseDown		(MouseEvent &mouseEvent);
	/**
	* The modal widget receives this when the mouse is pressed down on a widget other than
	* the modal widget or any of its children and their descendants.
	* @param mouseEvent Information about the mouse event.
	* @since 0.1.0
	*/
		virtual void	modalMouseDown	(MouseEvent &mouseEvent);
	/**
	* The modal widget receives this when the mouse is released on a widget other than
	* the modal widget or any of its children and their descendants.
	* @param mouseEvent Information about the mouse event.
	* @since 0.1.0
	*/
		virtual void    modalMouseUp    (MouseEvent &mouseEvent);
	/**
	* Called when the mouse is double clicked within the threshold set in the Gui.
	* @param mouseEvent Information about the mouse event.
	* @since 0.1.0
	*/
		virtual void	mouseDoubleClick(MouseEvent &mouseEvent);
	/**
	* Called when the mouse is moved.
	* @param mouseEvent Information about the mouse event.
	* @since 0.1.0
	*/
		virtual void	mouseMove		(MouseEvent &mouseEvent);
	/**
	* Called when the mouse is moved while pressed.
	* @param mouseEvent Information about the mouse event.
	* @since 0.1.0
	*/
		virtual void	mouseDrag		(MouseEvent &mouseEvent);
	/**
	* Called when the mouse is released.
	* @param mouseEvent Information about the mouse event.
	* @since 0.1.0
	*/
		virtual void	mouseUp			(MouseEvent &mouseEvent);
	/**
	* Called when the vertical mouse wheel is changed positively.
	* @param mouseEvent Information about the mouse event.
	* @since 0.1.0
	*/
		virtual void	mouseWheelUp	(MouseEvent &mouseEvent);
	/**
	* Called when the vertical mouse wheel is changed negatively.
	* @param mouseEvent Information about the mouse event.
	* @since 0.1.0
	*/
		virtual void	mouseWheelDown	(MouseEvent &mouseEvent);
	/**
	* Called when the mouse enters the widget.
	* @param mouseEvent Information about the mouse event.
	* @since 0.1.0
	*/
		virtual void	mouseEnter		(MouseEvent &mouseEvent);
	/**
	* Called when the mouse leaves the widget.
	* @param mouseEvent Information about the mouse event.
	* @since 0.1.0
	*/
		virtual void	mouseLeave		(MouseEvent &mouseEvent);
	/**
	* Called when the mouse has been idle over this widget for a certain time.
	* @param mouseEvent Information about the mouse event.
	* @since 0.1.0
	*/
		virtual void	mouseHover		(MouseEvent &mouseEvent);
	/**
	* Called when the widget receives modal focus.
	* @since 0.1.0
	*/
		virtual void	modalFocusGained();
	/**
	* Called when the widget loses modal focus.
	* @since 0.1.0
	*/
		virtual void	modalFocusLost();
	/**
	* @return A boolean indicating if this widget now has modal focus.
	* @since 0.1.0
	*/
		virtual bool	requestModalFocus();
	/**
	* Only the modal widget, its children, and their descendants can release the modal focus.
	* @return A boolean indicating if this widget has released the modal focus.
	* @since 0.1.0
	*/
		virtual bool	releaseModalFocus();

	/**
	* Adds a mouse listener.
	* @param listener The listener.
	* @since 0.1.0
	*/
		virtual void addMouseListener(MouseListener* listener);
	/**
	* Removes a mouse listener.
	* @param listener The listener.
	* @since 0.1.0
	*/
		virtual void removeMouseListener(MouseListener* listener);
	/**
	* Adds a keyboard listener.
	* @param listener The listener.
	* @since 0.1.0
	*/
		virtual void addKeyboardListener(KeyboardListener* listener);
	/**
	* Removes a keyboard listener.
	* @param listener The listener.
	* @since 0.1.0
	*/
		virtual void removeKeyboardListener(KeyboardListener* listener);

	/**
	* @return The public child at that index or NULL if not found.
	* @param index The index where the child is in the std::vector.
	* @since 0.1.0
	*/
		Widget*				getChildAt		(int index) const;
	/**
	* @return This widget's parent or NULL if the widget has no parent.
	* @since 0.1.0
	*/
		Widget*				getParent()				const;
	/**
	* If this widget has a parent but the parent is not in some way part of a Gui
	* then the returned widget may not be the top most one of the Gui.
	* @return The top most widget or NULL if this widget has no parent.
	* @since 0.1.0
	*/
		Widget*				getTopWidget() const;
	/**
	* @return The Gui associated with the top most widget.
	* Will return NULL if the top most widget cannot be found.
	* @since 0.1.0
	*/
		Gui*				getGui()		const;

	/**
	* @return A boolean indicating if this widget can receive focus and modal focus.
	* @since 0.1.0
	*/
		virtual bool			isFocusable()			const;
	/**
	*
	* When a widget is disabled it will not receive mouse or keyboard input.
	* It will also set the enabled flag in PaintEvent to false.
	*
	* If this widget is disabled, its children inherently cannot receive input.
	* @return A boolean indicating if this widget is enabled.
	* @since 0.1.0
	*/
		virtual bool			isEnabled()				const;
		/**
		* When a widget is not visible, it will not receive input, nor be rendered.
		*
		* If this widget is not visible, its children inherently will not be visible.
		* @return A boolean indicating if this widget is visible.
		* @since 0.1.0
		*/
		virtual bool			isVisible()				const;
		/**
		* @return A boolean indicating if this can be tabbed in and out.
		* @since 0.1.0
		*/
		virtual bool			isTabable()				const;
		/**
		* @return This widget's index in its parent's public children std::vector.
		*
		* @return -1 if this widget has no parent or is a private child of its parent.
		* @since 0.1.0
		*/
		int						getIndexInParent()		const;
		/**
		* @return The color of the font which is usually the color of the widget's text.
		* @since 0.1.0
		*/
		virtual const Color& getFontColor()			const;
		/**
		* @return The widget's background color.
		* @since 0.1.0
		*/
		virtual const Color& getBackColor()			const;
		/**
		* @return The font used to paint text.
		* @since 0.1.0
		*/
		virtual const Font*	getFont()				const;
		/**
		* a value of 1 indicates that it is fully opaque.
		*
		* a value of 0 indicates that it is fully transparent.
		*
		* Note: It is the responsibility of the one who implements the paint event to make use of this.
		* @since 0.1.0
		* @return A value between 0.0 and 1.0 indicating how opaque the widget is.
		*/
		float					getOpacity()			const;
		/**
		* @return A rectangle where the top left Point is the widget's location.
		*
		* The size of the rectangle is this widget's size.
		* @since 0.1.0
		*/
		virtual const Rectangle getRelativeRectangle() const;
		/**
		* @return A rectangle where the top left Point is 0,0.
		*
		* The size of the rectangle is this widget's size.
		* @since 0.1.0
		*/
		virtual const Rectangle getSizeRectangle() const;
		/**
		* @return The widget's location.
		*
		* This value is relative to the parent, and factors in the parent's margins.
		* @since 0.1.0
		*/
		virtual const Point& getLocation()			const;
		/**
		* @return A rectangle where the top left Point is the widget's absolute position.
		*
		* The size of the rectangle is this widget's size.
		* @since 0.1.0
		*/
		virtual const Rectangle getAbsoluteRectangle()	const;
		/**
		* @return The size of the widget.
		* @since 0.1.0
		*/
		virtual const Dimension&	getSize()				const;

		/**
		* @return The width of the widget.
		* @since 0.1.0
		*/
		virtual int getWidth() const;
		/**
		* @return The height of the widget.
		* @since 0.1.0
		*/
		virtual int getHeight() const;
		/**
		* @return The inner width of the widget.
		*
		* This is the width minus the left and right margins.
		* @since 0.1.0
		*/
		virtual int getInnerWidth() const;
		/**
		* @return The inner height of the widget.
		*
		* This is the width minus the top and bottom margins.
		* @since 0.1.0
		*/
		virtual int getInnerHeight() const;
		/**
		* @return The minimum size of the widget.
		*
		* The size can never be set to less than this.
		* @since 0.1.0
		*/
		virtual const Dimension& getMinSize()			const;
		/**
		* The size can never be set to more than this.
		*
		* Note: Setting a value of 0 for either axis
		* indicates that this axis has no restriction.
		* @return The maximum size of the widget.
		* @since 0.1.0
		*/
		virtual const Dimension& getMaxSize()			const;
		/**
		* The Gui calls this to know if the mouse is over this widget.
		*
		* By default, this checks if the point is inside the widget's size rectangle.
		* Although certain widgets override this to check the widget's inner rectangle.
		* @return A boolean indicating if this relative point is inside the widget.
		* @param p Relative point.
		* @since 0.1.0
		*/
		virtual bool			intersectionWithPoint	(const Point &p) const;
		/**
		* Positions this widget to the given anchor in its parent.
		* @param alignment The alignment to align this wdget to.
		* @since 0.1.0
		*/
		virtual void            alignToParent(AreaAlignmentEnum alignment);
		/**
		* @return The UTF8 encoded text string of this widget.
		* @since 0.1.0
		*/
		virtual const std::string&	getText()			const;
		/**
		* Sets the size to the parameter Dimension and will clamp it to the minimum and maximum sizes.
		* @param size The desired size.
		* @since 0.1.0
		*/
		virtual void			setSize					(const Dimension &size);
		/**
		* Sets the size to the parameter width and height and will clamp them to the minimum and maximum sizes.
		* @param width The desired width.
		* @param height The desired height.
		* @since 0.1.0
		*/
		virtual void			setSize					(int width, int height);
		/**
		* Called by the Gui when this widget gains input focus.
		* @since 0.1.0
		*/
		virtual void			focusGained();
		/**
		* Will try to give this widget input focus.
		*
		* Will not work if the widget is not focusable.
		* @since 0.1.0
		*/

		virtual void			focus();
		/**
		* Called by the Gui when this widget loses input focus.
		* @since 0.1.0
		*/
		virtual void			focusLost();
		/**
		* Called by the Gui when this widget needs to be painted.
		* @since 0.1.0
		*/

		void					paint					(const PaintEvent &paintEvent);
		/**
		* Sets a hint of whether or not this Widget can be reverse tabbed.
		* @since 0.2.0
		*/
			virtual void			setReverseTabable(bool tab);
		/**
		* @return True if this Widget is hinted as reverse tabable.
		* @since 0.2.0
		*/
			virtual bool			isReverseTabable() const;
			/**
		* Sets a hint of whether or not this Widget is a Layout.
		* @since 0.2.0
		*/
			virtual void			setIsLayout(bool layout);
		/**
		* @return True if this Widget is hinted as a Layout.
		* @since 0.2.0
		*/
			virtual bool			isLayout() const;

		/**
		* sets whether or not this widget is enabled.
		* @param enabled Boolean indicating if the widget will be enabled.
		* @since 0.1.0
		*/
		virtual void			setEnabled				(bool enabled);
		/**
		* sets the widget's font.
		* @param font The font that will be used for this widget.
		* @since 0.1.0
		*/
		virtual void			setFont					(const Font *font);
		/**
		* Sets the location to the parameter Point.
		*
		* The location is relative to its parent.
		* @param location The desired relative location.
		* @since 0.1.0
		*/
		virtual void			setLocation				(const Point &location);
		/**
		* Sets the location to the parameter x and y.
		*
		* The location is relative to its parent.
		* @param x The desired relative x coordinate.
		* @param y The desired relative y coordinate.
		* @since 0.1.0
		*/
		virtual void			setLocation				(int x, int y);
		/**
		* Sets the minimum size of the widget to the parameter Dimension.
		* @param size The minimum size.
		* @since 0.1.0
		*/
		virtual void			setMinSize			(const Dimension &size);
		/**
		* Sets the maximum size of the widget to the parameter Dimension.
		*
		* Note: Setting a value of 0 for either axis
		* indicates that this axis has no restriction.
		* @param size The maximum size.
		* @since 0.1.0
		*/
		virtual void			setMaxSize			(const Dimension &size);
		/**
		* Sets the widget's text to the UTF8 encoded parameter string.
		*
		* @param text The UTF8 encoded string.
		* @since 0.1.0
		*/
		virtual void			setText					(const std::string &text);
		/**
		* Sets the widget's background Color.
		*
		* @param color The desired background Color.
		* @since 0.1.0
		*/
		virtual void			setBackColor			(const Color &color);
		/**
		* Sets the widget's font Color.
		*
		* @param color The desired font Color.
		* @since 0.1.0
		*/
		virtual void			setFontColor			(const Color &color);
		/**
		* Sets the widget's opacity from 0.0 to 1.0.
		*
		* @param opacity The desired opacity from transparent to opaque.
		* @since 0.1.0
		*/
		virtual void			setOpacity				(float opacity);
		/**
		* Sets whether or not this widget, and inherently its children, are rendered and receive input.
		*
		* @param visible Whether or not this widget is visible.
		* @since 0.1.0
		*/
		virtual void			setVisibility			(bool visible);
		/**
		* @return A rectangle where the top left Point is LEFT_MARGIN, TOP_MARGIN.
		*
		* The size of the rectangle is this widget's inner size.
		* @since 0.1.0
		*/
		virtual const Rectangle	getInnerRectangle   () const;
		/**
		* @return This widget's absolute position.
		* @since 0.1.0
		*/
		Point				getAbsolutePosition		() const;	
		/**
		* Makes this widget the front most child in its parent.
		*
		* This affects the render order.
		* @since 0.1.0
		*/
		void					bringToFront			();
		/**
		* Makes this widget the back most child in its parent.
		*
		* This affects the render order.
		* @since 0.1.0
		*/
		void					sendToBack				();
		/**
		* This will focus this widget's next child.
		*
		* It will focus the first child if its last child is focused or none of its children have focus.
		* @since 0.1.0
		*/
		virtual void			focusNext				();
		/**
		* This will focus this widget's previous child.
		*
		* It will focus the last child if its first child is focused or none of its children have focus.
		* @since 0.1.0
		*/
		virtual void			focusPrevious			();
		/**
		* @return A boolean indicating if this widget has the input focus.
		* @since 0.1.0
		*/
		virtual bool			isFocused				() const;
		/**
		* Set the text used to display the ToolTip. 
		* @since 0.2.0
		*/
		virtual void			setToolTipText			(const std::string& text);
		/**
		* @return The text used to display the ToolTip.
		* @since 0.2.0
		*/
		virtual std::string		getToolTipText					();

		/**
		* Makes this widget visible.
		* @see setVisibility
		* @since 0.1.0
		*/
		void					show					();
		/**
		* Makes this widget invisible.
		* @see setVisibility
		* @since 0.1.0
		*/
		void					hide					();
		/**
		* @return The width minus the left and right margins and the height minus the top and bottom margins.
		* @since 0.1.0
		*/
		const Dimension&			getInnerSize			() const;	
		/**
		* @return A boolean indicating if this widget's font is the globally shared font.
		* @since 0.1.0
		*/
		bool					isUsingGlobalFont() const;
		/**
		* Called when the Gui's logic method is called and the parent is not handling it.
		* @param timeElapsed The amount of time the application has been running.
		*
		* This method is useful for animated and timed events.
		* @since 0.1.0
		*/
		virtual void logic(double timeElapsed);

			/**
		* When true, public children's logic will not be called.
		* @since 0.2.0
		*/
		virtual void setHandleChildlogic(bool handled);

		/**
		* @return True if public children's logic will not be called.
		* @since 0.2.0
		*/
		virtual bool isChildLogicHandled() const;

	/**
	* @return The number of UTF8 characters in the widget's text.
	* @since 0.1.0
	*/
		virtual int getTextLength() const;

	/**
	* Sets whether or not this widget can receive input focus.
	* @param focusable The boolean.
	* @since 0.1.0
	*/
		virtual void setFocusable			(bool focusable);
	/**
	* Sets whether or not this widget can be tabbed to.
	* @param tabable The boolean.
	* @since 0.1.0
	*/
		virtual void setTabable				(bool tabable);

	/**
	* Adds a widget listener.
	* @param listener The listener.
	* @since 0.1.0
	*/
		virtual void addWidgetListener(WidgetListener *listener);
	/**
	* Removes a widget listener.
	* @param listener The listener.
	* @since 0.1.0
	*/
		virtual void removeWidgetListener(WidgetListener *listener);
	/**
	* Adds an action listener.
	* @param listener The listener.
	* @since 0.1.0
	*/
		virtual void addActionListener(ActionListener *listener);
	/**
	* Removes an action listener.
	* @param listener The listener.
	* @since 0.1.0
	*/
		virtual void removeActionListener(ActionListener *listener);

	/**
	* Adds a focus listener.
	* @param listener The listener.
	* @since 0.1.0
	*/
		virtual void addFocusListener(FocusListener* listener);
	/**
	* Removes a focus listener.
	* @param listener The listener.
	* @since 0.1.0
	*/
		virtual void removeFocusListener(FocusListener* listener);

	/**
	* @return the cursor that should be set when the mouse enters the widget.
	* @since 0.2.0
	*/
		virtual CursorProvider::CursorEnum getEnterCursor() const;

	/**
	* @return The global font.
	* @since 0.1.0
	*/
		static Font*			getGlobalFont();
	/**
	* Sets the global font.
	* @param font The font that will become the global font.
	* @since 0.1.0
	*/
		static void				setGlobalFont			(const Font *font);

			/**
	* @return True if the parameter cursor was set
	* @since 0.2.0
	*/
		bool setCursor(CursorProvider::CursorEnum cursor);

    /** Implementation differs per widget. Will resize the Widget to fit its contents.
	* ex: Button will resize to fit its text.
	* @since 0.2.0
	*/
    virtual void resizeToContents();
	    /** Implementation differs per widget. Will resize the Widget to fit its contents recursively.
	* ex: Button will resize to fit its text.
	* @since 0.2.0
	*/
    virtual void resizeToContentsRecursive();
	    /** Implementation differs per widget. Will resize the Widget to fit its contents recursively.
	* ex: Button will resize to fit its text.
	* @since 0.2.0
	*/
    virtual void resizeToContentsRecursiveUp();
    /** Clears focus recursively.
	* @since 0.2.0
	*/
    void checkLostFocusRecursive();
    /** By clearing parent widget, all children will lose top.
     * If the top focus manager points to them, they would have no chance to unfocus when they are destroyed,
     * that would result in the focus manager pointing to deleted widget. 
	* @since 0.2.0
	*/
    void clearParentWidget();
    
    /** @return True if the Widget is a TextField or TextBox subclass.
    * @since 0.2.0
    */
    virtual bool isTextComponent() const;
    
    /** @return True if the Widget is a TextField subclass.
    * @since 0.2.0
    */
    virtual bool isTextField() const;
    
    /** @return True if the Widget is a TextBox subclass.
    * @since 0.2.0
    */
    virtual bool isTextBox() const;
        
    /** Sets whether this Widget causes a location change when draged or pressed.
    * @since 0.2.0
    */
    virtual void setCausesLocationChange(bool causes);
        
    /** @return True if this Widget causes a location change when draged or pressed.
    * @since 0.2.0
    */
    virtual bool isCausingLocationChange() const;
    
    /** @return True if the Widget accepts input from the keyboard.
    * @since 0.2.0
    */
    virtual bool canAcceptKeyInput() const;

	virtual void _bringToFront();
	virtual void _sendToBack();

	virtual void setGlobalOpacity(float o);
	virtual float getGlobalOpacity() const;
	};
}

#endif
