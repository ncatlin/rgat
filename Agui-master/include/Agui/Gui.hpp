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

#ifndef AGUI_GUI_HPP
#define AGUI_GUI_HPP

#include "Agui/Graphics.hpp"
#include "Agui/Widget.hpp"
#include "Agui/EventArgs.hpp"
#include <stack>
#include <queue>
#include "Agui/Input.hpp"
#include "Agui/BaseTypes.hpp"
#include "Agui/FocusManager.hpp"
#include "Agui/KeyboardListener.hpp"
#include "Agui/MouseListener.hpp"
#include "Agui/CursorProvider.hpp"
#include "Agui/Transform.hpp"
#include "Agui/TapListener.hpp"
namespace agui
{
	class AGUI_CORE_DECLSPEC TopContainer;
	class AGUI_CORE_DECLSPEC ToolTip;
	/**
     * @mainpage
     * @section Welcome
     * This is the documentation for the classes in the Agui Library.
	 *
	 * Agui is a cross platform and back end independent library for Graphical User Interfaces in games. 
	 * This means that any code you write with
	 * it will work in whatever environment you are working with. At this time, only an Allegro 5
	 * back end is developed, but you are free to develop your own.
	 *
	 * In addition, every class in Agui that uses text uses UTF8. 
	 * This means that Unicode is natively supported throughout.
     */

	/**
     * Class for a Gui.
	 *
	 * You should create one of these for every Gui you need.
	 *
	 * All desktop Widgets must be added through this.
	 *
	 * This class requires you to setInput and setGraphics for it to work correctly.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC Gui
	{
		FocusManager focusMan;
		double currentTime;
		std::vector<KeyboardListener*> keyPreviewListeners;
		std::vector<MouseListener*> mousePreviewListeners;
        std::vector<TapListener*> tapListeners;
		Input* input;
		Graphics* graphicsContext;
		std::stack<Widget*> flaggedWidgets;
		TopContainer* baseWidget;
		double lasttickTime;
		double lastToolTipTime;
		double toolTipShowLength;
		ToolTip* toolTip;
		int maxToolTipWidth;
		bool hasHiddenToolTip;
		std::stack<Widget*> q;
		std::queue<MouseInput> queuedMouseDown;
		MouseInput emptyMouse;
		MouseEvent relArgs;
		bool destroyingFlaggedWidgets;
		CursorProvider* cursorProvider;
	
		double timerInterval;

		KeyEnum tabNextKey;
		ExtendedKeyEnum tabNextExtKey;
		bool    tabNextShift;
		bool    tabNextControl;
		bool    tabNextAlt;
		KeyEnum tabPreviousKey;
		ExtendedKeyEnum tabPreviousExtKey;
		bool    tabPreviousShift;
		bool    tabPreviousControl;
		bool    tabPreviousAlt;

		//used to focus a tabable widget
		bool passedFocus; 

		bool tabbingEnabled;
        bool focusEnabled;

		//modal variable

		MouseEvent mouseEvent;
		double doubleClickExpireTime;
		double doubleClickInterval;
		Widget* lastMouseDownControl;
		Widget* previousWidgetUnderMouse;
		Widget* widgetUnderMouse;
		Widget* controlWithLock;
		Widget* lastHoveredControl;
		Widget *mouseUpControl;
		bool canDoubleClick;

		double hoverInterval;
		double timeUntilNextHover;

		KeyEvent keyEvent;
		MouseButtonEnum lastMouseButton;

		bool wantWidgetLocationChanged;
		bool enableExistanceCheck;

		bool useTransform;
		Transform transform;

		bool delayMouseDown;
        
        Point lastDragPos;
        Point startDragPos;
        double downTime;
        double touchInertia;
        double lastInertiaTime;
        Widget* inertiaReceiver;

		std::queue<Widget*> frontWidgets;
		std::queue<Widget*> backWidgets;
        
    
        void haltInertia();
        void processInertia();
        void beginInertia(Widget* target, float speed);

	/**
     * Converts the mouse event's position into one that is relative to the parameter widget.
     * @since 0.1.0
     */
		void makeRelArgs(Widget *source);
	/**
     * Handles the hover event.
     * @since 0.1.0
     */
		void handleHover();
	/**
     * Handles the double click event.
     * @since 0.1.0
     */
		void handleDoubleClick();
	/**
     * Invalidates the double click event.
     * @since 0.1.0
     */
		void resetDoubleClickTime();
	/**
     * Invalidates the hover event.
     * @since 0.1.0
     */
		void resetHoverTime();

	/**
     * Sets the key event.
     * @since 0.1.0
     */
		void setKeyEvent(const KeyboardInput &keyboard,bool handled);
	/**
     * Sets the last mouse down widget.
     * @since 0.1.0
     */
		void setLastMouseDownControl(Widget* control);
	/**
     * Sets the mouse event.
     * @since 0.1.0
     */
		void setMouseEvent(const MouseInput &mouse);
	/**
     * Sets which mouse button is pressed.
     * @since 0.1.0
     */
		void setMouseButtonDown(MouseButtonEnum button);
	/**
     * Finds which widget is under the mouse using recursion.
     * @since 0.1.0
     */
		Widget* recursiveGetWidgetUnderMouse(Widget* root,
			const MouseEvent &mouse);

	/**
     * Handles the Gui's timed events.
     * @since 0.1.0
     */
		void handleTimedEvents();

	/**
     * Handles the ToolTip hide logic.
     * @since 0.2.0
     */
		void handleToolTip();

	/**
     * @return last mouse down widget.
     * @since 0.1.0
     */
		Widget* getLastMouseDownControl() const;
	/**
     * @return Which mouse button is pressed.
     * @since 0.1.0
     */
		MouseButtonEnum getMouseButtonDown() const;
	/**
     * @return The mouse event.
     * @since 0.1.0
     */
		MouseEvent getMouseEvent() const;
	/**
     * @return True if the parameter widget is a child of the modal widget.
     * @since 0.1.0
     */
		bool widgetIsModalChild(Widget* widget) const;

	/**
     * @return True if the focused widget was passed.
     * @since 0.1.0
     */
		bool recursiveFocusNext( Widget* target, Widget* focused);
	/**
     * Focuses the next tabable widget in the Gui.
     * @since 0.1.0
     */
		virtual void focusNextTabableWidget();

		/**
     * @return True if the focused widget was passed.
     * @since 0.1.0
     */
		bool recursiveFocusPrevious( Widget* target, Widget* focused);
	/**
     * Focuses the previous tabable widget in the Gui.
     * @since 0.1.0
     */
		virtual void focusPreviousTabableWidget();

		//events
	/**
     * Handles mouse move and mouse wheel events.
	 *
	 * If a widget's location, size, or visibility has changed, the Gui will call this
	 * with isLocationEvent = true.
     * @since 0.1.0
     */
		void handleMouseAxes(const MouseInput &mouse,bool isLocationEvent = false);
	/**
     * Handles a mouse button being pushed down.
     * @since 0.1.0
     */
		void handleMouseDown(const MouseInput &mouse);
			/**
     * Handles a mouse button being released.
     * @since 0.1.0
     */
		void handleMouseUp(const MouseInput &mouse);
			/**
     * Handles a key being pushed down.
     * @since 0.1.0
     */
		void handleKeyDown(const KeyboardInput &keyboard);
			/**
     * Handles a key being released.
     * @since 0.1.0
     */
		void handleKeyUp(const KeyboardInput &keyboard);
	/**
     * Handles a key being held and not released thereby triggering a repeat.
     * @since 0.1.0
     */
		void handleKeyRepeat(const KeyboardInput &keyboard);
	/**
	 * Calls Widget::logic() for every widget starting at base widget.
     * @since 0.1.0
     */
		void recursiveDoLogic(Widget* baseWidget);
	/**
	 * Removes the widget from the Gui. It essentially NULLs all pointers of the parameter widget used by the Gui
	 * to avoid crashes if a widget was under the mouse at the time of its death.
     * @since 0.1.0
     */
		void _removeWidget(Widget *widget);

	/**
	 * Handles tabbing.
     * @since 0.1.0
     */
		bool handleTabbing();
     /**
	 * @return True if the parameter widget exists.
     * @since 0.1.0
     */
		bool widgetExists(const Widget* root, const Widget* target) const;

	/**
	 * @return The focused widget or NULL if none are focused.
     * @since 0.1.0
     */
		Widget* getFocusedWidget() const;

	/**
	 * Dispatches a keyboard event to the listeners. If a listener handles it,
	 * the focused widget will not receive it.
     * @since 0.1.0
     */
		void _dispatchKeyPreview(KeyEvent &keyEvent, KeyEvent::KeyboardEventEnum type);

		/**
	 * Dispatches a mouse event to the listeners. If a listener handles it,
	 * the intended widget will not receive it.
	 *Only sends basic OS events. Not events like Drag,Enter,Leave,etc
     * @since 0.2.0
     */
		void _dispatchMousePreview(const MouseInput& input, MouseEvent::MouseEventEnum type);

	/**
	 * Dispatches the queued keyboard events.
     * @since 0.1.0
     */
		void _dispatchKeyboardEvents();
	/**
	 * Dispatches the queued mouse events.
     * @since 0.1.0
     */
		void _dispatchMouseEvents();

		
	public:
			/**
     * Releases widget under mouse
     * @since 0.2.0
     */
		void _modalChanged();
	/**
     * @return last found widget under the mouse.
     * @since 0.1.0
     */
		virtual Widget* getWidgetUnderMouse() const;
	/**
	 * Calls _removeWidget.
     * @since 0.1.0
     */
		void _dispatchWidgetDestroyed(Widget* widget);
	/**
	 * Called by a widget when its location, size, or visibility changes.
     * @since 0.1.0
     */
		void _widgetLocationChanged();
	/**
	 * @return True if the Gui is responsible for dequeuing and calling delete on the flagged widgets.
     * @since 0.1.0
     */
		bool isDestroyingFlaggedWidgets() const;
	/**
	 * Set to false if the user is responsible for dequeuing and calling delete on the flagged widgets.
	 * Otherwise the Gui will do it on the next logic loop.
     * @since 0.1.0
     */
		void setDestroyFlaggedWidgets(bool destroying);
	/**
	 * Set to true to enable tabbing.
     * @since 0.1.0
     */
		void setTabbingEnabled(bool tabbing);
	/**
	 * @return True if tabbing is enabled.
     * @since 0.1.0
     */
		bool isTabbingEnabled() const;
	/**
	 * @return A reference to the stack of flagged widget.
	 * only needed if the user is deleting them.
     * @since 0.1.0
     */
		std::stack<Widget*>& getFlaggedWidgets();
	/**
	 * Called by a widget when it wants to be flagged for destruction.
     * @since 0.1.0
     */
		void flagWidget(Widget *widget);
	/**
	 * Destroys the flagged widgets.
     * @since 0.1.0
     */
		void destroyFlaggedWidgets();
	/**
	 * Sets the tab next key. Default is KEY_TAB.
     * @since 0.1.0
     */
		virtual void setTabNextKey(KeyEnum key,
			ExtendedKeyEnum extKey = EXT_KEY_NONE,
			bool shift = false,
			bool control = false, 
			bool alt = false);
	/**
	 * Sets the tab previous key. Default is KEY_TAB + control.
     * @since 0.1.0
     */
		virtual void setTabPreviousKey(KeyEnum key,
			ExtendedKeyEnum extKey = EXT_KEY_NONE,
			bool shift = false,
			bool control = false,
			bool alt = false);
	/**
	 * Sets how long the mouse must be over a widget without moving for the widget to receive a hover event in seconds.
     * @since 0.1.0
     */
		void setHoverInterval(double time);
		/**
	 * @return How long the mouse must be over a widget without moving for the widget to receive a hover event in seconds.
     * @since 0.1.0
     */
		double getHoverInterval() const;
	/**
	 * @return How long after a first click will a second click result in a double click event in seconds.
     * @since 0.1.0
     */
		double getDoubleClickInterval() const;
	/**
	 * Sets how long after a first click will a second click result in a double click event in seconds.
     * @since 0.1.0
     */
		void setDoubleClickInterval(double time);
	/**
	 * Resizes the Top widget to the size of the display. Needs the graphics context to be set.
     * @since 0.1.0
     */
		void resizeToDisplay();
	/**
	 * Adds the parameter widget to the desktop if it has no parent.
     * @since 0.1.0
     */
		void add(Widget* widget);
	/**
	 * Removes the parameter widget from the desktop if it is on the desktop.
     * @since 0.1.0
     */
		void remove(Widget* widget);
	/**
	 * @return True if the parameter widget exists.
     * @since 0.1.0
     */
		bool widgetExists(Widget* target);
	/**
	 * Should be called every time your game loop updates.
	 *
	 * It will poll the Input, dequeue all queued mouse and keyboard events, and
	 * call Widget::logic on every widget in the Gui.
     * @since 0.1.0
     */
		virtual void logic();

	/**
	 * Adds a key preview listener. If a key preview listener handles the event, the focused widget will not receive it.
     * @since 0.1.0
     */
		void addKeyPreviewListener(KeyboardListener* listener);
	/**
	 * Removes a key preview listener. If a key preview listener handles the event, the focused widget will not receive it.
     * @since 0.1.0
     */
		void removeKeyPreviewListener( KeyboardListener* listener );
	/**
	 * Adds a mouse preview listener. If a mouse preview listener handles the event, the intended widget will not receive it.
     * @since 0.2.0
     */
		void addMousePreviewListener(MouseListener* listener);
	/**
	 * Removes a mouse preview listener. If a mouse preview listener handles the event, the intended widget will not receive it.
     * @since 0.2.0
     */
       void removeMousePreviewListener( MouseListener* listener );
    /**
    * Adds a tap listener.
    * @since 0.2.1
    */
       void addTapListener(TapListener* listener);
    /**
    * Removes a tap listener.
    * @since 0.2.1
    */
       void removeTapListener( TapListener* listener );
        
	/**
	 * @return The amount of time in seconds the application has been running.
	 *
	 * Useful for timed events.
     * @since 0.1.0
     */
        double getElapsedTime() const;
	/**
	 * Default constructor.
     * @since 0.1.0
     */
		Gui(void);
	/**
	 * Will paint every widget in the Gui and their children.
	 * 
	 * Call this each time you render.
     * @since 0.1.0
     */
		void render();
	 /**
	 * Set the graphics context for the Gui. Will resize the Gui to the display size.
     * @since 0.1.0
     */
		void setGraphics(Graphics *context);
	/**
	 * Set the input for the Gui. Will resize the Gui to the display size.
     * @since 0.1.0
     */
		void setInput(Input* input);
	/**
	 * Set the size of the desktop. Call this when your display resizes.
     * @since 0.1.0
     */
		void setSize(int width, int height);
	/**
	 * @return The top most, desktop widget of the Gui. Every widget in the Gui is a child of this.
     * @since 0.1.0
     */
		TopContainer* getTop() const;

	/**
	 * Set the ToolTip used when showing ToolTip text.
     * @since 0.2.0
     */
		void setToolTip(ToolTip* toolTip);
	/**
	 * @return The ToolTip used if it is set.
     * @since 0.2.0
     */
		ToolTip* getToolTip() const;

	/**
	 * Shows the ToolTip for the specified Widget.
     * @since 0.2.0
     */
		void showToolTip(Widget* widget, int x, int y);

		/**
	 * @return True if the tooltip is showing.
     * @since 0.2.0
     */
		bool isToolTipVisible() const;

	/**
	 * Hides the ToolTip.
     * @since 0.2.0
     */
		void hideToolTip();

		/**
	 * Set the maximum width used when showing the ToolTip.
	 * The width can be <= 0 to autosize. If the text is less
	 * than this maximum, the ToolTip's width will be the minimum
	 * needed to show the text correctly.
     * @since 0.2.0
     */
		void setMaxToolTipWidth(int width);
	/**
	 * @return The maximum width of the ToolTip.
     * @since 0.2.0
     */
		int getMaxToolTipWidth() const;

		/**
	 * Set whether or not widget exist checks will be made
	 * when a mouse event occurs. Disable for speedup.
     * @since 0.2.0
     */
		void setExistanceCheck(bool check);
	/**
	* @return True if widget exist checks will be made
	* when a mouse event occurs. Disable for speedup.
     * @since 0.2.0
     */
		int isDoingExistanceCheck() const;

		/**
	 * @return The maximum amount of time a ToolTip will show for.
     * @since 0.2.0
     */

		double getToolTipShowLength() const;
	/**
	 * @Set the maximum amount of time a ToolTip will show for.
     * @since 0.2.0
     */
		void setToolTipShowLength(double val);

			/**
	 * Invalidates the tooltip time.
     * @since 0.2.0
     */
		void invalidateToolTip();

		
	/**
	 * @Set the backend specific cursor provider.
     * @since 0.2.0
     */
		void setCursorProvider(CursorProvider* provider);

	/**
	 * @Set the transform to use on the mouse.
	 * @See setUseTransform
     * @since 0.2.0
     */
		void setTransform(const Transform& transform);

	/**
	 * @Return the transform to use on the mouse.
	 * @See setUseTransform
     * @since 0.2.0
     */
		const Transform& getTransform() const;

			/**
	 * @Set whether or not to use a transformation on the mouse coordinates.
     * @since 0.2.0
     */
		void setUseTransform(bool use);

	/**
	 * @Return true if the transform is used on the mouse.
     * @since 0.2.0
     */
		bool isUsingTransform() const;
        
   /**
   * @Set whether or not to use a transformation on the mouse coordinates.
   * @since 0.2.0
   */
   void setFocusEnabled(bool enabled);
        
   /**
   * @Return true if focus events are enabled.
   * @since 0.2.0
   */
    bool isFocusEnabled() const;

					/**
	 * @Set whether or not the mouse down events are delayed by 1 logic() update.
	 * Fixes a small issue on touch pads when enabled.
     * @since 0.2.0
     */
		void setDelayMouseDownEvents(bool delay);

	/**
	 * @Return true if the mouse down events are delayed by 1 logic() update.
     * @since 0.2.0
     */
		bool isDelayingMouseDownEvents() const;

		
	/**
	 * @Return false if the widget under mouse is the top or NULL.
     * @since 0.2.0
     */
		bool isWidgetUnderMouse() const;



	
	/**
	 * @return True if the cursor provider is set and it successfully set the cursor
     * @since 0.2.0
     */

		bool setCursor(CursorProvider::CursorEnum cursor);

		/**
	 * @return The widget with drag focus or NULL
     * @since 0.2.0
     */

		Widget* getLockWidget();

			/**
     * Allows you to manually null the Widget under the mouse.
     * @since 0.2.1
     */
		void setWidgetUnderMouseToNull();

	/**
     * @return True if widget location changes are tracked accurately.
     * @since 0.2.1
     */
		bool isWidgetLocationChangesEnabled() const;

	/**
     * @return The Input set for this Gui.
     * @since 0.2.1
     */
		Input* getInput();

	/**
     * @return The Graphics set for this Gui.
     * @since 0.2.1
     */
		Graphics* getGraphics();

	/**
     * Teleport the mouse position of this Gui. Forces a logic call.
     * @since 0.2.1
     */
		void teleportMouse(int x, int y);

			/**
	 * Sets whether or not the expensive call to check if the widget
	 * under the mouse changed when widgets resize, move etc is called.
     * @since 0.2.0
     */

		void toggleWidgetLocationChanged(bool on);


		void bringWidgetToFront(Widget* w);
		void sendWidgetToBack(Widget* w);
	/**
	 * Default destructor.
     * @since 0.1.0
     */
		virtual ~Gui(void);
	};
}
#endif
