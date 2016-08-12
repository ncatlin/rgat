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

#ifndef AGUI_SLIDER_HPP
#define AGUI_SLIDER_HPP

#include "Agui/Widget.hpp"
#include "Agui/Widgets/Button/Button.hpp"
#include "Agui/Widgets/Slider/SliderListener.hpp"
namespace agui {
		/**
	 * Class that represents a Slider that can be set vertically or horizontally.
	 *
	 * ActionEvent when:
	 *
	 * Slider value changes.
	 *
	 * Optional constructor widget:
	 *
	 * Widget (Marker)
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC Slider : public Widget, 
		protected MouseListener
	{
	private:
		OrientationEnum orientation;
		float centerRatio;
		int value;
		int min;
		int max;
		int change;

		Widget *pChildMarker;
		bool isMaintainingMarker;
		std::vector<SliderListener*> sliderListeners;
	protected:
		virtual void mouseDragCB(MouseEvent &mouseEvent);
		virtual void mouseDownCB(MouseEvent &mouseEvent);
	/**
     * Positions the marker given a value.
     * @since 0.1.0
     */
		virtual void positionMarker(int value);
		virtual void paintComponent(const PaintEvent &paintEvent);
		virtual void paintBackground(const PaintEvent &paintEvent);
	/**
     * Left / Right or Up / Down arrow keys move the slider.
     * @since 0.1.0
     */
		virtual void handleKeyboard(KeyEvent &keyEvent);

	public:
	/**
     * Sets whether the marker is more toward one side than the other, default is balanced (0.5f).
     * @since 0.1.0
     */
		void setCenterRatio(float ratio);
	/**
     * @return How much the marker is more toward one side than the other, default is balanced (0.5f).
     * @since 0.1.0
     */
		float getCenterRatio() const;
	/**
     * @return a value from 0.0f to 1.0f which indicates the percent the slider marker is along the slider.
     * @since 0.1.0
     */
		virtual float getPercentage() const;
	/**
     * Adds the parameter SliderListener.
     * @since 0.1.0
     */
		virtual void addSliderListener(SliderListener *listener);
	/**
     * Removes the parameter SliderListener.
     * @since 0.1.0
     */
		virtual void removeSliderListener(SliderListener *listener);
		virtual void keyDown(KeyEvent &keyEvent);
		virtual void keyRepeat(KeyEvent &keyEvent);
		virtual void mouseDown(MouseEvent &mouseEvent);
		virtual void mouseWheelDown(MouseEvent &mouseEvent);
		virtual void mouseWheelDownCB(MouseEvent &mouseEvent);
		virtual void mouseWheelUp(MouseEvent &mouseEvent);
		virtual void mouseWheelUpCB(MouseEvent &mouseEvent);
		virtual void setSize(int width, int height);
		virtual void setSize(const Dimension &size);
	/**
     * @return Given a value on the slider, returns the position of the marker.
     * @since 0.1.0
     */
		virtual int valueToPosition(int value) const;
	/**
     * @return Given a position, returns the value on the slider.
     * @since 0.1.0
     */
		virtual int positionToValue(int position) const;
	/**
     * Sets the length (in values) the slider moves in a key press and mouse wheel event.
     * @since 0.1.0
     */
		virtual void setStepLength(int length);
	/**
     * @return The length (in values) the slider moves in a key press and mouse wheel event.
     * @since 0.1.0
     */
		virtual int getStepLength() const;
	/**
     * @return The size of the marker.
     * @since 0.1.0
     */
		virtual const Dimension& getMarkerSize() const;
	/**
     * Sets the size of the marker.
     * @since 0.1.0
     */
		virtual void setMarkerSize(const Dimension &size);
	/**
     * Sets the orientation of the slider.
     * @since 0.1.0
     */
		void setOrientation(OrientationEnum orientation);
	/**
     * @return The orientation of the slider.
     * @since 0.1.0
     */
		OrientationEnum getOrientation() const;
	 /**
     * @return Maximum value - minimum value.
     * @since 0.1.0
     */
		int getRange() const;
	/**
     * @return The minimum value of the slider.
     * @since 0.1.0
     */
		int getMinValue() const;
	/**
     * @return The maximum value of the slider.
     * @since 0.1.0
     */
		int getMaxValue() const;
	/**
     * Sets the minimum value of the slider.
     * @since 0.1.0
     */
		void setMinValue(int val);
	/**
     * Sets the maximum value of the slider.
     * @since 0.1.0
     */
		void setMaxValue(int val);
	/**
     * @return The current value of the slider.
     * @since 0.1.0
     */
		int getValue() const;
	/**
     * Sets the current value of the slider.
     * @since 0.1.0
     */
		void setValue(int val);

	/**
     * Construct with optional marker Widget.
     * @since 0.1.0
     */
		Slider(Widget *marker = NULL);
	/**
     * Default destructor.
     * @since 0.1.0
     */
		virtual ~Slider(void);
	};
}
#endif
