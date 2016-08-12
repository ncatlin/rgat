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

#include "Agui/BorderLayout.hpp"

namespace agui
{
	BorderLayout::BorderLayout(void)
		: north(NULL),south(NULL),
		east(NULL), west(NULL), center(NULL),
		northMargin(20),southMargin(20),
		eastMargin(20),westMargin(20),
		horizontalSpacing(5),verticalSpacing(5)
	{
	}

	BorderLayout::~BorderLayout(void)
	{
	}

	bool BorderLayout::isWidgetSet( BorderLayoutEnum which ) const
	{
		switch (which)
		{
		case NORTH:
			return north != NULL;
			break;
		case SOUTH:
			return south != NULL;
			break;
		case EAST:
			return east != NULL;
			break;
		case WEST:
			return west != NULL;
			break;
		case CENTER:
			return center != NULL;
			break;
		}
		return false;
	}

	void BorderLayout::setBorderMargin( BorderLayoutEnum which, int margin )
	{
		if(margin < 0)
		{
			margin = 0;
		}

		switch (which)
		{
		case NORTH:
			northMargin = margin;
			break;
		case SOUTH:
			southMargin = margin;
			break;
		case EAST:
			eastMargin = margin;
			break;
		case WEST:
			westMargin = margin;
			break;
		case CENTER:
			break;
		}

		updateLayout();
	}

	void BorderLayout::setBorderMargins( 
		int north, int south, int east, int west )
	{
		if(north < 0)
		{
			north = 0;
		}

		if(south < 0)
		{
			south = 0;
		}

		if(east < 0)
		{
			east = 0;
		}

		if(west < 0)
		{
			west = 0;
		}

		northMargin = north;
		southMargin = south;
		eastMargin = east;
		westMargin = west;

		updateLayout();
	}

	int BorderLayout::getBorderMargin( BorderLayoutEnum which ) const
	{
		switch (which)
		{
		case NORTH:
			return northMargin;
			break;
		case SOUTH:
			return southMargin;
			break;
		case EAST:
			return eastMargin;
			break;
		case WEST:
			return westMargin;
			break;
		case CENTER:
			return 0;
			break;
		}
		return 0;
	}

	void BorderLayout::add( Widget* widget )
	{
		if(!widget)
		{
			return;
		}

		if(!isWidgetSet(NORTH))
		{
			north = widget;
			if(getBorderMargin(NORTH) < widget->getHeight())
				setBorderMargin(NORTH,widget->getHeight());
		}
		else if(!isWidgetSet(SOUTH))
		{
			south = widget;
			if(getBorderMargin(SOUTH) < widget->getHeight())
				setBorderMargin(SOUTH,widget->getHeight());
		}
		else if(!isWidgetSet(EAST))
		{
			east = widget;
			if(getBorderMargin(EAST) < widget->getWidth())
				setBorderMargin(EAST,widget->getWidth());
		}
		else if(!isWidgetSet(WEST))
		{
			west = widget;
			if(getBorderMargin(WEST) < widget->getWidth())
				setBorderMargin(WEST,widget->getWidth());
		}
		else if(!isWidgetSet(CENTER))
		{
			center = widget;
		}
		else
		{
			return;
		}
		Layout::add(widget);
	}

	void BorderLayout::add( Widget* widget, BorderLayoutEnum which )
	{
		if(isWidgetSet(which))
		{
			return;
		}
		else
		{
			if(which == NORTH)
			{
				north = widget;
				if(getBorderMargin(NORTH) < widget->getHeight())
					setBorderMargin(NORTH,widget->getHeight());
			}
			else if(which == SOUTH)
			{
				south = widget;
				if(getBorderMargin(SOUTH) < widget->getHeight())
					setBorderMargin(SOUTH,widget->getHeight());
			}
			else if(which == EAST)
			{
				east = widget;
				if(getBorderMargin(EAST) < widget->getWidth())
					setBorderMargin(EAST,widget->getWidth());
			}
			else if(which == WEST)
			{
				west = widget;
				if(getBorderMargin(WEST) < widget->getWidth())
					setBorderMargin(WEST,widget->getWidth());
			}
			else if(which == CENTER)
			{
				center = widget;
			}

			Layout::add(widget);
		}
	}

	void BorderLayout::remove( Widget* widget )
	{
		if(widget == north)
		{
			north = NULL;
		}
		else if(widget == south)
		{
			south = NULL;
		}
		else if(widget == east)
		{
			east = NULL;
		}
		else if(widget == west)
		{
			west = NULL;
		}
		else if(widget == center)
		{
			center = NULL;
		}

		Layout::remove(widget);
	}

	void BorderLayout::setHorizontalSpacing( int spacing )
	{
		horizontalSpacing = spacing;
		updateLayout();
	}

	void BorderLayout::setVerticalSpacing( int spacing )
	{
		verticalSpacing = spacing;
		updateLayout();
	}

	int BorderLayout::getHorizontalSpacing() const
	{
		return horizontalSpacing;
	}

	int BorderLayout::getVerticalSpacing() const
	{
		return verticalSpacing;
	}

	void BorderLayout::layoutChildren()
	{
		//Layout is like this:
				/*
				  N
				W C E
				  S
				*/

		//layout north
		
		int northMargin = this->northMargin;
		int southMargin = this->southMargin;
		int eastMargin = this->eastMargin;
		int westMargin = this->westMargin;

		bool isNorth = north && north->isVisible();
		bool isSouth = south && south->isVisible();
		bool isEast =  east && east->isVisible();
		bool isWest =  west && west->isVisible();
		bool isCenter = center  && center->isVisible();

		if(isNorth)
		{
			if(northMargin < north->getMinSize().getHeight() && north->getMinSize().getHeight() > 0)
			{
				northMargin = north->getMinSize().getHeight();
			}

			if(northMargin > north->getMaxSize().getHeight() && north->getMaxSize().getHeight() > 0)
			{
				northMargin = north->getMaxSize().getHeight();
			}
			north->setLocation(0,0);
			north->setSize(getInnerWidth(),northMargin);
		}

		//layout south
		if(isSouth)
		{
			if(southMargin < south->getMinSize().getHeight() && south->getMinSize().getHeight() > 0)
			{
				southMargin = south->getMinSize().getHeight();
			}

			if(southMargin > south->getMaxSize().getHeight() && south->getMaxSize().getHeight() > 0)
			{
				southMargin = south->getMaxSize().getHeight();
			}

			south->setLocation(0,getInnerHeight() - southMargin);
			south->setSize(getInnerWidth(),southMargin);
		}

		//figure out gaps
		int vGapNorth = 0;
		int vGapSouth = 0;
		if(isNorth)
		{
			vGapNorth = northMargin + verticalSpacing;
		}
		if(isSouth)
		{
			vGapSouth = southMargin + verticalSpacing;
		}

		//layout west
		if(isWest)
		{
			if(westMargin < west->getMinSize().getWidth() && west->getMinSize().getWidth() > 0)
			{
				westMargin = west->getMinSize().getWidth();
			}

			if(westMargin > west->getMaxSize().getWidth() && west->getMaxSize().getWidth() > 0)
			{
				westMargin = west->getMaxSize().getHeight();
			}

			west->setLocation(0,vGapNorth);
			west->setSize(westMargin,
				getInnerHeight() - 
				vGapNorth - vGapSouth);
		}

		//layout east
		if(isEast)
		{
			if(eastMargin < east->getMinSize().getWidth() && east->getMinSize().getWidth() > 0)
			{
				eastMargin = east->getMinSize().getWidth();
			}

			if(eastMargin > east->getMaxSize().getWidth() && east->getMaxSize().getWidth() > 0)
			{
				eastMargin = east->getMaxSize().getHeight();
			}

			east->setLocation(getInnerWidth() - eastMargin,vGapNorth);
			east->setSize(eastMargin,
				getInnerHeight() - 
				vGapNorth - vGapSouth);
		}

		int hGapWest = 0;
		int hGapEast = 0;
		if(isWest)
		{
			hGapWest = westMargin + horizontalSpacing;
		}

		if(isEast)
		{
			hGapEast = eastMargin + horizontalSpacing;
		}

		//layout center
		if(isCenter)
		{
			center->setLocation(hGapWest,vGapNorth);
			center->setSize(getInnerWidth() - hGapWest - hGapEast,
				getInnerHeight() - vGapNorth - vGapSouth);
		}

	}

	Widget* BorderLayout::getWidget( BorderLayoutEnum which )
	{
		if(which == NORTH)
		{
			return north;
		}
		else if(which == SOUTH)
		{
			return south;
		}
		else if(which == EAST)
		{
			return east;
		}
		else if(which == WEST)
		{
			return west;
		}
		else if(which == CENTER)
		{
			return center;
		}
		else
		{
			return NULL;
		}
	}

}
