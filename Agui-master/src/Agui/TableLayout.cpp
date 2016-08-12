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

#include "Agui/TableLayout.hpp"
#include <math.h>

namespace agui
{
	TableLayout::TableLayout(void)
        :rows(1),columns(1),
         horizontalSpacing(5),verticalSpacing(5)
	{
	}

	TableLayout::~TableLayout(void)
	{
	}

	void TableLayout::layoutChildren()
	{
		//dividing by zero is rather silly...
		//so we won't let it happen!
		if (rows == 0 && columns == 0)
		{
			return;
		}

		int numChildren = 0;
		for (WidgetArray::iterator it = getChildBegin(); 
			it != getChildEnd(); ++it)
		{
            if ((*it)->isVisible() || !isFilteringVisibility())
			{
				numChildren++;
			}
		}

		if (numChildren == 0)
		{
			return;
		}

        int childrenInRow = columns;
        if (columns == 0)
		{
            childrenInRow = (int)ceil((double)numChildren / (double)rows);
		}

        if (childrenInRow <= 0)
		{
            childrenInRow = 1;
		}

		int xCount = 0;
		int yCount = 0;

        std::vector<int> columnWidths;
        columnWidths.resize(this->columns);

        int rowsCount = 0;
        for (WidgetArray::iterator it = getChildBegin();
                it != getChildEnd(); ++it)
		{
            if(!(*it)->isVisible() && isFilteringVisibility())
            {
                continue;
            }

            if (xCount == 0)
                rowsCount++;

            columnWidths[xCount] = std::max(columnWidths[xCount], (*it)->getWidth());

            xCount++;

			//next row
            if(xCount == childrenInRow)
			{
				xCount = 0;
				yCount++;
			}
        }
        rows = rowsCount;

        std::vector<int> rowHeights;
        rowHeights.resize(this->rows);

        xCount = 0;
        yCount = 0;

        for (WidgetArray::iterator it = getChildBegin();
                it != getChildEnd(); ++it)
        {
            if(!(*it)->isVisible() && isFilteringVisibility())
            {
                continue;
            }

            rowHeights[yCount] = std::max(rowHeights[yCount], (*it)->getHeight());

            xCount++;

			//next row
            if(xCount == childrenInRow)
			{
				xCount = 0;
				yCount++;
			}
        }

        int locationX = 0;
        int locationY = 0;

        xCount = 0;
        yCount = 0;

        for (WidgetArray::iterator it = getChildBegin();
			it != getChildEnd(); ++it)
		{
			if (!(*it)->isVisible() && isFilteringVisibility())
			{
				continue;
			}

            //linearly solve for the locations and size
            //this ensures that the spacing is respected
            if (xCount != 0)
                locationX += columnWidths[xCount - 1] + this->horizontalSpacing;

            // vertical alignment to center
            (*it)->setLocation(locationX, locationY + (rowHeights[yCount] - (*it)->getHeight()) / 2);

			xCount++;

			//next row
            if (xCount == childrenInRow)
			{
                locationX = 0;
                locationY += rowHeights[yCount] + this->verticalSpacing;
                xCount = 0;
                yCount++;
			}
		}

        int width = 0;
        for (size_t i = 0; i < columnWidths.size(); i++)
            width += columnWidths[i];
        width += (this->columns - 1) * this->horizontalSpacing;

        int height = 0;
        for (size_t i = 0; i < rowHeights.size(); i++)
            height += rowHeights[i];
        height += (this->rows -1) * this->verticalSpacing;

        // called to prevent to recursively call this function as reaction to set size
        Widget::setSize(Dimension(width + getMargin(SIDE_LEFT) + getMargin(SIDE_RIGHT),
                                  height + getMargin(SIDE_TOP) + getMargin(SIDE_BOTTOM)));
	}

	void TableLayout::setNumberOfRows( int rows )
	{
		if(rows < 0)
		{
			rows = 0;
		}

		this->rows = rows;
		updateLayout();
	}

	void TableLayout::setNumberOfColumns( int columns )
	{
		if (columns < 0)
		{
			columns = 0;
		}
		this->columns = columns;
		updateLayout();
	}

	void TableLayout::setHorizontalSpacing( int spacing )
	{
		horizontalSpacing = spacing;
		updateLayout();
	}

	void TableLayout::setVerticalSpacing( int spacing )
	{
		verticalSpacing = spacing;
	}

	int TableLayout::getNumberOfRows() const
	{
		return rows;
	}

	int TableLayout::getNumberOfColumns() const
	{
		return columns;
	}

	int TableLayout::getHorizontalSpacing() const
	{
		return horizontalSpacing;
	}

	int TableLayout::getVerticalSpacing() const
	{
		return verticalSpacing;
	}

    void TableLayout::resizeToContents()
    {
        this->layoutChildren();
    }

}
