#include "colordemowidget.h"
#include <iostream>

colorDemoWidget::colorDemoWidget(QWidget *parent)
	: QWidget(parent)
{
	//have to add a child in a layout to make colour show up
	childlayout = new QGridLayout(this);
	solidBlock = new QWidget(this);
	childlayout->addWidget(solidBlock);
	childlayout->setContentsMargins(0, 0, 0, 0);

	solidBlock->setMinimumSize(QSize(190, 15));
}

colorDemoWidget::~colorDemoWidget()
{
}

void colorDemoWidget::setLabelMode(QString text, bool isbold)
{
	if (childlabel == NULL)
	{
		delete solidBlock;

		childlabel = new QLabel(this);
		childlabel->setAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
		childlabel->setMinimumSize(QSize(190, 15));

		childlayout->addWidget(childlabel);

		if (isbold)
		{
			boldfont = isbold;
			setBold(true);
		}
	}

	childlabel->setText(text);
}

void colorDemoWidget::setBold(bool bold)
{
	if (childlabel)
	{
		QFont font(childlabel->font());
		font.setBold(bold);
		childlabel->setFont(font);
	}
	else
	{
		std::cerr << "Error: attempt to set bold on non-label widget" << std::endl;
	}
}

//set the stylesheet
void colorDemoWidget::setColour(QColor colour)
{

	
	if (childlabel == NULL)
	{
		QString stylesheet = "background:" + colour.name();
		setStyleSheet(stylesheet);
	}
	else
	{
		QString stylesheet = "color:" + colour.name();
		childlabel->setStyleSheet(stylesheet);
	}
	
}