#include "colordemowidget.h"
#include "qlayout.h"
#include <iostream>

colorDemoWidget::colorDemoWidget(QWidget *parent)
	: QWidget(parent)
{
	//have to add a child in a layout to make colour show up
	QGridLayout *boxlayout = new QGridLayout(this);
	QWidget *child = new QWidget(this);
	boxlayout->addWidget(child);
	boxlayout->setContentsMargins(0, 0, 0, 0);

	child->setMinimumSize(QSize(190, 15));
}

colorDemoWidget::~colorDemoWidget()
{
}
