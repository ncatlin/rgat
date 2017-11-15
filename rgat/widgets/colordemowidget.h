#pragma once

#include "qwidget.h"

class colorDemoWidget : public QWidget
{
	Q_OBJECT

public:
	colorDemoWidget(QWidget *parent);
	~colorDemoWidget();

signals:
	void mousePressEvent(QMouseEvent *event) override;
};
