#pragma once

#include "qlayout.h"
#include "qlabel.h"
#include "qwidget.h"

class colorDemoWidget : public QWidget
{
	Q_OBJECT
public:
	colorDemoWidget(QWidget *parent);
	~colorDemoWidget();

	void setLabelMode(QString text, bool isbold = false);
	void setBold(bool bold);
	void setColour(QColor colour, bool border = false);
	void setEffectiveHeight(int height);
	QColor getColour() { return myColour; }
signals:
	void mousePressEvent(QMouseEvent *event) override;

private:
private:
	QWidget *solidBlock = NULL;
	QLayout *childlayout = NULL;
	QLabel *childlabel = NULL;

	QColor myColour;
	bool boldfont = false;
};
