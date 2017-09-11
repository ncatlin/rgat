#pragma once
#include "qframe.h"

class mouseoverFrame :
	public QFrame
{
	Q_OBJECT
public:
	mouseoverFrame(QWidget *parent = 0);
	~mouseoverFrame();

	void *clientState = NULL;
	
public Q_SLOTS:
	void changedLabel();

};

