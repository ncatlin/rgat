#pragma once

#include "qwidget.h"
#include "colordemowidget.h"
#include "rgatState.h"

namespace confNS {
	enum widgID { traceColBackground, traceColHighline, traceColActivLine,
		traceColEdgeCall, traceColEdgeRet, traceColEdgeNew, traceColEdgeOld, traceColEdgeUnins, traceColEdgeEx,
		traceColNodeSeq, traceColNodeJump, traceColNodeCall, traceColNodeRet, traceColNodeUnins,
		traceColInsText, traceColExtSymbol, traceColExtRising, traceColIntSymbol, traceColIntRising	};
}

class settingsDialogWidget :
	public QWidget
{
	Q_OBJECT
public:
	settingsDialogWidget(QWidget *parent);
	~settingsDialogWidget();

	//ui refers to this class so have to use void * to avoid circular reference
	void *settingsUIPtr; 
	void connectWidgets();
	void *clientState;

public Q_SLOTS: 
	void colourClick(confNS::widgID clickID);

private:
	void initialiseWidgets();
	void setCurrentColours();
	void colourSet(confNS::widgID clickID, QColor col);

private:
	map <confNS::widgID, colorDemoWidget *> colourWidgets;
};

