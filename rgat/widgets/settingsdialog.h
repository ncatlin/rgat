#pragma once

#include "qwidget.h"
#include "colordemowidget.h"
#include "rgatState.h"

namespace confNS {
	enum widgID { eTraceBackground, eTraceEdgeCall, eTraceEdgeRet, eTraceEdgeNew, 
		eTraceEdgeOld, eTraceEdgeUnins, eTraceEdgeEx, eTraceNodeSeq,
		eTraceNodeJump, eTraceNodeCall, eTraceNodeRet, eTraceNodeUnins,
		eTraceHighline, eTraceActivLine	};
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
	void initialiseWidgetPtrs();
	void setCurrentColours();
	void colourSet(confNS::widgID clickID, QColor col);

private:
	map <confNS::widgID, colorDemoWidget *> colourWidgets;
};

