#pragma once

#include "qwidget.h"
#include "colordemowidget.h"
#include "rgatState.h"

enum eSettingsWidget { traceColBackground, traceColHighline, traceColActivLine,
		traceColEdgeCall, traceColEdgeRet, traceColEdgeNew, traceColEdgeOld, traceColEdgeUnins, traceColEdgeEx,
		traceColNodeSeq, traceColNodeJump, traceColNodeCall, traceColNodeRet, traceColNodeUnins,
		traceColInsText, traceColExtSymbol, traceColExtRising, traceColIntSymbol, traceColIntRising, 
		heatColBackground, heatColHeat1, heatColHeat2, heatColHeat3, heatColHeat4, heatColHeat5, heatColHeat6,
		heatColHeat7, heatColHeat8, heatColHeat9, heatColHeat10, heatText, heatHighlight,
		condColBackground, condColEdge, condColTrue, condColFalse, condColBoth,
		previewColBackground, previewColActive, previewColInactive
};

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
	void colourClick(eSettingsWidget clickID);
	void pageSelected(QTreeWidgetItem *item);

private:
	void initialiseWidgets();
	void setCurrentColours();
	void colourSet(eSettingsWidget clickID, QColor col); 
	void setColoursFromConfig(); 
	void setStackIndexes();

private:
	map <eSettingsWidget, colorDemoWidget *> colourWidgets;
};

