#pragma once

#include "qwidget.h"
#include "colordemowidget.h"
#include "rgatState.h"

enum eSettingsWidget { traceColBackground, traceColActivLine,
		traceColEdgeCall, traceColEdgeRet, traceColEdgeNew, traceColEdgeOld, traceColEdgeUnins, traceColEdgeEx,
		traceColNodeSeq, traceColNodeJump, traceColNodeCall, traceColNodeRet, traceColNodeUnins,
		traceColInsText, traceColExtSymbol, traceColExtRising, traceColIntSymbol, traceColIntRising, traceColPlaceholder,
		heatColBackground, heatColHeat1, heatColHeat2, heatColHeat3, heatColHeat4, heatColHeat5, heatColHeat6,
		heatColHeat7, heatColHeat8, heatColHeat9, heatColHeat10, heatText,
		condColBackground, condColEdge, condColTrue, condColFalse, condColBoth,
		previewColBackground, previewColActive, previewColInactive
};

enum eStackPages {
	eInvalid = -1, eRenderTracePage = 0, eRenderHeatmapPage = 1, eRenderConditionalsPage = 2, eRenderPreviewPage = 3,
	eGraphSettingsPage = 4, ePreviewSettingsPage = 5, eInstrumentationSettingsPage = 6
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
	void previewSliderChanged(int newValue);
	void setPreviewRotationEnabled(bool newState);

private:
	void initialiseWidgets();
	void setCurrentColours();
	void colourSet(eSettingsWidget clickID, QColor col); 
	void setColoursFromConfig(); 
	void setStackIndexes();
	void updateColourSetting(eSettingsWidget clickID, QColor col); 
	eStackPages menuTitleToStackIndex(QString title);
	void setSettingsChildren(QTreeWidgetItem* item);

private:
	map <eSettingsWidget, colorDemoWidget *> colourWidgets;
};

