#include "settingsdialog.h"
#include "ui_settingsDialog.h"
#include "rgatState.h"
#include "qlayout.h"

settingsDialogWidget::settingsDialogWidget(QWidget *parent)
	: QWidget(parent)
{

}



settingsDialogWidget::~settingsDialogWidget()
{
}

void settingsDialogWidget::initialiseWidgetPtrs()
{
	Ui::SettingsWindow *setsUI = (Ui::SettingsWindow *)this->settingsUIPtr;
	colourWidgets[confNS::widgID::eTraceBackground] = setsUI->bg_tracecol;
	colourWidgets[confNS::widgID::eTraceEdgeCall] = setsUI->calledge_tracecol;
	colourWidgets[confNS::widgID::eTraceEdgeRet] = setsUI->retedge_tracecol;
	colourWidgets[confNS::widgID::eTraceEdgeOld] = setsUI->oldedge_tracecol;
	colourWidgets[confNS::widgID::eTraceEdgeNew] = setsUI->newedge_tracecol;
	colourWidgets[confNS::widgID::eTraceEdgeUnins] = setsUI->uninsedge_tracecol;
	colourWidgets[confNS::widgID::eTraceEdgeEx] = setsUI->exedge_tracecol;
	colourWidgets[confNS::widgID::eTraceNodeJump] = setsUI->jumpnode_tracecol;
	colourWidgets[confNS::widgID::eTraceNodeRet] = setsUI->retnode_tracecol;
	colourWidgets[confNS::widgID::eTraceNodeSeq] = setsUI->seqnode_tracecol;
	colourWidgets[confNS::widgID::eTraceNodeCall] = setsUI->callnode_tracecol;
	colourWidgets[confNS::widgID::eTraceNodeUnins] = setsUI->uninsnode_tracecol;
	colourWidgets[confNS::widgID::eTraceHighline] = setsUI->highlightline_tracecol;
	colourWidgets[confNS::widgID::eTraceActivLine] = setsUI->activline_tracecol;
}

void settingsDialogWidget::connectWidgets()
{
	initialiseWidgetPtrs();

	for (auto widgetsIt = colourWidgets.begin(); widgetsIt != colourWidgets.end(); widgetsIt++)
	{
		confNS::widgID clickID = widgetsIt->first;
		connect(widgetsIt->second, &colorDemoWidget::mousePressEvent, this, [this, clickID]{ colourClick(clickID); });
	}
	
	setCurrentColours();
	

}

void settingsDialogWidget::setCurrentColours()
{
	Ui::SettingsWindow *settingsUI = (Ui::SettingsWindow *)this->settingsUIPtr;
	clientConfig *config = &((rgatState *)clientState)->config;

	colourSet(confNS::widgID::eTraceBackground, config->mainColours.background);
	colourSet(confNS::widgID::eTraceActivLine, config->mainColours.activityLine);
	colourSet(confNS::widgID::eTraceHighline, config->mainColours.highlightLine);
}

void settingsDialogWidget::colourSet(confNS::widgID clickID, QColor col)
{
	Ui::SettingsWindow *settingsUI = (Ui::SettingsWindow *)this->settingsUIPtr;

	QString chosenColSS = "background:" + col.name();
	switch (clickID)
	{
	case confNS::widgID::eTraceBackground:
		//set the background containing all the colour demo widgets
		settingsUI->traceColoursFrame->setStyleSheet(chosenColSS);

		//set the demo widget itself, with a border
		colourWidgets.at(clickID)->setStyleSheet(chosenColSS + "; border: 2px dotted grey");
		break;

	default:
		colourWidgets.at(clickID)->setStyleSheet(chosenColSS);
	}
}

void settingsDialogWidget::colourClick(confNS::widgID clickID)
{
	QColorDialog colorDlg(this);
	QColor col = colorDlg.getColor();
	colourSet(clickID, col);
	


}