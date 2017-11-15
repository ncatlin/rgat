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

void settingsDialogWidget::initialiseWidgets()
{
	Ui::SettingsWindow *setsUI = (Ui::SettingsWindow *)this->settingsUIPtr;
	colourWidgets[confNS::widgID::traceColBackground] = setsUI->bg_tracecol;
	colourWidgets[confNS::widgID::traceColEdgeCall] = setsUI->calledge_tracecol;
	colourWidgets[confNS::widgID::traceColEdgeRet] = setsUI->retedge_tracecol;
	colourWidgets[confNS::widgID::traceColEdgeOld] = setsUI->oldedge_tracecol;
	colourWidgets[confNS::widgID::traceColEdgeNew] = setsUI->newedge_tracecol;
	colourWidgets[confNS::widgID::traceColEdgeUnins] = setsUI->uninsedge_tracecol;
	colourWidgets[confNS::widgID::traceColEdgeEx] = setsUI->exedge_tracecol;
	colourWidgets[confNS::widgID::traceColNodeJump] = setsUI->jumpnode_tracecol;
	colourWidgets[confNS::widgID::traceColNodeRet] = setsUI->retnode_tracecol;
	colourWidgets[confNS::widgID::traceColNodeSeq] = setsUI->seqnode_tracecol;
	colourWidgets[confNS::widgID::traceColNodeCall] = setsUI->callnode_tracecol;
	colourWidgets[confNS::widgID::traceColNodeUnins] = setsUI->uninsnode_tracecol;
	colourWidgets[confNS::widgID::traceColHighline] = setsUI->highlightline_tracecol;
	colourWidgets[confNS::widgID::traceColActivLine] = setsUI->activline_tracecol;

	colourWidgets[confNS::widgID::traceColInsText] = setsUI->instext_tracecol;
	setsUI->instext_tracecol->setLabelMode("inc eax; dec ebx; div ecx; pop; pop; ret;");
	
	colourWidgets[confNS::widgID::traceColExtSymbol] = setsUI->extsym_tracecol;
	setsUI->extsym_tracecol->setLabelMode("VirtualProtect(X, Y, PAGE_EXECUTE_READWRITE, Z)");

	colourWidgets[confNS::widgID::traceColExtRising] = setsUI->extsymrising_tracecol;
	setsUI->extsymrising_tracecol->setLabelMode("VirtualProtect(X, Y, PAGE_EXECUTE_READWRITE, Z)");

	colourWidgets[confNS::widgID::traceColIntSymbol] = setsUI->intsym_tracecol;
	setsUI->intsym_tracecol->setLabelMode("VirtualProtect(X, Y, PAGE_EXECUTE_READWRITE, Z)");

	colourWidgets[confNS::widgID::traceColIntRising] = setsUI->intsymrising_tracecol;
	setsUI->intsymrising_tracecol->setLabelMode("VirtualProtect(X, Y, PAGE_EXECUTE_READWRITE, Z)");
}

void settingsDialogWidget::connectWidgets()
{
	initialiseWidgets();

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

	colourSet(confNS::widgID::traceColBackground, config->mainColours.background);
	colourSet(confNS::widgID::traceColActivLine, config->mainColours.activityLine);
	colourSet(confNS::widgID::traceColHighline, config->mainColours.highlightLine);

	colourSet(confNS::widgID::traceColEdgeCall, config->graphColours.at(eEdgeNodeType::eEdgeCall));
	colourSet(confNS::widgID::traceColEdgeRet, config->graphColours.at(eEdgeNodeType::eEdgeReturn));
	colourSet(confNS::widgID::traceColEdgeNew, config->graphColours.at(eEdgeNodeType::eEdgeNew));
	colourSet(confNS::widgID::traceColEdgeOld, config->graphColours.at(eEdgeNodeType::eEdgeOld));
	colourSet(confNS::widgID::traceColEdgeEx, config->graphColours.at(eEdgeNodeType::eEdgeException));
	colourSet(confNS::widgID::traceColEdgeUnins, config->graphColours.at(eEdgeNodeType::eEdgeLib));

	colourSet(confNS::widgID::traceColNodeCall, config->graphColours.at(eEdgeNodeType::eNodeCall));
	colourSet(confNS::widgID::traceColNodeJump, config->graphColours.at(eEdgeNodeType::eNodeJump));
	colourSet(confNS::widgID::traceColNodeRet, config->graphColours.at(eEdgeNodeType::eNodeReturn));
	colourSet(confNS::widgID::traceColNodeSeq, config->graphColours.at(eEdgeNodeType::eNodeNonFlow));
	colourSet(confNS::widgID::traceColNodeUnins, config->graphColours.at(eEdgeNodeType::eNodeExternal));


	colourSet(confNS::widgID::traceColInsText, config->mainColours.instructionText);
	colourSet(confNS::widgID::traceColExtSymbol, config->mainColours.symbolTextExternal);
	colourSet(confNS::widgID::traceColExtRising, config->mainColours.symbolTextExternalRising);
	colourSet(confNS::widgID::traceColIntSymbol, config->mainColours.symbolTextInternal);
	colourSet(confNS::widgID::traceColIntRising, config->mainColours.symbolTextInternalRising);
	
}

void settingsDialogWidget::colourSet(confNS::widgID clickID, QColor col)
{
	Ui::SettingsWindow *settingsUI = (Ui::SettingsWindow *)this->settingsUIPtr;


	switch (clickID)
	{
		case confNS::widgID::traceColBackground:
		{
		QString chosenColSS = "background: " + col.name();
		//set the background containing all the colour demo widgets
		settingsUI->traceColoursFrame->setStyleSheet(chosenColSS);
		
		//set the demo widget itself, with a border
		colourWidgets.at(clickID)->setStyleSheet(chosenColSS + "; border: 2px dotted grey");
		break;
		}

		default:
			colourWidgets.at(clickID)->setColour(col);
	}
}

void settingsDialogWidget::colourClick(confNS::widgID clickID)
{
	QColorDialog colorDlg(this);
	QColor col = colorDlg.getColor();
	colourSet(clickID, col);
	


}