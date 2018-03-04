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
	colourWidgets.clear();
}

void settingsDialogWidget::setColoursFromConfig()
{
	Ui::SettingsWindow *setsUI = (Ui::SettingsWindow *)this->settingsUIPtr;

	//main trace display colour settings
	colourWidgets[eSettingsWidget::traceColBackground] = setsUI->bg_tracecol;
	colourWidgets[eSettingsWidget::traceColEdgeCall] = setsUI->calledge_tracecol;
	colourWidgets[eSettingsWidget::traceColEdgeRet] = setsUI->retedge_tracecol;
	colourWidgets[eSettingsWidget::traceColEdgeOld] = setsUI->oldedge_tracecol;
	colourWidgets[eSettingsWidget::traceColEdgeNew] = setsUI->newedge_tracecol;
	colourWidgets[eSettingsWidget::traceColEdgeUnins] = setsUI->uninsedge_tracecol;
	colourWidgets[eSettingsWidget::traceColEdgeEx] = setsUI->exedge_tracecol;
	colourWidgets[eSettingsWidget::traceColNodeJump] = setsUI->jumpnode_tracecol;
	colourWidgets[eSettingsWidget::traceColNodeRet] = setsUI->retnode_tracecol;
	colourWidgets[eSettingsWidget::traceColNodeSeq] = setsUI->seqnode_tracecol;
	colourWidgets[eSettingsWidget::traceColNodeCall] = setsUI->callnode_tracecol;
	colourWidgets[eSettingsWidget::traceColNodeUnins] = setsUI->uninsnode_tracecol;
	colourWidgets[eSettingsWidget::traceColActivLine] = setsUI->activline_tracecol;

	colourWidgets[eSettingsWidget::traceColInsText] = setsUI->instext_tracecol;
	colourWidgets[eSettingsWidget::traceColInsText]->setLabelMode("inc eax; dec ebx; div ecx; pop; pop; ret;");

	QString symbolLabelExample = "VirtualProtect(X, Y, PAGE_EXECUTE_READWRITE, Z)";
	colourWidgets[eSettingsWidget::traceColExtSymbol] = setsUI->extsym_tracecol;
	colourWidgets[eSettingsWidget::traceColExtSymbol]->setLabelMode(symbolLabelExample);

	colourWidgets[eSettingsWidget::traceColExtRising] = setsUI->extsymrising_tracecol;
	colourWidgets[eSettingsWidget::traceColExtRising]->setLabelMode(symbolLabelExample);

	colourWidgets[eSettingsWidget::traceColIntSymbol] = setsUI->intsym_tracecol;
	colourWidgets[eSettingsWidget::traceColIntSymbol]->setLabelMode(symbolLabelExample);

	colourWidgets[eSettingsWidget::traceColPlaceholder] = setsUI->placeholderLabel_tracecol;
	colourWidgets[eSettingsWidget::traceColPlaceholder]->setLabelMode(symbolLabelExample);

	colourWidgets[eSettingsWidget::traceColIntRising] = setsUI->intsymrising_tracecol;
	colourWidgets[eSettingsWidget::traceColIntRising]->setLabelMode(symbolLabelExample);

	//heatmap display colour settings
	colourWidgets[eSettingsWidget::heatColBackground] = setsUI->bg_heatcol;
	
	colourWidgets[eSettingsWidget::heatColHeat1] = setsUI->heat1_heatcol;
	colourWidgets[eSettingsWidget::heatColHeat2] = setsUI->heat2_heatcol;
	colourWidgets[eSettingsWidget::heatColHeat3] = setsUI->heat3_heatcol;
	colourWidgets[eSettingsWidget::heatColHeat4] = setsUI->heat4_heatcol;
	colourWidgets[eSettingsWidget::heatColHeat5] = setsUI->heat5_heatcol;
	colourWidgets[eSettingsWidget::heatColHeat6] = setsUI->heat6_heatcol;
	colourWidgets[eSettingsWidget::heatColHeat7] = setsUI->heat7_heatcol;
	colourWidgets[eSettingsWidget::heatColHeat8] = setsUI->heat8_heatcol;
	colourWidgets[eSettingsWidget::heatColHeat9] = setsUI->heat9_heatcol;
	colourWidgets[eSettingsWidget::heatColHeat10] = setsUI->heat10_heatcol;	
	colourWidgets[eSettingsWidget::heatText] = setsUI->text_heatcol;
	colourWidgets[eSettingsWidget::heatText]->setLabelMode("27182818");
	
	colourWidgets[eSettingsWidget::condColBackground] = setsUI->cond_bg;
	colourWidgets[eSettingsWidget::condColTrue] = setsUI->cond_alwaystrue;
	colourWidgets[eSettingsWidget::condColFalse] = setsUI->cond_nevertrue;
	colourWidgets[eSettingsWidget::condColBoth] = setsUI->cond_bothpaths;
	colourWidgets[eSettingsWidget::condColEdge] = setsUI->cond_edge;

	colourWidgets[eSettingsWidget::previewColBackground] = setsUI->prevcol_background;
	colourWidgets[eSettingsWidget::previewColActive] = setsUI->prevcol_activeborder;
	colourWidgets[eSettingsWidget::previewColInactive] = setsUI->prevcol_inactiveborder;
}

eStackPages settingsDialogWidget::menuTitleToStackIndex(QString title)
{
	if (title == "Trace")
		return eStackPages::eRenderTracePage;
	else if (title == "Heatmap")
		return eStackPages::eRenderHeatmapPage;
	else if (title == "Conditionals")
		return eStackPages::eRenderConditionalsPage;
	else if (title == "Preview")
		return eStackPages::eRenderPreviewPage;
	else if (title == "Graph Display")
		return eStackPages::eGraphSettingsPage;
	else if (title == "Preview Pane")
		return eStackPages::ePreviewSettingsPage;
	else if (title == "Instrumentation")
		return eStackPages::eInstrumentationSettingsPage;
	else if (title == "File Paths")
		return eStackPages::eFilePathsPage;
	else
		return eStackPages::eInvalid;
}


void settingsDialogWidget::setSettingsChildren(QTreeWidgetItem* item)
{

	int childCount = item->childCount();
	if (childCount > 0)
	{
		item->setExpanded(true);
		for (int i = 0; i < childCount; i++)
		{
			setSettingsChildren(item->child(i));
		}
	}

	eStackPages targetPage = menuTitleToStackIndex(item->text(0));
	if (targetPage != eStackPages::eInvalid)
	{
		item->setData(1, Qt::ItemDataRole::UserRole, targetPage);
	}
}


void settingsDialogWidget::setStackIndexes()
{

	Ui::SettingsWindow *settingsUI = (Ui::SettingsWindow *)this->settingsUIPtr;

	int itemCount = settingsUI->settingpageSelectTree->topLevelItemCount();
	for (int i = 0; i < itemCount; i++)
	{
		setSettingsChildren(settingsUI->settingpageSelectTree->topLevelItem(i));
	}
}

void settingsDialogWidget::initialiseWidgets()
{
	Ui::SettingsWindow *settingsUI = (Ui::SettingsWindow *)this->settingsUIPtr;
	clientConfig *config = &((rgatState *)clientState)->config;

	settingsUI->bg_tracecol->setEffectiveHeight(25);
	settingsUI->bg_heatcol->setEffectiveHeight(25);
	settingsUI->cond_bg->setEffectiveHeight(25);

	setColoursFromConfig();
	setStackIndexes();
	setupPathsWidgets();

	settingsUI->showMarkerCheck->setChecked(config->showActiveMarker);
}

void settingsDialogWidget::setupPathsWidgets()
{
	Ui::SettingsWindow *settingsUI = (Ui::SettingsWindow *)this->settingsUIPtr;
	clientConfig *config = &((rgatState *)clientState)->config;

	if (boost::filesystem::exists(config->PinDir))
		settingsUI->pinPathLine->setText(QString::fromStdString(config->PinDir.string()));
	if (boost::filesystem::exists(config->DRDir))
		settingsUI->drPathLine->setText(QString::fromStdString(config->DRDir.string()));
	if (boost::filesystem::exists(config->saveDir))
		settingsUI->savePathLine->setText(QString::fromStdString(config->saveDir.string()));

	settingsUI->drPathBtn->setIcon(style()->standardIcon(QStyle::SP_DialogOpenButton));
	settingsUI->pinPathBtn->setIcon(style()->standardIcon(QStyle::SP_DialogOpenButton));
	settingsUI->savePathBtn->setIcon(style()->standardIcon(QStyle::SP_DialogOpenButton));
}

void settingsDialogWidget::connectWidgets()
{
	initialiseWidgets();

	for (auto widgetsIt = colourWidgets.begin(); widgetsIt != colourWidgets.end(); widgetsIt++)
	{
		eSettingsWidget clickID = widgetsIt->first;
		connect(widgetsIt->second, &colorDemoWidget::mousePressEvent, this, [this, clickID]{ colourClick(clickID); });
	}
	
	setCurrentColours();
}

void settingsDialogWidget::setCurrentColours()
{
	clientConfig *config = &((rgatState *)clientState)->config;

	colourSet(eSettingsWidget::traceColBackground, config->mainColours.background);
	colourSet(eSettingsWidget::traceColActivLine, config->mainColours.activityLine);

	colourSet(eSettingsWidget::traceColEdgeCall, config->graphColours.at(eEdgeNodeType::eEdgeCall));
	colourSet(eSettingsWidget::traceColEdgeRet, config->graphColours.at(eEdgeNodeType::eEdgeReturn));
	colourSet(eSettingsWidget::traceColEdgeNew, config->graphColours.at(eEdgeNodeType::eEdgeNew));
	colourSet(eSettingsWidget::traceColEdgeOld, config->graphColours.at(eEdgeNodeType::eEdgeOld));
	colourSet(eSettingsWidget::traceColEdgeEx, config->graphColours.at(eEdgeNodeType::eEdgeException));
	colourSet(eSettingsWidget::traceColEdgeUnins, config->graphColours.at(eEdgeNodeType::eEdgeLib));

	colourSet(eSettingsWidget::traceColNodeCall, config->graphColours.at(eEdgeNodeType::eNodeCall));
	colourSet(eSettingsWidget::traceColNodeJump, config->graphColours.at(eEdgeNodeType::eNodeJump));
	colourSet(eSettingsWidget::traceColNodeRet, config->graphColours.at(eEdgeNodeType::eNodeReturn));
	colourSet(eSettingsWidget::traceColNodeSeq, config->graphColours.at(eEdgeNodeType::eNodeNonFlow));
	colourSet(eSettingsWidget::traceColNodeUnins, config->graphColours.at(eEdgeNodeType::eNodeExternal));

	colourSet(eSettingsWidget::traceColInsText, config->mainColours.instructionText);
	colourSet(eSettingsWidget::traceColExtSymbol, config->mainColours.symbolTextExternal);
	colourSet(eSettingsWidget::traceColExtRising, config->mainColours.symbolTextExternalRising);
	colourSet(eSettingsWidget::traceColIntSymbol, config->mainColours.symbolTextInternal);
	colourSet(eSettingsWidget::traceColIntRising, config->mainColours.symbolTextInternalRising);
	colourSet(eSettingsWidget::traceColPlaceholder, config->mainColours.symbolTextPlaceholder);

	colourSet(eSettingsWidget::heatColBackground, config->heatmap.background);
	colourSet(eSettingsWidget::heatColHeat1, config->heatmap.edgeFrequencyCol.at(0));
	colourSet(eSettingsWidget::heatColHeat2, config->heatmap.edgeFrequencyCol.at(1));
	colourSet(eSettingsWidget::heatColHeat3, config->heatmap.edgeFrequencyCol.at(2));
	colourSet(eSettingsWidget::heatColHeat4, config->heatmap.edgeFrequencyCol.at(3));
	colourSet(eSettingsWidget::heatColHeat5, config->heatmap.edgeFrequencyCol.at(4));
	colourSet(eSettingsWidget::heatColHeat6, config->heatmap.edgeFrequencyCol.at(5));
	colourSet(eSettingsWidget::heatColHeat7, config->heatmap.edgeFrequencyCol.at(6));
	colourSet(eSettingsWidget::heatColHeat8, config->heatmap.edgeFrequencyCol.at(7));
	colourSet(eSettingsWidget::heatColHeat9, config->heatmap.edgeFrequencyCol.at(8));
	colourSet(eSettingsWidget::heatColHeat10, config->heatmap.edgeFrequencyCol.at(9));
	colourSet(eSettingsWidget::heatText, config->heatmap.lineTextCol);

	colourSet(eSettingsWidget::condColBackground, config->conditional.background);
	colourSet(eSettingsWidget::condColTrue, config->conditional.cond_succeed);
	colourSet(eSettingsWidget::condColFalse, config->conditional.cond_fail);
	colourSet(eSettingsWidget::condColBoth, config->conditional.cond_both);
	colourSet(eSettingsWidget::condColEdge, config->conditional.edgeColor);

	colourSet(eSettingsWidget::previewColBackground, config->preview.background); 
	colourSet(eSettingsWidget::previewColActive, config->preview.activeHighlight);
	colourSet(eSettingsWidget::previewColInactive, config->preview.inactiveHighlight);
	
}

void settingsDialogWidget::updateColourSetting(eSettingsWidget clickID, QColor col)
{
	clientConfig *config = &((rgatState *)clientState)->config;
	switch (clickID)
	{
	//main trace
	case eSettingsWidget::traceColBackground:
		config->mainColours.background = col;
		break;
	case eSettingsWidget::traceColActivLine:
		config->mainColours.activityLine = col;
		break;
	case eSettingsWidget::traceColEdgeCall:
		config->graphColours.at(eEdgeNodeType::eEdgeCall) = col;
		break;
	case eSettingsWidget::traceColEdgeRet:
		config->graphColours.at(eEdgeNodeType::eEdgeReturn) = col;
		break;
	case eSettingsWidget::traceColEdgeNew:
		config->graphColours.at(eEdgeNodeType::eEdgeNew) = col;
		break;
	case eSettingsWidget::traceColEdgeOld:
		config->graphColours.at(eEdgeNodeType::eEdgeOld) = col;
		break;
	case eSettingsWidget::traceColEdgeUnins:
		config->graphColours.at(eEdgeNodeType::eEdgeLib) = col;
		break;
	case eSettingsWidget::traceColEdgeEx:
		config->graphColours.at(eEdgeNodeType::eEdgeException) = col;
		break;
	case eSettingsWidget::traceColNodeSeq:
		config->graphColours.at(eEdgeNodeType::eNodeNonFlow) = col;
		break;
	case eSettingsWidget::traceColNodeJump:
		config->graphColours.at(eEdgeNodeType::eNodeJump) = col;
		break;
	case eSettingsWidget::traceColNodeCall:
		config->graphColours.at(eEdgeNodeType::eNodeCall) = col;
		break;
	case eSettingsWidget::traceColNodeRet:
		config->graphColours.at(eEdgeNodeType::eNodeReturn) = col;
		break;
	case eSettingsWidget::traceColNodeUnins:
		config->graphColours.at(eEdgeNodeType::eNodeExternal) = col;
		break;
	case eSettingsWidget::traceColInsText:
		config->mainColours.instructionText = col;
		break;
	case eSettingsWidget::traceColExtSymbol:
		config->mainColours.symbolTextExternal = col;
		break;
	case eSettingsWidget::traceColExtRising:
		config->mainColours.symbolTextExternalRising = col;
		break;
	case eSettingsWidget::traceColIntSymbol:
		config->mainColours.symbolTextInternal = col;
		break;
	case eSettingsWidget::traceColIntRising:
		config->mainColours.symbolTextInternalRising = col;
		break;
	case eSettingsWidget::traceColPlaceholder:
		config->mainColours.symbolTextPlaceholder = col;
		break;
	//heatmap
	case eSettingsWidget::heatColBackground:
		config->heatmap.background = col;
		break;
	case eSettingsWidget::heatColHeat1:
		config->heatmap.edgeFrequencyCol.at(0) = col;
		break;
	case eSettingsWidget::heatColHeat2:
		config->heatmap.edgeFrequencyCol.at(1) = col;
		break;
	case eSettingsWidget::heatColHeat3:
		config->heatmap.edgeFrequencyCol.at(2) = col;
		break;
	case eSettingsWidget::heatColHeat4:
		config->heatmap.edgeFrequencyCol.at(3) = col;
		break;
	case eSettingsWidget::heatColHeat5:
		config->heatmap.edgeFrequencyCol.at(4) = col;
		break;
	case eSettingsWidget::heatColHeat6:
		config->heatmap.edgeFrequencyCol.at(5) = col;
		break;
	case eSettingsWidget::heatColHeat7:
		config->heatmap.edgeFrequencyCol.at(6) = col;
		break;
	case eSettingsWidget::heatColHeat8:
		config->heatmap.edgeFrequencyCol.at(7) = col;
		break;
	case eSettingsWidget::heatColHeat9:
		config->heatmap.edgeFrequencyCol.at(8) = col;
		break;
	case eSettingsWidget::heatColHeat10:
		config->heatmap.edgeFrequencyCol.at(9) = col;
		break;
	case eSettingsWidget::heatText:
		break;

	//conditionals
	case eSettingsWidget::condColBackground:
		config->conditional.background = col;
		break;
	case eSettingsWidget::condColEdge:
		config->conditional.edgeColor = col;
		break;
	case eSettingsWidget::condColTrue:
		config->conditional.cond_succeed = col;
		break;
	case eSettingsWidget::condColFalse:
		config->conditional.cond_fail = col;
		break;
	case eSettingsWidget::condColBoth:
		config->conditional.cond_both = col;
		break;

	//preview
	case eSettingsWidget::previewColBackground:
		config->preview.background = col;
		break;
	case eSettingsWidget::previewColActive:
		config->preview.activeHighlight = col;
		break;
	case eSettingsWidget::previewColInactive:
		config->preview.inactiveHighlight = col;
		break;

	default:
		cerr << "Bad clickID in updateColour: " << clickID << endl;
	}

	config->saveConfig();
}

void settingsDialogWidget::colourSet(eSettingsWidget clickID, QColor col)
{
	Ui::SettingsWindow *settingsUI = (Ui::SettingsWindow *)this->settingsUIPtr;


	switch (clickID)
	{
		case eSettingsWidget::traceColBackground:
		case eSettingsWidget::heatColBackground:
		case eSettingsWidget::condColBackground:
		case eSettingsWidget::previewColBackground:
		{
			QString chosenColStyleSheet = "background: " + col.name();
			//set the background containing all the colour demo widgets
			switch (clickID)
			{
			case traceColBackground:
				settingsUI->traceColoursFrame->setStyleSheet(chosenColStyleSheet);
				break;
			case heatColBackground:
				settingsUI->heatmapColoursFrame->setStyleSheet(chosenColStyleSheet);
				break;
			case condColBackground:
				settingsUI->condColoursFrame->setStyleSheet(chosenColStyleSheet);
				break;
			case previewColBackground:
				settingsUI->previewColoursFrame->setStyleSheet(chosenColStyleSheet);
				break;
			}
			//set the demo widget itself, with a border
			colourWidgets.at(clickID)->setColour(col, true);
			break;
		}

		default:
			colourWidgets.at(clickID)->setColour(col);
	}

	updateColourSetting(clickID, col);
}

void settingsDialogWidget::colourClick(eSettingsWidget clickID)
{
	QColorDialog colorDlg(this);
	QColor currentCol = colourWidgets.at(clickID)->getColour();
	QColor col = colorDlg.getColor(currentCol, this, "Choose new colour");
	if (col.isValid()) 
		colourSet(clickID, col);
}

void settingsDialogWidget::pageSelected(QTreeWidgetItem *item)
{
	Ui::SettingsWindow *settingsUI = (Ui::SettingsWindow *)this->settingsUIPtr;
	QVariant itemTypeVariant = item->data(1, Qt::UserRole);
	eStackPages selectedItem = (eStackPages)itemTypeVariant.value<int>();
	settingsUI->stackedWidget->setCurrentIndex(selectedItem);
}


void settingsDialogWidget::previewSliderChanged(int newValue)
{
	Ui::SettingsWindow *setsUI = (Ui::SettingsWindow *)this->settingsUIPtr;
	clientConfig *config = &((rgatState *)clientState)->config;

	double sliderDivisions = setsUI->previewRotationSlider->maximum();
	double fastestRotsPerSec = sliderDivisions/50;
	double halfDivisions = sliderDivisions / 2;

	if (newValue > halfDivisions)
	{
		int clockWiseMagnitude = (halfDivisions - (sliderDivisions - newValue));
		double newRotations = clockWiseMagnitude * (fastestRotsPerSec / halfDivisions);
		config->preview.spinPerFrame = newRotations;
	}
	else
	{
		int clockWiseMagnitude = (halfDivisions - newValue);
		double newRotations = clockWiseMagnitude * (fastestRotsPerSec / halfDivisions);
		config->preview.spinPerFrame = -1 * newRotations;
	}

	//don't want to save on every change, will probably get saved at some other point anyway
}


void settingsDialogWidget::setPreviewRotationEnabled(bool newState)
{
	clientConfig *config = &((rgatState *)clientState)->config;

	config->preview.rotationEnabled = newState;

	config->saveConfig();
}

//this is repetition is crappy, should be able to roll this into filepathwidget
void settingsDialogWidget::fileDialogPin()
{
	clientConfig *config = &((rgatState *)clientState)->config;
	QString oldpath = QString::fromStdString(config->PinDir.string());
	QString newpathString = QFileDialog::getExistingDirectory(this,
		tr("Select PIN directory (containing pin.exe)"), oldpath);

	boost::filesystem::path newpath = boost::filesystem::path(newpathString.toStdString());
	if (!boost::filesystem::is_directory(newpath)) return;
	config->PinDir = newpath;
	config->saveConfig();

	setupPathsWidgets();
}

void settingsDialogWidget::fileDialogDR()
{
	clientConfig *config = &((rgatState *)clientState)->config;
	QString oldpath = QString::fromStdString(config->DRDir.string());
	QString newpathString = QFileDialog::getExistingDirectory(this,
		tr("Select DynamoRIO directory (containing bin32 and bin64)"), oldpath);

	boost::filesystem::path newpath = boost::filesystem::path(newpathString.toStdString());
	if (!boost::filesystem::is_directory(newpath)) return;
	config->DRDir = newpath;
	config->saveConfig();

	setupPathsWidgets();
}

void settingsDialogWidget::fileDialogSave()
{
	clientConfig *config = &((rgatState *)clientState)->config;
	QString oldpath = QString::fromStdString(config->saveDir.string());
	QString newpathString = QFileDialog::getExistingDirectory(this,
		tr("Select directory containing trace files"), oldpath);

	boost::filesystem::path newpath = boost::filesystem::path(newpathString.toStdString());
	if (!boost::filesystem::is_directory(newpath)) return;
	config->saveDir = newpath;
	config->saveConfig();

	setupPathsWidgets();
}


void settingsDialogWidget::setActiveLineEnabled(bool newState)
{
	clientConfig *config = &((rgatState *)clientState)->config;
	config->showActiveMarker = newState;
	config->saveConfig();
}