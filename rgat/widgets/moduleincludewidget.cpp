#include "stdafx.h"
#include "widgets\moduleincludewidget.h"
#include "ui_rgat.h"
#include "ui_moduleIncludeSelector.h"

moduleIncludeWidget::moduleIncludeWidget(QWidget *parent)
	:QStackedWidget(parent)
{
	setCurrentIndex(0); //default blacklist
}

void moduleIncludeWidget::clearAll()
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	WLDirs.clear();
	includeui->whitelistDirsList->clear();

	BLDirs.clear();
	includeui->blacklistDirsList->clear();

	WLFiles.clear();
	includeui->whitelistFilesList->clear();

	BLFiles.clear();
	includeui->blacklistFilesList->clear();
}

void moduleIncludeWidget::refreshLauncherUI()
{
	binaryTarget *binary = clientState->activeBinary;
	if (!binary) return;
	BWPATHLISTS bwlistPaths = binary->getBWListPaths();

	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	if (bwlistPaths.inWhitelistMode)
	{
		ui->mIncludeModeLabel->setText("Whitelist");
		ui->mIncludeDirsLab->setText("Directories: " + QString::number(bwlistPaths.WLDirs.size()));
		ui->mIncludeFilesLAb->setText("Files: " + QString::number(bwlistPaths.WLFiles.size()));
	}
	else
	{
		ui->mIncludeModeLabel->setText("Blacklist");
		ui->mIncludeDirsLab->setText("Directories: " + QString::number(bwlistPaths.BLDirs.size()));
		ui->mIncludeFilesLAb->setText("Files: " + QString::number(bwlistPaths.BLFiles.size()));
	}
}

void moduleIncludeWidget::refresh()
{
	binaryTarget *binary = clientState->activeBinary;
	if (!binary) return;

	BWPATHLISTS bwlistPaths = binary->getBWListPaths();

	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	includeui->blacklistRadio->blockSignals(true);
	includeui->whitelistRadio->blockSignals(true);
	if (bwlistPaths.inWhitelistMode)
	{
		includeui->blackWhiteListStack->setCurrentIndex(1);
		includeui->blacklistRadio->setChecked(false);
		includeui->whitelistRadio->setChecked(true);
	}
	else
	{
		includeui->blackWhiteListStack->setCurrentIndex(0);
		includeui->blacklistRadio->setChecked(true);
		includeui->whitelistRadio->setChecked(false);
	}
	includeui->blacklistRadio->blockSignals(false);
	includeui->whitelistRadio->blockSignals(false);

	clearAll();

	for each (boost::filesystem::path path in bwlistPaths.BLDirs)
	{
		addItem(includeui->blacklistDirsList, &BLDirs, QString::fromStdString(path.string()));
	}
	for each (boost::filesystem::path path in bwlistPaths.WLDirs)
	{
		addItem(includeui->whitelistDirsList, &WLDirs, QString::fromStdString(path.string()));
	}
	for each (boost::filesystem::path path in bwlistPaths.BLFiles)
	{
		addItem(includeui->blacklistFilesList, &BLFiles, QString::fromStdString(path.string()));
	}
	for each (boost::filesystem::path path in bwlistPaths.WLFiles)
	{
		addItem(includeui->whitelistFilesList, &WLFiles, QString::fromStdString(path.string()));
	}

	refreshLauncherUI();
}

void moduleIncludeWidget::whitelistRadioToggle(bool newstate)
{
	if (newstate == false) return;

	binaryTarget *binary = clientState->activeBinary;
	if (!binary) return;

	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	includeui->blacklistRadio->blockSignals(true);
	includeui->blacklistRadio->setChecked(false);
	includeui->blacklistRadio->blockSignals(false);
	setCurrentIndex(1);

	syncBinaryToUI();
	refreshLauncherUI();
}

void moduleIncludeWidget::blacklistRadioToggle(bool newstate)
{
	if (newstate == false) return;

	binaryTarget *binary = clientState->activeBinary;
	if (!binary) return;

	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	includeui->whitelistRadio->blockSignals(true);
	includeui->whitelistRadio->setChecked(false);
	includeui->whitelistRadio->blockSignals(false);
	setCurrentIndex(0);

	syncBinaryToUI();
	refreshLauncherUI();
}

void moduleIncludeWidget::syncBinaryToUI()
{
	binaryTarget *binary = clientState->activeBinary;
	if (!binary) return;

	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;

	BWPATHLISTS newdata;
	newdata.inWhitelistMode = includeui->whitelistRadio->isChecked();
	newdata.BLDirs = this->BLDirs;
	newdata.BLFiles = this->BLFiles;
	newdata.WLDirs = this->WLDirs;
	newdata.WLFiles = this->WLFiles;

	binary->setIncludelistData(newdata);
}


void moduleIncludeWidget::removeSelected(QListWidget *target)
{
	QList<QListWidgetItem *> selected = target->selectedItems();
	for each (QListWidgetItem * item in selected)
	{
		delete item;
	}
}

void moduleIncludeWidget::buildPathList(QListWidget *target, vector <boost::filesystem::path> *pathlist)
{
	pathlist->clear();
	int remainingRows = target->count();
	for (int i = 0; i < remainingRows; i++)
	{
		QString itemtext = target->item(i)->text();
		pathlist->push_back(boost::filesystem::path(itemtext.toStdString()).generic_path());
	}
}


void moduleIncludeWidget::removeSelectedWhiteDir() 
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	removeSelected(includeui->whitelistDirsList);
	buildPathList(includeui->whitelistDirsList, &WLDirs);
	syncBinaryToUI();
	refreshLauncherUI();
}

void moduleIncludeWidget::removeSelectedBlackDir() 
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	removeSelected(includeui->blacklistDirsList);
	buildPathList(includeui->blacklistDirsList, &BLDirs);
	syncBinaryToUI();
	refreshLauncherUI();
}

void moduleIncludeWidget::removeSelectedWhiteFile() 
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	removeSelected(includeui->whitelistFilesList);
	buildPathList(includeui->whitelistFilesList, &WLFiles);
	syncBinaryToUI();
	refreshLauncherUI();
}

void moduleIncludeWidget::removeSelectedBlackFile() 
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	removeSelected(includeui->blacklistFilesList);
	buildPathList(includeui->blacklistFilesList, &BLFiles);
	syncBinaryToUI();
	refreshLauncherUI();
}

void moduleIncludeWidget::addItem(QListWidget *target,
	vector <boost::filesystem::path> *pathlist, QString filename)
{
	boost::filesystem::path path = boost::filesystem::path(filename.toStdString()).generic_path();
	if (!boost::filesystem::exists(path))
		return;
	if (std::find(pathlist->begin(), pathlist->end(), path) != pathlist->end())
		return;

	QListWidgetItem *pathitem = new QListWidgetItem();
	pathitem->setText(filename);
	target->addItem(pathitem);
	pathlist->push_back(path);

	syncBinaryToUI();
	refreshLauncherUI();
}

void moduleIncludeWidget::addWhiteDir()
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	QString fileName = QFileDialog::getExistingDirectory(this,	tr("Select directory to whitelist"), "");

	if (!fileName.isEmpty())
		addItem(includeui->whitelistDirsList, &WLDirs, fileName);
}

void moduleIncludeWidget::addBlackDir()
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	QString fileName = QFileDialog::getExistingDirectory(this, tr("Select directory to blacklist"), "");

	if (!fileName.isEmpty())
		addItem(includeui->blacklistDirsList, &BLDirs, fileName);
}

void moduleIncludeWidget::addWhiteFile()
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	QString fileName = QFileDialog::getOpenFileName(this, tr("Select binary to whitelist"), "");

	if (!fileName.isEmpty())
		addItem(includeui->whitelistFilesList, &WLFiles, fileName);
}

void moduleIncludeWidget::addBlackFile()
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	QString fileName = QFileDialog::getOpenFileName(this, tr("Select binary to blacklist"), "");

	if (!fileName.isEmpty())
		addItem(includeui->blacklistFilesList, &BLFiles, fileName);
}