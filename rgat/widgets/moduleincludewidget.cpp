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

void moduleIncludeWidget::refresh()
{
	binaryTarget *binary = clientState->activeBinary;
	if (!binary) return;

	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	if (includeui->blacklistRadio->isChecked())
	{
		includeui->blackWhiteListStack->setCurrentIndex(0);
	}
	else
	{
		includeui->blackWhiteListStack->setCurrentIndex(1);
	}



	clearAll();

	BWPATHLISTS bwlistPaths = binary->getBWListPaths();
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
}

void moduleIncludeWidget::updateIncludeSummary()
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	Ui::rgatClass *mainui = (Ui::rgatClass *)clientState->ui;
	size_t dirscount, filescount;

	if (includeui->blacklistRadio->isChecked())
	{
		mainui->mIncludeModeLabel->setText("Blacklist");
		dirscount = includeui->blackWhiteListStack->blackDirsCount();
		filescount = includeui->blackWhiteListStack->blackFilesCount();
	}
	else
	{
		mainui->mIncludeModeLabel->setText("Whitelist");
		dirscount = includeui->blackWhiteListStack->whiteDirsCount();
		filescount = includeui->blackWhiteListStack->whiteFilesCount();
	}


}

void moduleIncludeWidget::whitelistRadioToggle(bool newstate)
{
	if (newstate == false) return;

	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	includeui->blacklistRadio->blockSignals(true);
	includeui->blacklistRadio->setChecked(false);
	includeui->blacklistRadio->blockSignals(false);
	setCurrentIndex(1);
	updateIncludeSummary();
}

void moduleIncludeWidget::blacklistRadioToggle(bool newstate)
{
	if (newstate == false) return;

	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	includeui->whitelistRadio->blockSignals(true);
	includeui->whitelistRadio->setChecked(false);
	includeui->whitelistRadio->blockSignals(false);
	setCurrentIndex(0);
	updateIncludeSummary();
}



void moduleIncludeWidget::removeSelected(QListWidget *target)
{
	QList<QListWidgetItem *> selected = target->selectedItems();
	cout << "removing " << selected.size() << "selected";
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
		pathlist->push_back(boost::filesystem::path(itemtext.toStdString()));
	}
}


void moduleIncludeWidget::removeSelectedWhiteDir() 
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	removeSelected(includeui->whitelistDirsList);
	buildPathList(includeui->whitelistDirsList, &WLDirs);
}

void moduleIncludeWidget::removeSelectedBlackDir() 
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	removeSelected(includeui->blacklistDirsList);
	buildPathList(includeui->blacklistDirsList, &BLDirs);
}

void moduleIncludeWidget::removeSelectedWhiteFile() 
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	removeSelected(includeui->whitelistFilesList);
	buildPathList(includeui->whitelistFilesList, &WLFiles);
}

void moduleIncludeWidget::removeSelectedBlackFile() 
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	removeSelected(includeui->blacklistFilesList);
	buildPathList(includeui->blacklistFilesList, &BLFiles);
}

void moduleIncludeWidget::addItem(QListWidget *target,
	vector <boost::filesystem::path> *pathlist, QString filename)
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;

	boost::filesystem::path path = boost::filesystem::path(filename.toStdString());
	if (!boost::filesystem::exists(path))
		return;
	if (std::find(pathlist->begin(), pathlist->end(), path) != pathlist->end())
		return;

	QListWidgetItem *pathitem = new QListWidgetItem();
	pathitem->setText(filename);
	target->addItem(pathitem);
	pathlist->push_back(path);
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
	QString fileName = QFileDialog::getExistingDirectory(this, tr("Select binary to whitelist"), "");

	if (!fileName.isEmpty())
		addItem(includeui->whitelistFilesList, &WLFiles, fileName);
}

void moduleIncludeWidget::addBlackFile()
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	QString fileName = QFileDialog::getExistingDirectory(this, tr("Select binary to blacklist"), "");

	if (!fileName.isEmpty())
		addItem(includeui->blacklistFilesList, &BLFiles, fileName);
}