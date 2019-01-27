#include "stdafx.h"
#include "widgets\moduleincludewidget.h"
#include "ui_rgat.h"
#include "ui_moduleIncludeSelector.h"

moduleIncludeWidget::moduleIncludeWidget(QWidget *parent)
	:QStackedWidget(parent)
{
	//default blacklist but save last choice
	//client state isn't inited yet though so we have to do it later
	setCurrentIndex(ModuleModeSelector::eCurrentBlacklistMode::eBlacklisting);
	BlacklistMode = ModuleModeSelector::eCurrentBlacklistMode::eBlacklisting;
	

	this->installEventFilter(this);

}

bool moduleIncludeWidget::eventFilter(QObject *object, QEvent *event)
{

	if (object == this && event->type() == QEvent::KeyPress) {
		QKeyEvent *keyEvent = static_cast<QKeyEvent *>(event);
		if (keyEvent->key() == Qt::Key_Delete || keyEvent->key() == Qt::Key_Backspace) {

			removeSelectedFile();

			return true;
		}
		else
			return false;
	}
	return false;
}

void moduleIncludeWidget::clearAll()
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	WLDirs.clear();
	BLDirs.clear();

	WLFiles.clear();
	includeui->whitelistFilesList->setRowCount(0);

	BLFiles.clear();
	includeui->blacklistFilesList->setRowCount(0);
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

void moduleIncludeWidget::repopulateFileTables(binaryTarget *binary, BWPATHLISTS &bwlistPaths)
{
	clearAll();

	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;

	for each (boost::filesystem::path path in bwlistPaths.BLDirs)
	{
		QString qstrpath = QString::fromStdString(path.string());
		addItem(includeui->blacklistFilesList, &BLDirs, qstrpath);
	}

	for each (boost::filesystem::path path in bwlistPaths.BLFiles)
	{
		QString qstrpath = QString::fromStdString(path.string());
		addItem(includeui->blacklistFilesList, &BLFiles, qstrpath);
	}

	for each (boost::filesystem::path path in bwlistPaths.WLDirs)
	{
		QString qstrpath = QString::fromStdString(path.string());
		addItem(includeui->whitelistFilesList, &WLDirs, qstrpath);
	}
	for each (boost::filesystem::path path in bwlistPaths.WLFiles)
	{
		QString qstrpath = QString::fromStdString(path.string());
		addItem(includeui->whitelistFilesList, &WLFiles, qstrpath);
	}
}

void moduleIncludeWidget::updateExplainLabels()
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	includeui->WLDirExplainText->setText(baseWLDirExplainText + " (" + QString::number(WLDirs.size()) + " Directories)");
	includeui->WLFileExplainText->setText(baseWLFileExplainText + " (" + QString::number(WLFiles.size()) + " Files)");
	includeui->BLDirExplainText->setText(baseBLDirExplainText + " (" + QString::number(BLDirs.size()) + " Directories)");
	includeui->BLFileExplainText->setText(baseBLFileExplainText + " (" + QString::number(BLFiles.size()) + " Files)");
}

void moduleIncludeWidget::SyncUIWithCurrentBinary()
{

	binaryTarget *binary = clientState->activeBinary;
	if (!binary) return;

	BWPATHLISTS bwlistPaths = binary->getBWListPaths();

	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	
	includeui->libModeSelectBtn->blockSignals(true);

	if (bwlistPaths.inWhitelistMode)
	{
		includeui->blackWhiteListStack->setCurrentIndex(ModuleModeSelector::eWhitelisting);
		includeui->libModeSelectBtn->setChecked(true);
	}
	else
	{
		includeui->blackWhiteListStack->setCurrentIndex(ModuleModeSelector::eBlacklisting);
		includeui->libModeSelectBtn->setChecked(false);
	}
	includeui->libModeSelectBtn->blockSignals(false);

	repopulateFileTables(binary, bwlistPaths);
	updateExplainLabels();
	refreshLauncherUI();
}

void moduleIncludeWidget::triggerFileDialog()
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	QStringList fileNames = QFileDialog::getOpenFileNames(this , "Choose files to blacklist");

	ModuleModeSelector::eCurrentBlacklistMode blacklistMode = this->BlacklistMode;

	for each(QString fname in fileNames)
	{
		if (blacklistMode == ModuleModeSelector::eCurrentBlacklistMode::eBlacklisting)
			addItem(includeui->blacklistFilesList, &BLFiles, fname);
		else
			addItem(includeui->whitelistFilesList, &WLFiles, fname);
	}
}

void moduleIncludeWidget::triggerDirDialog()
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	QString dirname = QFileDialog::getExistingDirectory(this, "Choose a directory to blacklist");

	if (BlacklistMode == ModuleModeSelector::eCurrentBlacklistMode::eBlacklisting)
		addItem(includeui->blacklistFilesList, &BLDirs, dirname);
	else
		addItem(includeui->whitelistFilesList, &WLDirs, dirname);

}

void moduleIncludeWidget::modeToggle(bool newstate)
{
	if (BlacklistMode == ModuleModeSelector::eCurrentBlacklistMode::eBlacklisting)
		switchToWhitelistMode();
	else
		switchToBlacklistMode();

	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
}

void moduleIncludeWidget::switchToBlacklistMode()
{

	BlacklistMode = ModuleModeSelector::eCurrentBlacklistMode::eBlacklisting;


	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;

	includeui->blackWhiteListStack->setCurrentIndex(ModuleModeSelector::eCurrentBlacklistMode::eBlacklisting);
	includeui->libModeSelectBtn->setText("Toggle Whitelisting");

	binaryTarget *binary = clientState->activeBinary;

	if (!binary) { 
		Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
		ui->mIncludeModeLabel->setText("Blacklist");
		return;
	}

	syncBinaryToUI();
	refreshLauncherUI();
}

void moduleIncludeWidget::switchToWhitelistMode()
{
	BlacklistMode = ModuleModeSelector::eCurrentBlacklistMode::eWhitelisting;

	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	includeui->blackWhiteListStack->setCurrentIndex(ModuleModeSelector::eCurrentBlacklistMode::eWhitelisting);
	includeui->libModeSelectBtn->setText("Toggle Blacklisting");

	binaryTarget *binary = clientState->activeBinary;
	if (!binary) { 
		Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
		ui->mIncludeModeLabel->setText("Whitelist");
		return; 
	}
	
	syncBinaryToUI();
	refreshLauncherUI();
}

void moduleIncludeWidget::syncBinaryToUI()
{

	binaryTarget *binary = clientState->activeBinary;
	if (!binary) return;

	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;

	BWPATHLISTS newdata;

	newdata.inWhitelistMode = (BlacklistMode == ModuleModeSelector::eWhitelisting);
	newdata.BLDirs = this->BLDirs;
	newdata.BLFiles = this->BLFiles;
	newdata.WLDirs = this->WLDirs;
	newdata.WLFiles = this->WLFiles;

	binary->setIncludelistData(newdata);
}

void moduleIncludeWidget::deletePathFromModuleIncludeLists(boost::filesystem::path path, bool isDirectory)
{
	if (BlacklistMode == ModuleModeSelector::eBlacklisting)
	{
		if (isDirectory)
		{
			auto itr = std::find(BLDirs.begin(), BLDirs.end(), path);
			if (itr != BLDirs.end()) BLDirs.erase(itr);
		}
		else {
			auto itr = std::find(BLFiles.begin(), BLFiles.end(), path);
			if (itr != BLFiles.end()) BLFiles.erase(itr);
		}
	}
	else
	{
		if (isDirectory)
		{
			auto itr = std::find(WLDirs.begin(), WLDirs.end(), path);
			if (itr != WLDirs.end()) WLDirs.erase(itr);
		}
		else {
			auto itr = std::find(WLFiles.begin(), WLFiles.end(), path);
			if (itr != WLFiles.end()) WLFiles.erase(itr);
		}
	}
}

void moduleIncludeWidget::removeSelectedTableRows(QTableWidget *target)
{
	//https://www.qtcentre.org/threads/4885-Remove-selected-rows-from-a-QTableView
	QItemSelection selection(target->selectionModel()->selection());
	QList<int> rows;
	foreach(const QModelIndex & index, selection.indexes()) {
		rows.append(index.row());
	}
	qSort(rows);

	int prev = -1;
	for (int i = rows.count() - 1; i >= 0; i -= 1) {
		int current = rows[i];
		if (current != prev) 
		{
			//delete from data
			QString fpath = target->item(current, 1)->text();
			bool isdir = target->item(current, 1)->data(Qt::UserRole).toBool();
			deletePathFromModuleIncludeLists(boost::filesystem::path(fpath.toStdString()), isdir);

			//delete from ui
			target->model()->removeRows(current, 1);
			prev = current;
		}
	}

}

void moduleIncludeWidget::buildPathList(QTableWidget *target, vector <boost::filesystem::path> *pathlist)
{
	pathlist->clear();
	int remainingRows = target->rowCount();
	for (int i = 0; i < remainingRows; i++)
	{
		QString itemtext = target->itemAt(1, i)->text();
		pathlist->push_back(boost::filesystem::path(itemtext.toStdString()).generic_path());
	}
}

void moduleIncludeWidget::removeSelectedFile()
{
	Ui::moduleIncludeSelectDialog *includeui = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	if (this->BlacklistMode == ModuleModeSelector::eCurrentBlacklistMode::eBlacklisting)
		removeSelectedTableRows(includeui->blacklistFilesList);
	else
		removeSelectedTableRows(includeui->whitelistFilesList);

	syncBinaryToUI();
	updateExplainLabels();
	refreshLauncherUI();
}

bool checkPathSensible(boost::filesystem::path path, vector <boost::filesystem::path> *existingPathlist)
{
	if (!boost::filesystem::exists(path))
		return false;
	if (std::find(existingPathlist->begin(), existingPathlist->end(), path) != existingPathlist->end())
		return false;
	return true;
}

QString getFileIconpath(boost::filesystem::path fpath, bool blackListing) {
	QString iconpath = ":/Resources/";
	if (boost::filesystem::is_directory(fpath))
	{
		iconpath += blackListing ? "folder-r.png" : "folder-g.png";
	}
	else
	{
		iconpath += blackListing ? "bin-r.png" : "bin-g.png";
	}
	return iconpath;
}


void moduleIncludeWidget::addItem(QTableWidget *target,
	vector <boost::filesystem::path> *pathlist, QString filename)
{
	boost::filesystem::path path = boost::filesystem::path(filename.toStdString()).generic_path();
	if (!checkPathSensible(path, pathlist))
		return;
	
	QTableWidgetItem *fileTableIconItem = new QTableWidgetItem();
	QIcon icon;
	QString iconPath = getFileIconpath(path, BlacklistMode == ModuleModeSelector::eCurrentBlacklistMode::eBlacklisting);
	icon.addFile(iconPath, QSize(), QIcon::Normal, QIcon::Off);
	fileTableIconItem->setIcon(icon);

	QTableWidgetItem *fileTablePathItem = new QTableWidgetItem();
	fileTablePathItem->setText(filename);
	fileTablePathItem->setData(Qt::UserRole, boost::filesystem::is_directory(path));

	target->setRowCount(target->rowCount() + 1);
	int rowIdx = target->rowCount() - 1;
	target->setItem(rowIdx, 0, fileTableIconItem);
	target->setItem(rowIdx, 1, fileTablePathItem);

	pathlist->push_back(path);

	updateExplainLabels();
	syncBinaryToUI();
	refreshLauncherUI();
}

