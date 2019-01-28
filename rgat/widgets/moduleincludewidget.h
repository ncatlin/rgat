#pragma once
#include "qstackedwidget.h"
#include "rgatState.h"

namespace ModuleModeSelector {
	enum eCurrentBlacklistMode{eBlacklisting = 0, eWhitelisting = 1};
}

class moduleIncludeWidget :
	public QStackedWidget
{
	Q_OBJECT

public:
	moduleIncludeWidget(QWidget *parent = 0);
	~moduleIncludeWidget() {} ;

	rgatState *clientState = NULL;
	void SyncUIWithCurrentBinary();
	size_t blackDirsCount() { return BLDirs.size(); }
	size_t blackFilesCount() { return BLFiles.size(); }
	size_t whiteDirsCount() { return WLDirs.size(); }
	size_t whiteFilesCount() { return WLFiles.size(); }
	void syncBinaryToUI();

public Q_SLOTS:
	void modeToggle(bool newstate);
	void triggerFileDialog();
	void triggerDirDialog();
	void removeSelectedFile();

private:
	void deletePathFromModuleIncludeLists(boost::filesystem::path path, bool isDirectory);
	void removeSelectedTableRows(QTableWidget *target);
	void repopulateFileTables(binaryTarget *binary, BWPATHLISTS &bwlistPaths);
	void updateExplainLabels();
	bool eventFilter(QObject *object, QEvent *event);

	void switchToBlacklistMode();
	void switchToWhitelistMode();

	void buildPathList(QTableWidget *target, vector <boost::filesystem::path> *pathlist);
	void clearAll();
	void addItem(QTableWidget *target,
		vector <boost::filesystem::path> *pathlist, QString filename);
	void refreshLauncherUI();
	bool inBlacklistMode() { return (BlacklistMode == ModuleModeSelector::eBlacklisting); }

	ModuleModeSelector::eCurrentBlacklistMode BlacklistMode;

	vector <boost::filesystem::path> WLDirs;
	vector <boost::filesystem::path> BLDirs;
	vector <boost::filesystem::path> WLFiles;
	vector <boost::filesystem::path> BLFiles;

	QString baseWLDirExplainText = "Whitelisted Directories - Code in subdirectories will be instrumented";
	QString baseWLFileExplainText = "Whitelisted Binaries - Code in specified files will be instrumented";
	QString baseBLDirExplainText = "Blacklisted Directories - Code in subdirectories will be ignored";
	QString baseBLFileExplainText = "Blacklisted Binaries - Code in in specified files will be ignored";

};
