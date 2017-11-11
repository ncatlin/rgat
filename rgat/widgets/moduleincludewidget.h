#pragma once
#include "qstackedwidget.h"
#include "rgatState.h"

class moduleIncludeWidget :
	public QStackedWidget
{
	Q_OBJECT

public:
	moduleIncludeWidget(QWidget *parent = 0);
	~moduleIncludeWidget() {} ;

	rgatState *clientState = NULL;
	void updateIncludeSummary();
	void refresh();
	size_t blackDirsCount() { return BLDirs.size(); }
	size_t blackFilesCount() { return BLFiles.size(); }
	size_t whiteDirsCount() { return WLDirs.size(); }
	size_t whiteFilesCount() { return WLFiles.size(); }

public Q_SLOTS:
	void whitelistRadioToggle(bool newstate);
	void blacklistRadioToggle(bool newstate);
	void addWhiteDir();
	void addBlackDir();
	void addWhiteFile();
	void addBlackFile();
	void removeSelectedWhiteDir();
	void removeSelectedBlackDir();
	void removeSelectedWhiteFile();
	void removeSelectedBlackFile();

private:
	void removeSelected(QListWidget *target);
	void buildPathList(QListWidget *target, vector <boost::filesystem::path> *pathlist);
	void clearAll();
	void addItem(QListWidget *target,
		vector <boost::filesystem::path> *pathlist, QString filename);

	vector <boost::filesystem::path> WLDirs;
	vector <boost::filesystem::path> BLDirs;
	vector <boost::filesystem::path> WLFiles;
	vector <boost::filesystem::path> BLFiles;
};
