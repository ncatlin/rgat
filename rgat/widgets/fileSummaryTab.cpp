/*
Copyright 2016-2017 Nia Catlin

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
Displays some basic static analysis and provides tracing/instrumentation options + launch control
*/

#include "stdafx.h"
#include "widgets\fileSummaryTab.h"
#include "ui_rgat.h"
#include "rgat.h"
#include "Dbghelp.h"
#include "parser-library/parse.h"

fileSummaryTab::fileSummaryTab(QWidget *parent)
	: QWidget(parent)
{
}


fileSummaryTab::~fileSummaryTab()
{
}


//https://stackoverflow.com/a/24192835
template<class T> QString FormatWithCommas(T value)
{
	string numWithCommas = to_string(value);
	int insertPosition = (int)numWithCommas.length() - 3;
	while (insertPosition > 0) {
		numWithCommas.insert(insertPosition, ",");
		insertPosition -= 3;
	}
	return QString::fromStdString(numWithCommas);
}

//return true if deemed to be tracable
bool setFileTypeField(binaryTarget *target, peparse::parsed_pe *header, Ui::rgatClass *ui)
{
	QString bitwidth = ""; 
	if (target->getBitWidth())
		bitwidth = QString::number(target->getBitWidth()) + " bit";

	if (header->peHeader.nt.Signature != IMAGE_NT_SIGNATURE)
	{
		ui->tgt_typeLineEdit->setText("Bad signature ("+ bitwidth +")");
		return false;
	}

	bool isDotNet = (header->peHeader.nt.OptionalHeader.DataDirectory[peparse::DIR_COM_DESCRIPTOR].VirtualAddress != NULL);
	if (isDotNet)
	{
		ui->tgt_typeLineEdit->setText(bitwidth + " .NET (Tracing not supported)");
		return false;
	}

	if (header->peHeader.nt.FileHeader.Characteristics & IMAGE_FILE_DLL)
	{
		ui->tgt_typeLineEdit->setText("Dynamic-link library (Direct tracing not yet supported)");
		return false;
	}

	if (header->peHeader.nt.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
	{
		ui->tgt_typeLineEdit->setText(bitwidth + " Executable");
		return true;
	}


	ui->tgt_typeLineEdit->setText(bitwidth + " Binary");
	return true;

}

void fileSummaryTab::fillAnalyseTab(binaryTarget *target)
{

	if (!target) return;
	if (target == lastExaminedBinary) return;

	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	QString nameString = QString::fromStdString(target->path().filename().string());
	ui->tgt_nameLineEdit->setText(nameString);

	uintmax_t exesize = boost::filesystem::file_size(target->path());
	QString filesize = FormatWithCommas(exesize);
	ui->tgt_sizeLineEdit->setText(filesize + " bytes");

	string hashDigest = target->get_sha1hash();
	if (!hashDigest.empty())
	{
		ui->tgt_hashLineEdit->setText(QString::fromStdString(hashDigest));
	}
	else
	{
		ui->tgt_hashLineEdit->setText("Failed to calculate hash");
	}

	string cpath = target->path().string();
	peparse::parsed_pe *header = peparse::ParsePEFromFile(cpath.c_str());
	if (!header)
	{
		stringstream peerror;
		cout << "[rgat]peparse error: " << peparse::GetPEErrString() << endl;
		peerror << "Potentially incompatible binary <peparse error " << peparse::GetPEErr() << " - '" << peparse::GetPEErrString() << "' " << " at " <<hex<< peparse::GetPEErrLoc() << ">";
		ui->tgt_typeLineEdit->setText(QString::fromStdString(peerror.str()));
		ui->tgt_typeLineEdit->setStyleSheet("QLineEdit {color: red; padding-left: 5;};");
	}
	else
	{
		bool traceableFile = setFileTypeField(target, header, ui);
		if (traceableFile)
			ui->tgt_typeLineEdit->setStyleSheet("QLineEdit {color: green; padding-left: 5;};");
		else
			ui->tgt_typeLineEdit->setStyleSheet("QLineEdit {color: red; padding-left: 5;};");

		peparse::DestructParsedPE(header);
	}


	lastExaminedBinary = target;
}


void fileSummaryTab::refreshLaunchOptionsFromUI(binaryTarget *target)
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;

	target->launchopts.args = ui->cmdLineEdit->text().toStdString();
	target->launchopts.debugLogging = ui->debugCheck->isChecked();
	target->launchopts.pause = ui->pauseCheck->isChecked();
	target->launchopts.removeSleeps = ui->sleepCheck->isChecked();
}
