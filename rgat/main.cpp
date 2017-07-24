#include "stdafx.h"
#include "rgat.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);

	rgat w;

	
	w.show();
	return a.exec();
}
