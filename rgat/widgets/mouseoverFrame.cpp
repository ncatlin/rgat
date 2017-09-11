#include "mouseoverFrame.h"
#include "rgatState.h"


mouseoverFrame::mouseoverFrame(QWidget *parent)
	:QFrame(parent)
{
}

mouseoverFrame::~mouseoverFrame()
{
}

void mouseoverFrame::changedLabel()
{
	((rgatState *)clientState)->mouseoverLabelChanged();
}