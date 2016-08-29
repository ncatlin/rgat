#include "highlightWindow.h"

void HighlightSelectionFrame::updateHighlightNodes(HIGHLIGHT_DATA *highlightData, 
	thread_graph_data *graph, PROCESS_DATA* activePid)
{
	highlightData->highlightNodes.clear();
	if (!highlightData->highlightState) return;

	switch (highlightData->highlightState)
	{
	case HL_HIGHLIGHT_ADDRESS:
	{
		vector<INS_DATA*> insList = activePid->disassembly.at(highlightData->highlightAddr);
		vector<INS_DATA*>::iterator insListIt = insList.begin();
		int currentTid = graph->tid;
		for (; insListIt != insList.end(); ++insListIt)
		{
			INS_DATA *target = *insListIt;
			node_data *n = graph->get_node(target->threadvertIdx.at(currentTid));
			highlightData->highlightNodes.push_back(n);
		}
		break;
	}

	case HL_HIGHLIGHT_SYM:
	{
		vector<int>::iterator externIt = graph->externList.begin();
		for (; externIt != graph->externList.end(); ++externIt)
		{
			if (highlightData->highlight_s == graph->get_node_sym(*externIt, activePid))
				highlightData->highlightNodes.push_back(graph->get_node(*externIt));
		}
		break;
	}

	case HL_HIGHLIGHT_MODULE:
	{
		vector<int>::iterator externIt = graph->externList.begin();
		for (; externIt != graph->externList.end(); ++externIt)
		{
			if (highlightData->highlightModule == graph->get_node(*externIt)->nodeMod)
				highlightData->highlightNodes.push_back(graph->get_node(*externIt));
		}
		break;
	}
	}
}

void HighlightSelectionFrame::refreshDropdowns()
{
	thread_graph_data *graph = clientState->activeGraph;
	if (!clientState->activePid || !graph) return;

	if (graph->get_num_nodes())
	{
		unsigned long firstAddress = graph->get_node(0)->address;
		stringstream hexaddress;
		hexaddress << "0x" << hex << firstAddress;
		addressText->setText(hexaddress.str());
	}

	if (lastSymCount == graph->externList.size()) return;

	obtainMutex(graph->funcQueueMutex, "Display externlist", 1200);
	vector<int> externListCopy = graph->externList;
	dropMutex(graph->funcQueueMutex, "Display externlist");
	vector<int>::iterator externIt = externListCopy.begin();

	vector<string> addedSyms;
	map<int,int> activeModules;
	for (; externIt != externListCopy.end(); ++externIt)
	{
		string sym = graph->get_node_sym(*externIt, clientState->activePid);
		bool newSym = find(addedSyms.begin(), addedSyms.end(), sym) == addedSyms.end();
		if (newSym)
			addedSyms.push_back(sym);
		node_data* node = graph->get_node(*externIt);
		++activeModules[node->nodeMod];

	}
	lastSymCount = externListCopy.size();

	std::sort(addedSyms.begin(), addedSyms.end());
	vector<string>::iterator symIt;
	symbolDropdown->clearItems();
	for (symIt = addedSyms.begin(); symIt != addedSyms.end(); ++symIt)
		symbolDropdown->addItem(*symIt);

	moduleDropdown->clearItems();
	map<int, string>::iterator pathIt = clientState->activePid->modpaths.begin();
	for (; pathIt != clientState->activePid->modpaths.end(); ++pathIt)
	{
		stringstream pathString;
		if (pathIt->second == "NULL")
			pathString << "[UNKNOWN]";
		else
			pathString << pathIt->second;
		
		if (activeModules.count(pathIt->first))
			pathString << " (" << activeModules.at(pathIt->first) << ")";
		moduleDropdown->addItem(pathString.str());
	}
	lastModCount = clientState->activePid->modpaths.size();

}


#define HLT_LABEL_X 10
#define HLT_TEXT_X 80
#define HLT_BTN_X 315
#define HLT_TEXT_LEN (HLT_BTN_X-HLT_TEXT_X)-10

#define HLT_ADDRESS_Y 10
#define HLT_SYMBOL_Y 50
#define HLT_MODULE_Y 90


HighlightSelectionFrame::HighlightSelectionFrame(agui::Gui *widgets, VISSTATE *state, agui::Font *font)
{
	clientState = state;
	highlightButtonListener *highlightBtnListen;

	highlightFrame = new agui::Frame;
	highlightFrame->setSize(400, 190);
	highlightFrame->setLocation(200, 300);
	widgets->add(highlightFrame);
	highlightFrame->setVisibility(false);

	addressLabel = new agui::Label;
	addressLabel->setLocation(HLT_LABEL_X, HLT_ADDRESS_Y);
	addressLabel->setText("Address:");
	addressLabel->resizeToContents();
	highlightFrame->add(addressLabel);
	addressText = new agui::TextField;
	addressText->setLocation(HLT_TEXT_X, HLT_ADDRESS_Y);
	addressText->setText("Address");
	addressText->resizeToContents();
	addressText->setSize(HLT_TEXT_LEN, 20);
	highlightFrame->add(addressText);
	addressBtn = new agui::Button;
	addressBtn->setLocation(HLT_BTN_X, HLT_ADDRESS_Y);
	addressBtn->setText("Highlight");
	addressBtn->resizeToContents();
	highlightBtnListen = new highlightButtonListener(clientState, HL_HIGHLIGHT_ADDRESS, this);
	addressBtn->addActionListener(highlightBtnListen);
	highlightFrame->add(addressBtn);

	symbolLabel = new agui::Label;
	symbolLabel->setLocation(HLT_LABEL_X, HLT_SYMBOL_Y);
	symbolLabel->setText("Symbol:");
	symbolLabel->resizeToContents();
	highlightFrame->add(symbolLabel);
	symbolDropdown = new agui::DropDown;
	symbolDropdown->setLocation(HLT_TEXT_X, HLT_SYMBOL_Y);
	symbolDropdown->setText("Loaded Symbols");
	symbolDropdown->setSize(HLT_TEXT_LEN, 20);
	highlightFrame->add(symbolDropdown);
	symbolBtn = new agui::Button;
	symbolBtn->setLocation(HLT_BTN_X, HLT_SYMBOL_Y);
	symbolBtn->setText("Highlight");
	symbolBtn->resizeToContents();
	highlightBtnListen = new highlightButtonListener(clientState, HL_HIGHLIGHT_SYM, this);
	symbolBtn->addActionListener(highlightBtnListen);
	highlightFrame->add(symbolBtn);

	moduleLabel = new agui::Label;
	moduleLabel->setLocation(HLT_LABEL_X, HLT_MODULE_Y);
	moduleLabel->setText("Module:");
	moduleLabel->resizeToContents();
	highlightFrame->add(moduleLabel);
	moduleDropdown = new agui::DropDown;
	moduleDropdown->setLocation(HLT_TEXT_X, HLT_MODULE_Y);
	moduleDropdown->setText("Loaded Modules");
	moduleDropdown->setSize(HLT_TEXT_LEN, 20);
	highlightFrame->add(moduleDropdown);
	moduleBtn = new agui::Button;
	moduleBtn->setLocation(HLT_BTN_X, HLT_MODULE_Y);
	moduleBtn->setText("Highlight");
	moduleBtn->resizeToContents();
	highlightBtnListen = new highlightButtonListener(clientState, HL_HIGHLIGHT_MODULE, this);
	moduleBtn->addActionListener(highlightBtnListen);
	highlightFrame->add(moduleBtn);

	agui::Button *refreshBtn = new agui::Button;
	refreshBtn->setLocation(HLT_TEXT_X, HLT_MODULE_Y + 40);
	refreshBtn->setText("Refresh");
	refreshBtn->resizeToContents();
	highlightBtnListen = new highlightButtonListener(clientState, HL_REFRESH_BTN, this);
	refreshBtn->addActionListener(highlightBtnListen);
	highlightFrame->add(refreshBtn);
}