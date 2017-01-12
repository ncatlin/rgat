/*
Copyright 2016 Nia Catlin

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
The source file for the instruction/symbol/module highlighting
selection dialog
*/

#include "highlightWindow.h"
#include "OSspecific.h"
#include "proto_graph.h"

//highlights all addresses/syms/etc that match filter
void HighlightSelectionFrame::updateHighlightNodes(HIGHLIGHT_DATA *highlightData, 
	proto_graph *graph, PROCESS_DATA* activePid)
{
	highlightData->highlightNodes.clear();
	if (!highlightData->highlightState || !graph) return;

	switch (highlightData->highlightState)
	{
		case HL_HIGHLIGHT_ADDRESS:
		{
			INSLIST insList = activePid->disassembly.at(highlightData->highlightAddr);
			INSLIST::iterator insListIt = insList.begin();
			int currentTid = graph->get_TID();
			for (; insListIt != insList.end(); ++insListIt)
			{
				INS_DATA *target = *insListIt;
				unordered_map<PID_TID, NODEINDEX>::iterator threadVIt = target->threadvertIdx.find(currentTid);
				if (threadVIt == target->threadvertIdx.end()) continue;
				node_data *n = graph->safe_get_node(threadVIt->second);
				highlightData->highlightNodes.push_back(n);
			}
			break;
		}

		case HL_HIGHLIGHT_SYM:
		{
			obtainMutex(graph->highlightsMutex, 1361);
			vector<unsigned int>::iterator externIt = graph->externList.begin();
			for (; externIt != graph->externList.end(); ++externIt)
			{
				if (highlightData->highlight_s == graph->get_node_sym(*externIt, activePid))
					highlightData->highlightNodes.push_back(graph->safe_get_node(*externIt));
			}
			dropMutex(graph->highlightsMutex);
			break;
		}

		case HL_HIGHLIGHT_MODULE:
		{
			obtainMutex(graph->highlightsMutex, 1362);
			vector<unsigned int>::iterator externIt = graph->externList.begin();
			for (; externIt != graph->externList.end(); ++externIt)
			{
				node_data *externNode = graph->safe_get_node(*externIt);
				if (highlightData->highlightModule == externNode->nodeMod)
					highlightData->highlightNodes.push_back(externNode);
			}
			dropMutex(graph->highlightsMutex);
			break;
		}

		case HL_HIGHLIGHT_EXCEPTIONS:
		{
			obtainMutex(graph->highlightsMutex, 1362);
			if (!graph->exceptionSet.empty())
			{
				set<NODEINDEX>::iterator exceptIt = graph->exceptionSet.begin();
				for (; exceptIt != graph->exceptionSet.end(); ++exceptIt)
					highlightData->highlightNodes.push_back(graph->safe_get_node(*exceptIt));
			}
			dropMutex(graph->highlightsMutex);
			break;
		}
	}
}

//adds new relevant items to dropdown menu
void HighlightSelectionFrame::refreshData()
{
	proto_graph *graph = ((plotted_graph *)clientState->activeGraph)->get_protoGraph();
	if (!clientState->activePid || !graph) return;

	if (lastSymCount != graph->externList.size())
	{
		//add all the used symbols to symbol list
		obtainMutex(graph->highlightsMutex, 1009);
		vector<unsigned int> externListCopy = graph->externList;
		dropMutex(graph->highlightsMutex);

		vector<unsigned int>::iterator externIt = externListCopy.begin();

		vector<string> addedSyms;
		map<int, int> activeModules;
		for (; externIt != externListCopy.end(); ++externIt)
		{
			string sym = graph->get_node_sym(*externIt, clientState->activePid);
			bool newSym = find(addedSyms.begin(), addedSyms.end(), sym) == addedSyms.end();
			if (newSym)
				addedSyms.push_back(sym);
			node_data* node = graph->safe_get_node(*externIt);
			++activeModules[node->nodeMod];

		}
		lastSymCount = externListCopy.size();
		symbolDropdown->clearItems();
		symbolDropdown->setText(" " + to_string(lastSymCount) + " Called Symbols");
		std::sort(addedSyms.begin(), addedSyms.end());
		vector<string>::iterator symIt;
		for (symIt = addedSyms.begin(); symIt != addedSyms.end(); ++symIt)
			symbolDropdown->addItem(*symIt);

		//add all the modules to the module dropdown, including indicator of num symbols called
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
		moduleDropdown->setText(" " + to_string(moduleDropdown->getItemCount()) + " Called Symbols");
	}

	obtainMutex(graph->highlightsMutex,1092);
	unsigned int exceptionCount = graph->exceptionSet.size();
	dropMutex(graph->highlightsMutex);
	if (exceptionCount == 1)
		exceptionLabel->setText("1 Exception");
	else
		exceptionLabel->setText(to_string(exceptionCount) + " Exceptions");

	lastRefresh = GetTickCount64();
}


#define HLT_LABEL_X 10
#define HLT_TEXT_X 80
#define HLT_BTN_X 315
#define HLT_TEXT_LEN (HLT_BTN_X-HLT_TEXT_X)-10

#define HIGHLIGHT_Y_SEP 30
#define HLT_ADDRESS_Y 30
#define HLT_SYMBOL_Y HLT_ADDRESS_Y + HIGHLIGHT_Y_SEP
#define HLT_MODULE_Y HLT_SYMBOL_Y + HIGHLIGHT_Y_SEP
#define HLT_EXCEPT_Y HLT_MODULE_Y + HIGHLIGHT_Y_SEP

HighlightSelectionFrame::HighlightSelectionFrame(agui::Gui *widgets, VISSTATE *state, agui::Font *font)
{
	clientState = state;
	highlightButtonListener *highlightBtnListen;

	highlightFrame = new agui::Frame;
	highlightFrame->setSize(400, 200);
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
	symbolDropdown->setText(" 0 Called Symbols");
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
	moduleDropdown->setText(" 0 Loaded Modules");
	moduleDropdown->setSize(HLT_TEXT_LEN, 20);
	highlightFrame->add(moduleDropdown);

	moduleBtn = new agui::Button;
	moduleBtn->setLocation(HLT_BTN_X, HLT_MODULE_Y);
	moduleBtn->setText("Highlight");
	moduleBtn->resizeToContents();
	highlightBtnListen = new highlightButtonListener(clientState, HL_HIGHLIGHT_MODULE, this);
	moduleBtn->addActionListener(highlightBtnListen);
	highlightFrame->add(moduleBtn);


	exceptionLabel = new agui::Label;
	exceptionLabel->setLocation(HLT_TEXT_X+40, HLT_EXCEPT_Y);
	exceptionLabel->setText("0 Exceptions");
	exceptionLabel->resizeToContents();
	highlightFrame->add(exceptionLabel);

	exceptionBtn = new agui::Button;
	exceptionBtn->setLocation(HLT_BTN_X, HLT_EXCEPT_Y);
	exceptionBtn->setText("Highlight");
	exceptionBtn->resizeToContents();
	highlightBtnListen = new highlightButtonListener(clientState, HL_HIGHLIGHT_EXCEPTIONS, this);
	exceptionBtn->addActionListener(highlightBtnListen);
	highlightFrame->add(exceptionBtn);

	agui::Button *closeBtn = new agui::Button;
	closeBtn->setText("X");
	closeBtn->setMargins(2, 5, 2, 5);
	closeBtn->resizeToContents();
	closeBtn->setLocation(highlightFrame->getWidth() - closeBtn->getWidth()-15, 5);
	closeBtn->addActionListener(highlightBtnListen);
	highlightFrame->add(closeBtn);
}