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
The class for the divergence/diff selection window
*/
#include "diffWindow.h"

int DiffSelectionFrame::getSelectedDiff() {
	if (firstDiffLabel->getCheckedState()) return 0;
	if (secondDiffLabel->getCheckedState()) return 1;
	return 0;
}

DiffSelectionFrame::DiffSelectionFrame(agui::Gui *widgets, VISSTATE *clientState, agui::Font *font) {
	int paneHeight = 400;
	diffFrame = new agui::Frame;
	diffFrame->setSize(480, paneHeight);
	diffFrame->setLocation(200, 300);
	diffFrame->setText("Select threads to compare->");
	diffFrame->setVisibility(false);
	widgets->add(diffFrame);

	agui::Label *selectLabel = new agui::Label;
	selectLabel->setText("Click graphs from preview pane to compare");
	selectLabel->setLocation(10, 20);
	selectLabel->resizeToContents();
	diffFrame->add(selectLabel);

	diffFont = font;
	firstDiffLabel = new agui::RadioButton;
	firstDiffLabel->setLocation(10, 70);
	firstDiffLabel->setFont(diffFont);
	firstDiffLabel->setText("Select Thread 1");
	firstDiffLabel->resizeToContents();
	firstDiffLabel->setChecked(true);
	diffFrame->add(firstDiffLabel);

	graph1Path = new agui::Label;
	graph1Path->setLocation(DIFF_INFOLABEL_X_OFFSET, 100);
	diffFrame->add(graph1Path);
	graph1Info = new agui::Label;
	graph1Info->setLocation(DIFF_INFOLABEL_X_OFFSET, 120);
	diffFrame->add(graph1Info);


	secondDiffLabel = new agui::RadioButton;
	secondDiffLabel->setLocation(10, 200);
	secondDiffLabel->setFont(diffFont);
	secondDiffLabel->setText("Select Thread 2");
	secondDiffLabel->resizeToContents();
	diffFrame->add(secondDiffLabel);

	graph2Path = new agui::Label;
	graph2Path->setLocation(DIFF_INFOLABEL_X_OFFSET, 230);
	diffFrame->add(graph2Path);
	graph2Info = new agui::Label;
	graph2Info->setLocation(DIFF_INFOLABEL_X_OFFSET, 250);
	diffFrame->add(graph2Info);


	RadioButtonListener *radiolisten = new RadioButtonListener(clientState, firstDiffLabel, secondDiffLabel);
	firstDiffLabel->addActionListener(radiolisten);
	secondDiffLabel->addActionListener(radiolisten);

	diffBtn = new agui::Button();
	diffBtn->setText("Compare");
	diffBtn->setEnabled(false);
	diffBtn->setLocation(170, paneHeight - 75);
	diffBtn->setSize(100, 40);
	diffBtn->setBackColor(agui::Color(210, 210, 210));

	CompareButtonListener *compareBtn = new CompareButtonListener(clientState);
	diffBtn->addActionListener(compareBtn);
	diffFrame->add(diffBtn);
}

thread_graph_data *DiffSelectionFrame::get_graph(int idx)
{
	if (idx == 1) return graph1;
	if (idx == 2) return graph2;
	return 0;
}

void DiffSelectionFrame::setDiffGraph(thread_graph_data *graph) {
	int graphIdx = getSelectedDiff();
	stringstream graphText;
	graphText << "[Thread " << std::to_string(graphIdx + 1) << "] PID:" << graph->pid << " TID:" << graph->tid;

	stringstream threadSummary;
	threadSummary << "Edges:" << graph->get_num_edges()
		<< " Verts:" << graph->get_num_nodes();

	if (graphIdx == 0)
	{
		firstDiffLabel->setText(graphText.str());
		firstDiffLabel->resizeToContents();
		graph1 = graph;
		graph1Path->setText(graph->modPath);
		graph1Info->setText(threadSummary.str());
	}
	else
	{
		secondDiffLabel->setText(graphText.str());
		secondDiffLabel->resizeToContents();
		graph2 = graph;
		graph2Path->setText(graph->modPath);
		graph2Info->setText(threadSummary.str());
	}

	if (graph1 && graph2)
		if (graph1 != graph2)
		{
			//int similarityScore = IMPLEMENT_ME(graph1, graph2);
			//set comparison label

			diffBtn->setEnabled(true);
			diffBtn->setBackColor(agui::Color(200, 200, 200));
			return;
		}

	diffBtn->setEnabled(false);
	diffBtn->setBackColor(agui::Color(128, 128, 128));
	return;
}
