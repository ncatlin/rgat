# rgat
An instruction trace visualisation tool intended to help reverse engineers make the link between target behaviour and code

## What is rgat?

rgat uses dynamic binary instrumentation (courtesy of DynamoRIO) to produce graphs from running executables. 
It creates static and animated visualisations in real-time to support types of analysis that might be a lot more cumbersome with 
disassemblers and debuggers alone.

[This page](https://github.com/ncatlin/rgat/wiki) explains what kind of things you can and can't do with it but basically, it looks like this:

Live animation:

![image](https://github.com/ncatlin/ncatlin/raw/master/firefox-live-small.gif)

Edge frequency Heatmap:
  
![gametime heatmap](https://github.com/ncatlin/ncatlin/raw/master/heatmapfront.png)

Static view zoomed into individual instructions:

![Static view zoomed into individual instructions](https://github.com/ncatlin/ncatlin/raw/master/frontpage1.png)

You may also want a brief introduction to the [graph layout](https://github.com/ncatlin/rgat/wiki/Graph-Layout).

## Latest Version

Version 0.3 is [here](https://github.com/ncatlin/rgat/raw/master/rgat-0.3.zip) for Windows x86 targets only, at the moment. Most of the file size is the included minimal DynamoRIO distribution.

Replay is back with a significantly improved interface, including a progress control slider.

Graph divergence is also back, but less precise.

See the [CHANGELOG](https://github.com/ncatlin/rgat/raw/master/CHANGELOG.txt) for further details. 

For the next version I plan to add support 64 bit executables.

## Download/Installation

It's built to depend on the Windows 10 Universal CRT so if you have a version lower than that you might need to [install it](https://support.microsoft.com/en-gb/kb/2999226)

Unzip it, run it.

Try to execute something. If you get an error then you likely need to install the [Visual C++ Redistributable for Visual Studio 2012](https://www.microsoft.com/en-gb/download/details.aspx?id=30679), because of reasons.

It should create a default config file at start-up, feel free to customise.

## Running

Virtual Machines and OpenGL do not get on well together. rgat works on VMWare Workstation with a Win 7 guest but it tends to crash VirtualBox. You can use it from the command line in environments without 3D capability and export the save file for analysis elsewhere.

Run, save and load traces from the file menu. Other functionality should be reasonably self-explanatory from the other menus.

run from the command line with -h to get a list of command line options. Ctrl-C will force rgat to save everything it has so far and quit.

Graph navigation is intended to be similar to Google Earth: drag it with the mouse and zoom with the scroll wheel. Num pad 7,8,1 and 2 allow finer grained zoom control.

Press 'n' to stop the stuff on the back of the sphere cluttering up your view, and 't' and 'm' to toggle instruction and dll text to the situation if the defaults don't work for the situation.

Use the arrow keys to stretch and compress the graph you are looking at. Turn off autoscaling in the options menu if rgat doesn't like it.

## Problems

See [Issues](https://github.com/ncatlin/rgat/issues) and [Limitations](https://github.com/ncatlin/rgat/wiki#limitations)

## Excuses

This is an unstable preview release. I promise not to use that excuse when the basic functionality has been done. 

Its reliance on DynamoRIO means that rgat suffers from all of the same limitations. 99% of problems you find will be my fault, though.

Instrumenting arbitrary code - especially malicious obfuscated code - tends to present a *lot* of edge cases.

## 'rgat'?

'runtime graph analysis tool' or 'ridiculous graph analysis tool', depending on your fondness for the concept.

## Credit where it is due

rgat relies upon: 

* [DynamoRIO](https://github.com/DynamoRIO/) for generating instruction [opcode] traces
* [Capstone](http://www.capstone-engine.org/) for disassembling them
* [Allegro 5](https://www.allegro.cc/) for managing OpenGL and handling input
* [agui](https://github.com/jmasterx/Agui/) for a lightweight UI that didn't involve distributing GTK/Qt/etc
* [base 64 code](http://www.adp-gmbh.ch/cpp/common/base64.html) for platform independent encoding.
