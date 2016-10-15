rgat 0.3 (unstable preview 'the features are back' release) https://github.com/ncatlin/drgat 

Installation
---------------
It's built to depend on the Windows 10 Universal CRT so if you have a version lower 
than that you might need to install it: https://support.microsoft.com/en-gb/kb/2999226

Unzip it, run.

Try to execute something. If you get an error then you likely need to install the 
Visual C++ Redistributable for Visual Studio 2012, because reasons.
See here: https://www.microsoft.com/en-gb/download/details.aspx?id=30679

It should create a default config file at start up, feel free to customise.

Running
----------
Virtual Machines and OpenGL do not get on well together. VMWare Workstation with a Win 7 guest 
works but VirtualBox tends to crash.

Run, save and load traces from the file menu. Other functionality should be reasonably self 
explanatory from the other menus.

run from the command line with -h to get a list of command line options. 
Ctrl-C will force rgat to save everything it has so far and quit.

Graph navigation is intended to be similar to Google Earth: drag it with the mouse and zoom 
with the scroll wheel. Num pad 7,8,1 and 2 allow finer grained zoom control.

Press 'n' to stop the stuff on the back of the sphere cluttering up your view, and 't' and 'm' 
to toggle instruction and dll text to the situation if the default's don't work for the situation.

Use the arrow keys to stretch and compress the graph you are looking at. Turn off autoscaling 
in the options menu if rgat doesn't like it.