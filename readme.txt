rgat 0.5.0-Alpha https://github.com/ncatlin/drgat 

Installation
---------------
It's built to depend on the Windows 10 Universal CRT so if you have a version lower 
than that you might need to install it: https://support.microsoft.com/en-gb/kb/2999226

It will run on Windows 7 (SP1) but getting the UCRT dependencies working for that OS can be tricky.

Unzip it, run.

Try to execute something. If you get an error then you likely need to install the 
Visual C++ Redistributable for Visual Studio 2012, because reasons.
See here: https://www.microsoft.com/en-gb/download/details.aspx?id=30679

The move to Qt placed the settings in the Windows registry. There isn't a settings dialog yet, 
so if the default for a setting doesn't work and there isn't a way to customise it somewhere 
in the program (such as for the paths), you may need to hunt it down in regedit. 
Try HKEY_CURRENT_USER/Software/rgat.

Running
----------
Virtual Machines and OpenGL often do not get on well together. 
VMWare Workstation works but VirtualBox tends to crash.