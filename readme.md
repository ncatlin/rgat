# rgat
An instruction trace visualisation tool intended to help reverse engineers make the link between target behaviour and code

## What is rgat?

rgat uses dynamic binary instrumentation (courtesy of DynamoRIO) to produce graphs from running executables. 
It creates visualisations in realtime to support types of analysis that might be a lot more cumbersome with 
disassemblers and debuggers alone.

[This page](https://github.com/ncatlin/rgat/wiki) explains what kind of things you can and can't do with it but basically it looks like this:

![sample image](https://github.com/ncatlin/ncatlin/raw/master/firefox-live-small.gif)

You may also want a brief introduction to the [graph layout](https://github.com/ncatlin/rgat/wiki/Graph-Layout).

## Download/Installation

It's [here](link), for instrumenting Windows x86 targets only, at the moment. Most of the file size is the included minimal DynamoRIO distribution.

It's built to depend on the Windows 10 Universal CRT so if you have a version lower than that you might need to [install it](https://support.microsoft.com/en-gb/kb/2999226)

Unzip it, run it.

Try to execute something. If you get an error then you likely need to install the [Visual C++ Redistributable for Visual Studio 2012](https://www.microsoft.com/en-gb/download/details.aspx?id=30679), because reasons.

It should create a default config file at start up, feel free to customise.

## Problems

See [Issues](https://github.com/ncatlin/rgat/issues) and [Limitations](https://github.com/ncatlin/rgat/wiki#limitations)

## Excuses

It's reliance on DynamoRIO means that rgat suffers from all of the same limitations and many more as well.

Instrumenting arbitrary code - especially malicious obfuscated code - tends to present a *lot* of edge cases.

## Credit where it is due

rgat uses 

* [DynamoRIO](https://github.com/DynamoRIO/) for generating instruction [opcode] traces
* [Capstone](http://www.capstone-engine.org/) for disassembling them
* [Allegro 5](https://www.allegro.cc/) for managing OpenGL and handling input
* [agui](https://github.com/jmasterx/Agui/) for a lightweight UI that didn't involve distributing GTK/Qt/etc
* [base 64 code from René Nyffenegger](http://www.adp-gmbh.ch/cpp/common/base64.html) for platform independent encoding.
