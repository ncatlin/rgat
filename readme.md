# rgat
An instruction trace visualisation tool intended to help reverse engineers make the link between target behaviour and code

## What is rgat?

rgat uses dynamic binary instrumentation (courtesy of DynamoRIO) to produce graphs from running executables. 
It creates static and animated visualisations in real-time to support types of analysis that might be a lot more cumbersome with 
disassemblers and debuggers alone.

[This page](https://github.com/ncatlin/rgat/wiki) explains what kind of things you can and can't do with it but basically, it looks like this:

Live animation:

![image](https://github.com/ncatlin/ncatlin/raw/master/ffox-cylinder-anim.gif)

Edge frequency Heatmap:
  
![gametime heatmap](https://github.com/ncatlin/ncatlin/raw/master/heatmapfront.png)

Static view zoomed into individual instructions:

![Static view zoomed into individual instructions](https://github.com/ncatlin/ncatlin/raw/master/frontpage1.png)

You may also want a brief introduction to the [graph layout](https://github.com/ncatlin/rgat/wiki/Graph-Layout).

## Latest Version

Version 0.5.0 is here: [zip (38MB)](https://github.com/ncatlin/rgat/releases/download/0.5.0/rgat-0.5.0.zip)/[7z (22MB)](https://github.com/ncatlin/rgat/releases/download/0.5.0/rgat-0.5.0.7z) for Windows x86 and x64 binary targets. rgat itself is compiled for running on x64 hosts.

This version sees the entire frontend UI reimplemented in Qt. Allegro served its purpose but implementing new features with Qt is actually a pleasure rather than a struggle, which will encourage further development.

See the [CHANGELOG](https://github.com/ncatlin/rgat/raw/master/CHANGELOG.txt) for a list of changes.

## Download/Installation

It's built to depend on the Windows 10 Universal CRT so if you have a version lower than that you might need to [install it](https://support.microsoft.com/en-gb/kb/2999226)

Unzip it, run it.

Try to execute something. If you get an error then you likely need to install the [Visual C++ Redistributable for Visual Studio 2012](https://www.microsoft.com/en-gb/download/details.aspx?id=30679), because of reasons.

## Problems

See [Issues](https://github.com/ncatlin/rgat/issues) and [Limitations](https://github.com/ncatlin/rgat/wiki#limitations)

## Excuses

This is an unstable preview release. I promise not to use that excuse when the basic functionality has been done. 

Its reliance on DynamoRIO means that rgat suffers from all of the same limitations. In particular - it won't currently instrument x86 binaries on the new Ryzen processors. 

99% of problems you find will be my fault, though. Instrumenting arbitrary code - especially malicious obfuscated code - tends to present a *lot* of edge cases.

## 'rgat'?

'runtime graph analysis tool' or 'ridiculous graph analysis tool', depending on your fondness for the concept.

## Credit where it is due

rgat relies upon: 

* [DynamoRIO](https://github.com/DynamoRIO/) for generating instruction [opcode] traces
* [Capstone](http://www.capstone-engine.org/) for disassembling them
* [Qt](https://www.qt.io/) for managing OpenGL and handling input
* [rapidjson](http://rapidjson.org) used for serialising traces
* [Base 64 code](http://www.adp-gmbh.ch/cpp/common/base64.html) for encoding symbol/module path strings
* [pe-parse] (https://github.com/trailofbits/pe-parse) which performs some binary header analysis
