[![MSBuild](https://github.com/ncatlin/rgatPrivate/actions/workflows/BuildWindows.yml/badge.svg)](https://github.com/ncatlin/rgatPrivate/actions/workflows/BuildWindows.yml)

# rgat
An instruction trace visualisation tool intended to help reverse engineers make the link between target behaviour and code

Feb 2021 note: A full re-write is in progress and should be ready for release in the next few months

## What is rgat?

rgat uses dynamic binary instrumentation (courtesy of DynamoRIO) to produce graphs from running executables. 
It creates static and animated visualisations in real-time to support types of analysis that might be a lot more cumbersome with 
disassemblers and debuggers alone.

[This page](https://github.com/ncatlin/rgat/wiki) explains what kind of things you can and can't do with it but basically, it (used to) look like this and I haven't updated the images yet:

Live animation:

![image](https://github.com/ncatlin/ncatlin/raw/master/ffox-cylinder-anim.gif)

Edge frequency Heatmap:
  
![gametime heatmap](https://github.com/ncatlin/ncatlin/raw/master/heatmapfront.png)

Static view zoomed into individual instructions:

![Static view zoomed into individual instructions](https://github.com/ncatlin/ncatlin/raw/master/frontpage1.png)

You may also want a brief introduction to the [graph layout](https://github.com/ncatlin/rgat/wiki/Graph-Layout).

## Latest Version 

Version 0.5.3 (Feb 2019) is here: [7z (16MB)](https://github.com/ncatlin/rgat/releases/download/0.5.3/rgat-0.5.3.7z) for Windows x86 and x64 binary targets.
rgat itself is compiled for running on x64 hosts.

At some point in the last year of no releases i've moved instrumentation to PIN because it worked more reliably at the time, especially on my AMD processor (which is a bit odd). I plan to have both DynamoRIO and PIN clients working to give a bit of redundancy.

Lot's of other usability changes, mainly around the UI and a settings dialog.

Preperation has been made for a Linux port. My TODO list is gigantic but getting a proper tree rendering is the main priority to make the visualisations actually useful on a wide variety of binaries.

See the [CHANGELOG](https://github.com/ncatlin/rgat/raw/master/CHANGELOG.txt) for a list of changes.

## Download/Installation

Try to execute something. If you have 'DLL not found errors', install the VS 2017 redistributable 
	https://go.microsoft.com/fwlink/?LinkId=746572

## Problems

See [Issues](https://github.com/ncatlin/rgat/issues) and [Limitations](https://github.com/ncatlin/rgat/wiki#limitations)

## Excuses

This is an unstable preview release. I promise not to use that excuse when the basic functionality has been done. 

99% of problems you find will be my fault, though. Instrumenting arbitrary code - especially malicious obfuscated code - tends to present a *lot* of edge cases.

## 'rgat'?

'runtime graph analysis tool' or 'ridiculous graph analysis tool', depending on your fondness for the concept.

## Credit where it is due

rgat relies upon: 

* [Intel PIN](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool) for generating instruction [opcode] traces
* [Capstone](http://www.capstone-engine.org/) for disassembling them
* [Qt](https://www.qt.io/) for managing OpenGL and handling input
* [rapidjson](http://rapidjson.org) used for serialising traces
* [Base 64 code](http://www.adp-gmbh.ch/cpp/common/base64.html) for encoding symbol/module path strings
* [pe-parse](https://github.com/trailofbits/pe-parse) which performs some binary header analysis
