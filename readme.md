[![MSBuild](https://github.com/ncatlin/rgat/actions/workflows/BuildWindows.yml/badge.svg)](https://github.com/ncatlin/rgat/actions/workflows/BuildWindows.yml)

*Note: rgat is an active research project that has emerged from a long re-write. 0.6.X will be a series of preview builds. Don't let the flashy videos entice you into thinking that it will be useful on real targets*

[Look here for documentation](https://ncatlin.github.io/rgatPages/)

**rgat** is a dynamic binary analysis tool for gathering and visualising instruction traces. It is intended to help software reverse engineers in bridging the gap between the high level API view of malware sandboxes and the low level function view of disassemblers and decompilers - particularly where code obfuscation is present. 


![Switching between different plots](https://ncatlin.github.io/rgatPages/img/plotgif.gif)

*Different layouts*

![The UI with a heatmap graph](https://ncatlin.github.io/rgatPages/img/heatmap_UI.png)
*Find busy areas with a heatmap render*

<video src='https://user-images.githubusercontent.com/5470374/140196228-e0beab8f-2aea-4593-8173-ffdb69962c5a.mp4' controls='controls' style='max-width: 800px;'></video>

*Live cylinder plot of UPX packing a binary*

<video src="https://user-images.githubusercontent.com/5470374/139732976-37df2626-7993-4398-92cd-2720c8acfdbe.mp4" controls="controls" style="max-width: 800px;"></video>
*'Detonate' malware into a force-directed graph layout*

### Features

- GPU accelerated graph layout
- Thread preview graphs
- Trace animation replay
- Heatmap generation
- API recording
- Signature scanning with YARA and partial Detect-It-Easy support
- Customisable instrumentation (module granularity)
- Remote tracing - perform tracing in real time over a network

See the [Changelog](https://github.com/ncatlin/rgat/blob/master/CHANGELOG.md) for a full list of features

See the [Trello](https://trello.com/b/OyO4A1O9/rgat) for the features under development or scheduled to be worked on and known bugs

It currently supports 32 and 64 bit Windows EXE's and DLL's, but it now runs on .NET so Linux support should be slightly less distant that it was a while ago. It won't work very well with .NET apps.


## Requirements and Installation

The two main requirements for 0.6.0 are:
- Windows, with the ability to run .NET 5 programs
- For the computer running the visualiser: A GPU with Vulkan driver support (ie: [_this_ test program](https://github.com/skeeto/vulkan-test) works)

##### To install
- If .NET 5+ isn't installed, [install it](https://dotnet.microsoft.com/download/dotnet/5.0/runtime)(run console apps -> x64). If nothing happens then running rgat in the console will tell you if this is the problem.
- Download the [latest release](https://github.com/ncatlin/rgat/releases) - currently 0.6.0
- Unzip rgat.exe *into its own directory*
- Run rgat.exe - it will unpack the tools it needs into the directory it is launched in
- Configure it to your liking in the settings
  
If nothing else you may want to get familiar with the [graph manipulation controls](rgatPages/userdocs/graph-manipulation.md)

##### To trace something
- Drag and drop a binary onto the UI
- Click 'Start Trace'
  
## Documentation

- [Usage Guide](https://ncatlin.github.io/rgatPages/userdocs/usage-overview)
- [How It Works/Development](https://ncatlin.github.io/rgatPages/devdocs/overview)

## Known Issues

- Pin's file API [doesn't play well with named pipes](https://trello.com/c/pqOdlGjc/256-sometimes-traces-just-dont-connect), so an unsafe API has to be used causing some traces to fail to start (especially .NET programs)
- A console window opens with rgat to enable interaction with console-enabled targets. Selecting text will hang the UI on any output until the selection is cleared - which might happen at startup.

### Technologies

- [Intel Pin](https://software.intel.com/content/www/us/en/develop/articles/pin-a-dynamic-binary-instrumentation-tool.html) for generating instruction traces
- [Veldrid](https://github.com/mellinoe/veldrid), a .NET graphics library
- [Dear ImGui](https://github.com/ocornut/imgui) providing the GUI, via [ImGui.NET](https://github.com/mellinoe/ImGui.NET)
- Force-directed graph layout based on Jared McQueen's [WebGL algorithm](https://github.com/jaredmcqueen/analytics/tree/eed32e17922ef16288984e27f46717e8b7a2d602)
- [Capstone](https://www.capstone-engine.org/) for disassembly
- [Yara](https://github.com/virustotal/yara), via the Airbus CERT [dnYara library](https://github.com/airbus-cert/dnYara)
- A woefully incomplete [.NET port](https://github.com/ncatlin/DiELibDotNet) of the [Detect-It-Easy engine](https://github.com/horsicq/DIE-engine)
- [PeNet](https://github.com/secana/PeNet) for static analysis of PE binaries

A full list and discussion of libraries can be found in the development documentation
