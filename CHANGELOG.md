Changelog

## [Unreleased]
### Added
- rgat has been completely re-written!
- Now written in C# to run on .NET Core
- The UI is now ImGui 
- Vulkan based GPU operations (replaces previous OpenGL use)
- A new, default, GPU accelerated force-directed graph layout
- Remote-tracing mode to allow use of GPU computed UI+graph layouts while recording the actual trace on a different machine. This has the twin benefit of allowing tracing on GPU-constrained environments and providing a separation between the tracing environment and the analysis environment (ie: for malware analysis).
- Circle graph layout
- Builtin graph/graph+previews/full window capture to PNG
- Builtin video capture mode, though the user needs to download FFmpeg seperately
- Filterable log window with alert/error/info/debug log granularity
- An optional bulk debug logging mode to write even more verbose logs to disk
- YARA and Detect it easy signature scanning for loaded binaries
- A signature downloader to fetch and update signature sets from GitHub
- A UI theme editor with support for importing/exporting
- A prototype visualiser bar under the main plot, which doubles as a replay control slider
- Blender-style keypress notifications
- Trace pausing/stepping. This does not use any debug APIs or registers.
- Auto centering feature to fit the graph in the window with a keypress
- Continuous auto-centering option to keep the graph centered
- Disassembly preview box to show which instructions have been executed recently
- Mini thread-activity plots in the preview pane
- A box shows the approximate camera location in the selected graphs preview
- The preview graph can be clicked to navigate around the selected graph
- Preview highlights now show as they are typed in the preview settings
- A testing framework with a JSON 'expected result' format. Tests can be queued and optionally continuously repeated.
- Keybind editor
- Update availability checks with categorised changelog display
- Update download & installation functionality
- Save format stable enough to avoid obsoleting any more saves (in the near future)) 
- Force-directed wireframe when rotating

### Changed
- Previous Saves Obsolete
- Previous Configs Obsolete

### Removed
- Trace divergence plot. It may be re-added in the future if there is demand.


## [0.5.2] - 2019-02-02
### Added
- Tracing tool tests 
- Plot size stretch/size adjustment buttons in the visualiser tab
- Mouseover menus for node labels
- Drag and drop support for binary targets
- Instrumentation can now be disabled/enabled on a per-module basis
- Lots of customisation settings

### Changed
- Instrumentation tool reimplemented in PIN due to poor DynamoRIO support for new Windows builds
- Libraries and bundled third-party tools updated
- Moved lots of redundant thread data to a parent process object to reduce save sizes
- Various code and UI improvements
- Previous Saves Obsolete

### Fixed
- High execution count instructions recorded more accurately

## [0.5.2] - 2017-08-25

### Changed
- Save files now support 64 bit traces
- Previous Saves Obsolete

### Fixed
- Lock related deadlock

## [0.5.1] - 2017-08-25
### Fixed
- Made the trace selector dropdown work in the visualiser pane
- The exit button in the file menu now works

## [0.5.0-Alpha] - 2017-08-24
### Added
- GUI reimplmented in Qt (was Allegro). Major features have their own tab.
- Trace analysis tab for text trace data

### Changed
- Previous Saves Obsolete
- Previous Configs Obsolete
- Configuration stored in registry instead of a .ini file

### Removed 
- Sphere layout
- Command line mode disabled pending reimplementation


## [0.4.2] - 2017-03-26
### Added
- Cylinder graph layout which handles large graph sizes much more cleanly and is now the default layout
- Menu for text toggling options [key: t]
- Graph text font slider
- Scaling reset feature
- Long edges now fade to show direction (bright->dull)

### Changed
- Save files now in JSON format, reducing rate of save obsolescence
- Previous saves obsolete
- Better handling for small displays
- Improved commmand line output
- Sphere scaling via arrow keys is now smoother
- More verbose drgat trace logging

### Fixed
- Ignore low backlog sizes to reduce label flickering
- Heatmap solver accuracy improvements. Known inaccuracies highlighted cyan on the heatmap
- Externs were creating false edges
- Fixed lack of long edge brightening during live animation
- Various crash, bug fixes

### Deprecated
- Sphere layout


## [0.4.1] - 2017-03-09
### Added
- Ability to switch between graph layouts at runtime
- Prototype tree graph which does not need to be rescaled as it grows
### Changed
- Previous saves obsolete
### Fixed
- Couple of crashes


## [0.4.0] - 2017-01-17
### Added
- Support for 64 bit windows targets
- Debug logging option to make tracing/reporting bugs easier.
### Changed
- Code improvements enabling new graph layouts 
- Previous Saves Obsolete

## [0.3.1] - 2016-10-16

### Fixed
- Added dynamorio debug dlls to distribution to squash warning messages
- Muted obnoxious warning for very high density graphs


## [0.3.0] - 2016-10-16

### Added
- New replay interface
- Replay progress control slider
- Trace divergence generation re-added

### Changed
- Debug symbol display now optional with key [i]
- Previous Saves Obsolete
- Previous Configs Obsolete

### Fixed
- Various minor fixes

## [0.2.0] - 2016-10-09
### Changed
- New trace generation algorithm using soft-deinstrumentation (Issue #6). Large performance improvement at the cost of not recording the exact order of certain blocks in busy areas.
- Heatmap generation changed to use a network solver

### Fixed
- Graph generation errors fixed
- Various crashes

### Removed
- Trace Replay
- Trace Divergence Plotting

## [0.1.4] - 2016-10-04
### Fixed 
- Thread termination more reliable
- Fixed crashes related to heatmap renderering
- Fixed a crash during rescaling
- Fixed text sometimes not appearing while zoomed in

## [0.1.3] - 2016-10-04
### Added
- Implemented handling for exceptions in trace targets	
- Highlight window auto-refresh

### Changed
- Previous Saves Obsolete
- Previous Configs Obsolete

### Fixed 
- Other minor fixes

## [0.1.2] - 2016-10-03

### Changed
- Improved performance with multithreaded targets

### Fixed
- Prevented loading of pre-existing PID's		
		

## [0.1.1] - 2016-10-02
### Fixed
- Made trace saving thread safe
- Minor miscellaneous fixes

## [0.1.0] - 2016-10-02

### Added
- Initial preview release
