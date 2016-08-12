cmake_minimum_required(VERSION 2.6)

project(agui)

OPTION(WANT_SHARED "Build agui and the backend as a shared library" OFF) 

OPTION(WANT_ALLEGRO5_BACKEND "Build the Allegro 5 backend" ON) 

OPTION(WANT_SFML2_BACKEND "Build the SFML2 backend" OFF) 

if(APPLE AND NOT IPHONE)
    set(MACOSX 1)
endif(APPLE AND NOT IPHONE)

if(MACOSX)
ADD_DEFINITIONS("-x objective-c++")
endif(MACOSX)

if(MACOSX)
set(CMAKE_EXE_LINKER_FLAGS "-framework Cocoa")
find_library(COCOA_LIBRARY Cocoa)
endif(MACOSX)

set(CLIPBOARD_SOURCE)

if(WIN32)
set(CLIPBOARD_SOURCE src/Agui/Clipboard/WinClipboard.cpp)
endif(WIN32)

if(MACOSX)
set(CLIPBOARD_SOURCE src/Agui/Clipboard/OSXClipboard.mm)
endif(MACOSX)


set(AGUI_SOURCES
    ${CLIPBOARD_SOURCE}
    src/Agui/Clipboard/Clipboard.cpp
	src/Agui/ActionEvent.cpp
	src/Agui/ActionListener.cpp
	src/Agui/BaseTypes.cpp
	src/Agui/BlinkingEvent.cpp
	src/Agui/BorderLayout.cpp
	src/Agui/CursorProvider.cpp
	src/Agui/Color.cpp
	src/Agui/Dimension.cpp
	src/Agui/EmptyWidget.cpp
	src/Agui/EventArgs.cpp
	src/Agui/FlowLayout.cpp
	src/Agui/FocusListener.cpp
	src/Agui/FocusManager.cpp
	src/Agui/Font.cpp
	src/Agui/Graphics.cpp
	src/Agui/GridLayout.cpp
	src/Agui/Gui.cpp
	src/Agui/Image.cpp
	src/Agui/Input.cpp
	src/Agui/KeyboardListener.cpp
	src/Agui/Layout.cpp
	src/Agui/MouseListener.cpp
	src/Agui/Point.cpp
	src/Agui/Rectangle.cpp
	src/Agui/ResizableText.cpp
	src/Agui/ResizableBorderLayout.cpp
	src/Agui/SelectionListener.cpp
	src/Agui/TableLayout.cpp
	src/Agui/Transform.cpp
	src/Agui/TopContainer.cpp
	src/Agui/Widget.cpp
	src/Agui/WidgetListener.cpp
	src/Agui/Widgets/Button/Button.cpp
	src/Agui/Widgets/Button/ButtonGroup.cpp
	src/Agui/Widgets/Button/ButtonListener.cpp
	src/Agui/Widgets/CheckBox/CheckBox.cpp
	src/Agui/Widgets/CheckBox/CheckBoxListener.cpp
	src/Agui/Widgets/DropDown/DropDown.cpp
	src/Agui/Widgets/DropDown/DropDownListener.cpp
	src/Agui/Widgets/Frame/Frame.cpp
	src/Agui/Widgets/Frame/FrameListener.cpp
	src/Agui/Widgets/ImageWidget/ImageWidget.cpp
	src/Agui/Widgets/Label/Label.cpp
	src/Agui/Widgets/Label/LabelListener.cpp
	src/Agui/Widgets/ListBox/ListBox.cpp
	src/Agui/Widgets/PopUp/PopUpMenu.cpp
	src/Agui/Widgets/PopUp/PopUpMenuItem.cpp
	src/Agui/Widgets/ListBox/ListBoxListener.cpp
	src/Agui/Widgets/RadioButton/RadioButton.cpp
	src/Agui/Widgets/RadioButton/RadioButtonListener.cpp
	src/Agui/Widgets/RadioButton/RadioButtonGroup.cpp
	src/Agui/Widgets/ScrollBar/HScrollBar.cpp
	src/Agui/Widgets/ScrollBar/HScrollBarListener.cpp
	src/Agui/Widgets/ScrollBar/VScrollBar.cpp
	src/Agui/Widgets/ScrollBar/VScrollBarListener.cpp
	src/Agui/Widgets/ScrollPane/ScrollPane.cpp
	src/Agui/Widgets/Slider/Slider.cpp
	src/Agui/Widgets/Slider/SliderListener.cpp
	src/Agui/Widgets/Tab/Tab.cpp
	src/Agui/Widgets/Tab/TabbedPane.cpp
	src/Agui/Widgets/Tab/TabbedPaneListener.cpp
	src/Agui/Widgets/TextBox/TextBox.cpp
	src/Agui/Widgets/TextBox/TextBoxListener.cpp
	src/Agui/Widgets/TextBox/ExtendedTextBox.cpp
	src/Agui/Widgets/TextField/TextField.cpp
	src/Agui/Widgets/TextField/TextFieldListener.cpp
	src/Agui/Widgets/ToolTip/ToolTip.cpp
	)

set(ALLEGRO5_BACKEND_SOURCES
	src/Agui/Backends/Allegro5/Allegro5Font.cpp
	src/Agui/Backends/Allegro5/Allegro5FontLoader.cpp
	src/Agui/Backends/Allegro5/Allegro5Graphics.cpp
	src/Agui/Backends/Allegro5/Allegro5Image.cpp
	src/Agui/Backends/Allegro5/Allegro5ImageLoader.cpp
	src/Agui/Backends/Allegro5/Allegro5Input.cpp
	src/Agui/Backends/Allegro5/Allegro5CursorProvider.cpp
	)
	
set(SFML2_BACKEND_SOURCES
	src/Agui/Backends/SFML2/SFML2Font.cpp
	src/Agui/Backends/SFML2/SFML2FontLoader.cpp
	src/Agui/Backends/SFML2/SFML2Graphics.cpp
	src/Agui/Backends/SFML2/SFML2Image.cpp
	src/Agui/Backends/SFML2/SFML2ImageLoader.cpp
	src/Agui/Backends/SFML2/SFML2Input.cpp
	)

	include_directories (./include) 
if(WANT_SHARED)
  add_library(agui SHARED ${AGUI_SOURCES})
  
   if(MACOSX)
  target_link_libraries (agui ${COCOA_LIBRARY} )
  endif(MACOSX)
  
  set_target_properties(agui PROPERTIES DEFINE_SYMBOL "AGUI_BUILD")
  
  if(WANT_ALLEGRO5_BACKEND)
    add_library(agui_allegro5 SHARED ${ALLEGRO5_BACKEND_SOURCES})
  set_target_properties(agui_allegro5 PROPERTIES DEFINE_SYMBOL "AGUI_BACKEND_BUILD")
  target_link_libraries (agui_allegro5 agui)
  endif()
  
    if(WANT_SFML2_BACKEND)
    add_library(agui_sfml2 SHARED ${SFML2_BACKEND_SOURCES})
  set_target_properties(agui_sfml2 PROPERTIES DEFINE_SYMBOL "AGUI_BACKEND_BUILD")
  target_link_libraries (agui_sfml2 agui)
  endif()
  
else()
  add_library(agui STATIC ${AGUI_SOURCES})
  
  if(MACOSX)
  target_link_libraries (agui ${COCOA_LIBRARY} )
  endif(MACOSX)
  
    if(WANT_ALLEGRO5_BACKEND)
    add_library(agui_allegro5 STATIC ${ALLEGRO5_BACKEND_SOURCES})
    set_target_properties(agui_allegro5 PROPERTIES COMPILE_DEFINITIONS "ALLEGRO_STATICLINK")
  endif()
  
    if(WANT_SFML2_BACKEND)
    add_library(agui_sfml2 STATIC ${SFML2_BACKEND_SOURCES})
    set_target_properties(agui_sfml2 PROPERTIES COMPILE_DEFINITIONS "SFML_STATIC")
  endif()
endif()
 