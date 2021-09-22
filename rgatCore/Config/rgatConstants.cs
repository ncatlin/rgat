﻿using System.Collections.Generic;

namespace rgat
{
    public class CONSTANTS
    {
        public static class PROGRAMVERSION
        {
            /// <summary>
            /// Major version
            /// </summary>
            public const int MAJOR = 0;
            /// <summary>
            /// Minor Version
            /// </summary>
            public const int MINOR = 6;
            /// <summary>
            /// Patch version
            /// </summary>
            public const int PATCH = 0;
            /// <summary>
            /// Optional, non-unique name for the given version (preview, release, bugfix, etc)
            /// Other values must still be unique (eg: '1.1.1 Preview' and '1.1.1 Release' cannot both exist)
            /// </summary>
            public const string PATCHNAME = null;

            /// <summary>
            /// The simple major.minorpath version of this rgat build. should probably reference the assembly instead. todo
            /// </summary>
            public static string RGAT_VERSION => $"{PROGRAMVERSION.MAJOR}.{PROGRAMVERSION.MINOR}.{PROGRAMVERSION.PATCH}";
            /// <summary>
            /// The SemVer version of rgat
            /// </summary>
            public static System.Version RGAT_VERSION_SEMANTIC => new System.Version(RGAT_VERSION);
        }




        public static class UI
        {
            /// <summary>
            /// Limit length of displayed module paths
            /// </summary>
            public const int MAX_MODULE_PATH_LENGTH = 50;
            /// <summary>
            /// Width of the preview pane
            /// </summary>
            public const int PREVIEW_PANE_WIDTH = 300;
            /// <summary>
            /// Height of each preview graph
            /// </summary>
            public const int PREVIEW_PANE_GRAPH_HEIGHT = 150;
            /// <summary>
            /// Horizontal preview graph padding
            /// </summary>
            public const float PREVIEW_PANE_X_PADDING = 3;
            /// <summary>
            /// Vertical preview graph padding
            /// </summary>
            public const float PREVIEW_PANE_Y_SEP = 6;
            /// <summary>
            /// Timer for tasks that need doing regularly but not every frame
            /// </summary>
            public const uint UI_SHORT_TIMER_INTERVAL = 500;
            /// <summary>
            /// Timer for occasional housekeeping tasks
            /// </summary>
            public const uint UI_LONG_TIMER_INTERVAL = 60000;
            /// <summary>
            /// How long the screenshot icon will stay on the status bar
            /// </summary>
            public const double SCREENSHOT_ICON_LINGER_TIME = 3;
            /// <summary>
            /// How fast the screenshot feedback rectangle will collapse
            /// 10 = it will linger for 1/10th of a second
            /// </summary>
            public const double SCREENSHOT_ANIMATION_RECT_SPEED = 10;
            /// <summary>
            /// How long alerts will stay in the alert pane
            /// </summary>
            public const double ALERT_TEXT_LINGER_TIME = 9000;
            public const double ALERT_CIRCLE_ANIMATION_TIME = 600;
            public const double ALERT_CIRCLE_ANIMATION_RADIUS = 100;

            public const int FILEPICKER_HISTORY_MAX = 10;
        }


        public static class Anim_Constants
        {
            public const ulong ASSUME_INS_PER_BLOCK = 10; //farcical but useful way to estimate how long a block spends executing
            public const float ANIM_INACTIVE_NODE_ALPHA = 0.00f;
            public const float ANIM_INACTIVE_EDGE_ALPHA = 0.00f;
            public const float EXTERN_FLOAT_RATE = 0.3f;
            public const int KEEP_BRIGHT = -1;
            public const float DEFAULT_NODE_DIAMETER = 200f;

        }

        public static class Layout_Constants
        {
            public const float MinimumTemperature = 0.1f;
            public const float TemperatureStepMultiplier = 0.99f;
        }

        public static class NETWORK
        {
            public const int DefaultKeyLength = 9;
            //number of times a host can try to connect with the wrong key
            public const int HostLockoutLimit = 5;
            //number of wrong-key connections allowed before the listener disables itself
            public const int TotalLockoutLimit = 15;
            public const int InterfaceRefreshIntervalMS = 6000;
            /// <summary>
            /// How long to wait between checks for new versions (check only happens on startup)
            /// </summary>
            public const int UpdateCheckMinimumDelayMinutes = 6 * 60;
        }

        public static class TRACING
        {
            public const int TagCacheSize = 1024;
        }


        /// <summary>
        /// Expected code certificate subjects for binaries rgat will load or execute
        /// </summary>
        public static class SIGNERS
        {
            /// <summary>
            /// Expected code certificate subject for pin.exe binaries
            /// </summary>
            public const string PIN_SIGNERS = "Intel Corporation";
            /// <summary>
            /// Expected code certificate subject for rgat binaries
            /// </summary>
            public const string RGAT_SIGNERS = "rgat dev";
        }


        public static class TESTS
        {
            /// <summary>
            /// The file extension for test description data files
            /// </summary>
            public const string testextension = ".test.json";
        }

        /*
         * 
         * Enums
         * 
         */
        public enum eNodeType { eInsUndefined, eInsJump, eInsReturn, eInsCall };

        /// <summary>
        /// Types for nodes edges which control how they are laid out or rendered
        /// </summary>
        public enum eEdgeNodeType
        {
            /// <summary>
            /// Edge to a call instruction
            /// </summary>
            eEdgeCall = 0, 
            /// <summary>
            /// Edge to an instruction that has already been visited from another instruction
            /// </summary>
            eEdgeOld, 
            /// <summary>
            /// Edge from a return instruction
            /// </summary>
            eEdgeReturn, 
            /// <summary>
            /// Edge of an API call
            /// </summary>
            eEdgeLib, 
            /// <summary>
            /// Edge to an instruction that has not been executed before
            /// </summary>
            eEdgeNew,
            /// <summary>
            /// Edge to an exception node
            /// </summary>
            eEdgeException, 
            /// <summary>
            /// Edge to another instruction in the same basic block
            /// </summary>
            eNodeNonFlow,
            /// <summary>
            /// An unconditional jump instruction
            /// </summary>
            eNodeJump,
            /// <summary>
            /// A call instruction
            /// </summary>
            eNodeCall, 
            /// <summary>
            /// A return instruction
            /// </summary>
            eNodeReturn, 
            /// <summary>
            /// An API call
            /// </summary>
            eNodeExternal, 
            /// <summary>
            /// An exception source
            /// </summary>
            eNodeException, 
            /// <summary>
            /// Invalid
            /// </summary>
            eENLAST, 
            /// <summary>
            /// The first instruction in a thread
            /// </summary>
            eFIRST_IN_THREAD = 99
        };

        public enum eRenderingMode { eStandardControlFlow, eHeatmap, eConditionals, eDegree }

        /// <summary>
        /// Category of filter used to highlight nodes
        /// </summary>
        public enum HighlightType { 
            /// <summary>
            /// An external API call
            /// </summary>
            Externals, 
            /// <summary>
            /// A memory address
            /// </summary>
            Addresses, 
            /// <summary>
            /// An exception
            /// </summary>
            Exceptions };


        /// <summary>
        /// A filesystem path setting
        /// </summary>
        public enum PathKey
        {
            /// <summary>
            /// Path of Intel pin.exe
            /// </summary>
            PinPath, 
            /// <summary>
            /// Path of the 32 bit rgat pintool
            /// </summary>
            PinToolPath32, 
            /// <summary>
            /// Path of the 64 bit rgat pintool
            /// </summary>
            PinToolPath64, 
            /// <summary>
            /// Path of ffmpeg.exe for video recording
            /// </summary>
            FFmpegPath,
            /// <summary>
            /// Directory to save traces to
            /// </summary>
            TraceSaveDirectory, 
            /// <summary>
            /// Directory where rgat tests are stored
            /// </summary>
            TestsDirectory, 
            /// <summary>
            /// Directory where Detect It easy signatures are stored
            /// </summary>
            DiESigsDirectory, 
            /// <summary>
            /// Directory where Yara rules are stored
            /// </summary>
            YaraRulesDirectory, 
            /// <summary>
            /// Directory to save screenshots/videos to
            /// </summary>
            MediaCapturePath
        }


        /// <summary>
        /// Describes the state of a conditional jump
        /// </summary>
        public enum ConditionalType
        {
            /// <summary>
            /// The instruction always falls through
            /// </summary>
            NOTCONDITIONAL = 0,
            /// <summary>
            /// The instruction is a conditional jump
            /// </summary>
            ISCONDITIONAL = 1,
            /// <summary>
            /// The conditional jump was not taken
            /// </summary>
            CONDFELLTHROUGH = 2,
            /// <summary>
            /// The conditional jump was taken
            /// </summary>
            CONDTAKEN = 4,
            /// <summary>
            /// The conditional jump was taken and fell though in the same trace
            /// </summary>
            CONDCOMPLETE = (ISCONDITIONAL | CONDFELLTHROUGH | CONDTAKEN)
        }


        public enum eKeybind
        {
            /// <summary>
            /// Shift the graph left (actually moves the camera right)
            /// </summary>
            MoveLeft,
            /// <summary>
            /// Shift the graph right (actually moves the camera left)
            /// </summary>
            MoveRight,
            /// <summary>
            /// Shift the graph up (actually moves the camera down)
            /// </summary>
            MoveUp,
            /// <summary>
            /// Shift the graph down (actually moves the camera up)
            /// </summary>
            MoveDown,
            /// <summary>
            /// Move the camera forward towards the graph
            /// </summary>
            ZoomIn,
            /// <summary>
            /// Move the camera back away from the graph
            /// </summary>
            ZoomOut,
            PitchXFwd,
            PitchXBack,
            YawYLeft,
            YawYRight,
            RollGraphZAnti,
            RollGraphZClock,
            CenterFrame,
            LockCenterFrame,
            /// <summary>
            /// Close the open dialog/menu
            /// </summary>
            Cancel, ToggleHeatmap, ToggleConditionals, RaiseForceTemperature,
            ToggleAllText, ToggleInsText, ToggleLiveText, QuickMenu,
            CaptureGraphImage, CaptureGraphPreviewImage, CaptureWindowImage, ToggleVideo, PauseVideo
        }

        public enum eSignatureType { YARA, DIE };

        public static class LayoutStyles
        {

            public enum Style { CylinderLayout, ForceDirected3DNodes, ForceDirected3DBlocks, Circle, Invalid };

            static readonly List<Style> _cacheLayouts = new List<Style>() { Style.ForceDirected3DBlocks, Style.ForceDirected3DNodes };

            public static bool RequiresCaching(Style layout) => _cacheLayouts.Contains(layout);
            public static bool IsForceDirected(Style layout) => RequiresCaching(layout);
        }



    }
}
