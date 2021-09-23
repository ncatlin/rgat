using System.Collections.Generic;

namespace rgat
{
    /// <summary>
    /// Various settings that won't need changing by the user. Probably.
    /// </summary>
    public class CONSTANTS
    {
        /// <summary>
        /// The rgat version
        /// </summary>
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



        /// <summary>
        /// UI constants
        /// </summary>
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
            /// <summary>
            /// How long to aniamate the alert circle
            /// </summary>
            public const double ALERT_CIRCLE_ANIMATION_TIME = 600;
            /// <summary>
            /// How big the alert animation circle is
            /// </summary>
            public const double ALERT_CIRCLE_ANIMATION_RADIUS = 100;
            /// <summary>
            /// Maxmimum directories to store in filepicker history
            /// </summary>
            public const int FILEPICKER_HISTORY_MAX = 10;
        }

        /// <summary>
        /// Animation constants
        /// </summary>
        public static class Anim_Constants
        {
            /// <summary>
            /// farcical but useful way to estimate how long a block spends executing
            /// </summary>
            public const ulong ASSUME_INS_PER_BLOCK = 10;
            //public const float ANIM_INACTIVE_NODE_ALPHA = 0.00f;
            //public const float ANIM_INACTIVE_EDGE_ALPHA = 0.00f;
            //public const float EXTERN_FLOAT_RATE = 0.3f;
            /// <summary>
            /// An enum for keeping the node/edge activated, but not implemented as an 
            /// </summary>
            public enum BRIGHTNESS {
                /// <summary>
                /// Maintain full alpha until deactivated
                /// </summary>
                KEEP_BRIGHT = -1 
            };

            /// <summary>
            /// Default node diameter in pixels
            /// </summary>
            public const float DEFAULT_NODE_DIAMETER = 200f;

        }

        /// <summary>
        /// Graph Layout Constants
        /// </summary>
        public static class Layout_Constants
        {
            /// <summary>
            /// The lowest temperature that is considered 'running'
            /// </summary>
            public const float MinimumTemperature = 0.1f;
            /// <summary>
            /// How much to reduce the temperature with every step
            /// </summary>
            public const float TemperatureStepMultiplier = 0.99f;
        }

        /// <summary>
        /// Remote tracing constants
        /// </summary>
        public static class NETWORK
        {
            /// <summary>
            /// Length of auto-generate network keys
            /// </summary>
            public const int DefaultKeyLength = 9;
            
            /// <summary>
            /// number of times a host can try to connect with the wrong key
            /// ! this is not used - we just turn networking off on the first bad attempt
            /// </summary>
            public const int HostLockoutLimit = 5;

            /// <summary>
            /// number of wrong-key connections allowed before the listener disables itself
            /// ! this is not used - we just turn networking off on the first bad attempt
            /// </summary>
            public const int TotalLockoutLimit = 15;

            /// <summary>
            /// How often to refresh the list of interfaces with the Remote tracing dialog open
            /// </summary>
            public const int InterfaceRefreshIntervalMS = 6000;

            /// <summary>
            /// How long to wait between checks for new versions (check only happens on startup)
            /// This stops constant network connections if the user is opening and closing rgat a lot
            /// </summary>
            public const int UpdateCheckMinimumDelayMinutes = 6 * 60;
        }

        /// <summary>
        /// Tracing constants
        /// </summary>
        public static class TRACING
        {
            /// <summary>
            /// Size of the tag cache allocated for each message part
            /// </summary>
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

        /// <summary>
        /// Test constants
        /// </summary>
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
        /// <summary>
        /// Node control flow type
        /// </summary>
        public enum eNodeType {
            /// <summary>
            /// Unknown or no control flow
            /// </summary>
            eInsUndefined,
            /// <summary>
            /// Performs  ajump
            /// </summary>
            eInsJump,
            /// <summary>
            /// Performs a return
            /// </summary>
            eInsReturn, 
            /// <summary>
            /// Performs a call
            /// </summary>
            eInsCall 
        };

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

        /// <summary>
        /// Supported graph colourations
        /// </summary>
        public enum eRenderingMode {
            /// <summary>
            /// Control flow type of nodes/edges
            /// </summary>
            eStandardControlFlow, 
            /// <summary>
            /// How busy nodes/edges are
            /// </summary>
            eHeatmap, 
            /// <summary>
            /// Conditional jump state
            /// </summary>
            eConditionals,
            /// <summary>
            /// How connected nodes are
            /// </summary>
            eDegree 
        }


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

        /// <summary>
        /// Available keybind actions
        /// </summary>
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
            /// <summary>
            /// Tilt the plot forwards on the X axis
            /// </summary>
            PitchXFwd,
            /// <summary>
            /// Tilt the plot back on the X axis
            /// </summary>
            PitchXBack,
            /// <summary>
            /// Turn the plot anticlockwise on the Y axis
            /// </summary>
            YawYLeft,
            /// <summary>
            /// Turn the plot clockwise on the Y axis
            /// </summary>
            YawYRight,
            /// <summary>
            /// Roll the graph anti clockwise on the Z axis
            /// </summary>
            RollGraphZAnti,
            /// <summary>
            /// Roll the graph clockwise on the Z axis
            /// </summary>
            RollGraphZClock,
            /// <summary>
            /// Center the graph so all nodes are in the frame
            /// </summary>
            CenterFrame,
            /// <summary>
            /// Keep centering the graph so all nodes are in the frame
            /// </summary>
            LockCenterFrame,
            /// <summary>
            /// Close the open dialog/menu
            /// </summary>
            Cancel, 
            /// <summary>
            /// Toggle heatmap rendering on or off
            /// </summary>
            ToggleHeatmap,
            /// <summary>
            /// Toggle conditional rendering on or off
            /// </summary>
            ToggleConditionals, 
            /// <summary>
            /// Raise the force directed layout activity
            /// </summary>
            RaiseForceTemperature,
            /// <summary>
            /// Toggle the display of all text on or off
            /// </summary>
            ToggleAllText,
            /// <summary>
            /// Toggle the display of instruction text on or off
            /// </summary>
            ToggleInsText,
            /// <summary>
            /// Toggle the display of animated text on or off
            /// </summary> 
            ToggleLiveText, 
            /// <summary>
            /// Toggle the quickmenu
            /// </summary>
            QuickMenu,
            /// <summary>
            /// Write an image of the graph to disk
            /// </summary>
            CaptureGraphImage, 
            /// <summary>
            /// Write an image of the graph and previews to disk
            /// </summary>
            CaptureGraphPreviewImage, 
            /// <summary>
            /// Write an image of the window to disk
            /// </summary>
            CaptureWindowImage, 
            /// <summary>
            /// Toggle video recording
            /// </summary>
            ToggleVideo, 
            /// <summary>
            /// Pause video recording without ending the video
            /// </summary>
            PauseVideo
        }

        /// <summary>
        /// Types of static binary signature
        /// </summary>
        public enum eSignatureType { 
            /// <summary>
            /// YARA
            /// </summary>
            YARA, 
            /// <summary>
            /// Detect it easy
            /// </summary>
            DIE 
        };

        /// <summary>
        /// Ways of laying out nodes
        /// </summary>
        public static class LayoutStyles
        {
            /// <summary>
            /// Available layout styles
            /// </summary>
            public enum Style { 
                /// <summary>
                /// Plot nodes in a spiralling cylinder
                /// </summary>
                CylinderLayout, 
                /// <summary>
                /// Plot nodes so they repel each other and attract connected nodes
                /// </summary>
                ForceDirected3DNodes, 
                /// <summary>
                /// Plot blocks so they repel each other and attract connected blocks
                /// </summary>
                ForceDirected3DBlocks, 
                /// <summary>
                /// Plot nodes in a circle
                /// </summary>
                Circle, 
                /// <summary>
                /// No
                /// </summary>
                Invalid 
            };

            static readonly List<Style> _cacheLayouts = new List<Style>() { Style.ForceDirected3DBlocks, Style.ForceDirected3DNodes };

            /// <summary>
            /// This layout was computed and needs to be saved if it is to be restored
            /// </summary>
            /// <param name="layout">Layout type</param>
            /// <returns>Requires caching</returns>
            public static bool RequiresCaching(Style layout) => _cacheLayouts.Contains(layout);

            /// <summary>
            /// True if the layout style is force directed
            /// </summary>
            /// <param name="layout">The layout style</param>
            /// <returns>True if the layout style is force directed</returns>
            public static bool IsForceDirected(Style layout) => RequiresCaching(layout);
        }



    }
}
