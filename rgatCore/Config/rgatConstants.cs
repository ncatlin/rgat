using System.Collections.Generic;

namespace rgat
{
    public class CONSTANTS
    {
        public static class PROGRAMVERSION
        {
            public const int MAJOR = 0;
            public const int MINOR = 6;
            public const int PATCH = 0;
            /// <summary>
            /// Optional, non-unique name for the given version (preview, release, bugfix, etc)
            /// Other values must still be unique (eg: '1.1.1 Preview' and '1.1.1 Release' cannot both exist)
            /// </summary>
            public const string PATCHNAME = null;
        }


        public static class UI
        {
            public const int MAX_DIFF_PATH_LENGTH = 50;
            public const int PREVIEW_PANE_WIDTH = 300;
            public const int PREVIEW_PANE_GRAPH_HEIGHT = 150;
            public const float PREVIEW_PANE_X_PADDING = 3;
            public const float PREVIEW_PANE_Y_SEP = 6;

            public const uint UI_SHORT_TIMER_INTERVAL = 500;
            public const uint UI_LONG_TIMER_INTERVAL = 60000;
            public const double SCREENSHOT_ICON_LINGER_TIME = 3;
            public const double SCREENSHOT_ANIMATION_RECT_SPEED = 10; //this will be 1/10th of the linger time
            public const double ALERT_TEXT_LINGER_TIME = 9000;
            public const double ALERT_CIRCLE_ANIMATION_TIME = 600;
            public const double ALERT_CIRCLE_ANIMATION_RADIUS = 100;

            public const int FILEPICKER_HISTORY_MAX = 10;
        }

        public static class GL_Constants
        {
            public const int XOFF = 0;
            public const int YOFF = 1;
            public const int ZOFF = 2;
            public const int ROFF = 0;
            public const int GOFF = 1;
            public const int BOFF = 2;
            public const int AOFF = 3;
            public const int LONGCURVEPTS = 32;
            public const int COLELEMS = 4;
            public const int POSELEMS = 3;

            public const int VBO_CYLINDER_POS = 0;
            public const int VBO_CYLINDER_COL = 1;

            public const int VBO_NODE_POS = 0;
            public const int VBO_NODE_COL = 1;
            public const int VBO_LINE_POS = 2;
            public const int VBO_LINE_COL = 3;
            public const int VBO_BLOCKLINE_POS = 4;
            public const int VBO_BLOCKLINE_COL = 5;
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


        public static class SIGNERS
        {
            public const string PIN_SIGNERS = "Intel Corporation";
            public const string RGAT_SIGNERS = "rgat dev";
        }


        public static class TESTS
        {
            public const string testextension = ".test.json";
        }

        /*
         * 
         * Enums
         * 
         */
        public enum eNodeType { eInsUndefined, eInsJump, eInsReturn, eInsCall };
        public enum eEdgeNodeType
        {
            eEdgeCall = 0, eEdgeOld, eEdgeReturn, eEdgeLib, eEdgeNew,
            eEdgeException, eNodeNonFlow, eNodeJump, eNodeCall, eNodeReturn, eNodeExternal, eNodeException, eENLAST, eFIRST_IN_THREAD = 99
        };

        public enum eRenderingMode { eStandardControlFlow, eHeatmap, eConditionals, eDegree }
        public enum HighlightType { eExternals, eAddresses, eExceptions };

        public enum PathKey
        {
            PinPath, PinToolPath32, PinToolPath64, FFmpegPath,
            TraceSaveDirectory, TestsDirectory, DiESigsDirectory, YaraRulesDirectory, MediaCapturePath
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


        /*
         * 
         * Helper functions
         * 
         */
        /// <summary>
        /// The simple major.minorpath version of this rgat build. should probably reference the assembly instead. todo
        /// </summary>
        public static string RGAT_VERSION => $"{PROGRAMVERSION.MAJOR}.{PROGRAMVERSION.MINOR}.{PROGRAMVERSION.PATCH}";
        /// <summary>
        /// The SemVer version of rgat
        /// </summary>
        public static System.Version RGAT_VERSION_SEMANTIC => new System.Version(RGAT_VERSION);

    }
}
