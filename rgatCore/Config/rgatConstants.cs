using System.Collections.Generic;

namespace rgat
{
    public class RGAT_CONSTANTS
    {
        public static class VERSION
        {
            public const int MAJOR = 0;
            public const int MINOR = 6;
            public const int FEATURE = 0;
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
        }

        public static class TRACING
        {
            public const int TagCacheSize = 1024;
        }


        public static class SIGNERS
        {
            public const string PIN_SIGNER = "Intel Corporation";
            public const string PINTOOL_SIGNER = "rgat dev";
            public const string CISCO_SIGNER = "Cisco WebEx LLC";
        }


        public static class TEST
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
        public enum eHighlightType { eExternals, eAddresses, eExceptions };

        public enum eConditionalType
        {
            NOTCONDITIONAL = 0, ISCONDITIONAL = 1,
            CONDFELLTHROUGH = 2, CONDTAKEN = 4,
            CONDCOMPLETE = (ISCONDITIONAL | CONDFELLTHROUGH | CONDTAKEN)
        }


        public enum eKeybind
        {
            MoveLeft, MoveRight, MoveUp, MoveDown,
            ZoomIn, ZoomOut, PitchXFwd, PitchXBack, YawYLeft, YawYRight, RollGraphZAnti, RollGraphZClock,
            CenterFrame, LockCenterFrame, Cancel, ToggleHeatmap, ToggleConditionals, RaiseForceTemperature,
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
        public static string RGAT_VERSION => $"{VERSION.MAJOR}.{VERSION.MINOR}.{VERSION.FEATURE}";

    }
}
