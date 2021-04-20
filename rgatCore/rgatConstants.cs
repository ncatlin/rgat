using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{
    enum eNodeType { eInsUndefined, eInsJump, eInsReturn, eInsCall };
    enum eEdgeNodeType
    {
        eEdgeCall = 0, eEdgeOld, eEdgeReturn, eEdgeLib, eEdgeNew,
        eEdgeException, eNodeNonFlow, eNodeJump, eNodeCall, eNodeReturn, eNodeExternal, eNodeException, eENLAST, eFIRST_IN_THREAD = 99
    };

    enum eRenderingMode { eStandardControlFlow, eHeatmap, eConditionals }
    enum eHighlightType { eExternals, eAddresses, eExceptions};

    enum eConditionalType
    {
        NOTCONDITIONAL = 0, ISCONDITIONAL = 1,
        CONDFELLTHROUGH = 2, CONDTAKEN = 4,
        CONDCOMPLETE = (ISCONDITIONAL | CONDFELLTHROUGH | CONDTAKEN)
    }

    enum eGraphLayout { eCylinderLayout, eForceDirected3DNodes, eForceDirected3DBlocks, eCircle, eLayoutInvalid };

    enum eKeybind { eMoveLeft, eMoveRight, eMoveUp, eMoveDown,
        eZoomIn, eZoomOut, ePitchXFwd, ePitchXBack, eYawYLeft, eYawYRight, eRollGraphZAnti, eRollGraphZClock, 
        eCenterFrame, eLockCenterFrame, eCancel, eToggleHeatmap, eToggleConditional, eRaiseForceTemperature,
        eToggleText, eToggleInsText, eToggleLiveText
    }

    enum eSignatureType { eYARA, eDetectItEasy};

    static class UI_Constants
    {
        public const int MAX_DIFF_PATH_LENGTH = 50;
        public const int PREVIEW_PANE_WIDTH = 300;
        public const int PREVIEW_PANE_GRAPH_HEIGHT = 150;
        public const int PREVIEW_PANE_PADDING = 5;
    }

    static class GL_Constants
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

    static class Anim_Constants
    {
        public const ulong ASSUME_INS_PER_BLOCK = 10; //farcical but useful way to estimate how long a block spends executing
        public const float ANIM_INACTIVE_NODE_ALPHA = 0.00f;
        public const float ANIM_INACTIVE_EDGE_ALPHA = 0.00f;
        public const float EXTERN_FLOAT_RATE = 0.3f;
        public const int KEEP_BRIGHT = -1;

    }

    static class Version_Constants
    {
        public const int RGAT_VERSION_MAJOR = 0;
        public const int RGAT_VERSION_MINOR = 6;
        public const int RGAT_VERSION_FEATURE = 0;
    }
}
