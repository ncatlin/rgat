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

    enum graphLayouts { eCylinderLayout = 0, eTreeLayout = 1, eLayoutInvalid };
    static class UI_Constants
    {
        public const int MAX_DIFF_PATH_LENGTH = 50;
    }

}
