using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{
    class rgatState
    {
        public BinaryTargets targets = new BinaryTargets();
        public BinaryTarget ActiveTarget { get; private set; } = null;

        public rgatState() { }


        public void AddTargetByPath(string path, bool selectIt = true)
        {
            targets.AddTargetByPath(path);
            if (selectIt) SetActiveTarget(path);
        }

        public void SetActiveTarget(string path)
        {
            BinaryTarget newTarget = targets.GetTargetByPath(path);
            if (newTarget != null && newTarget != ActiveTarget)
            {
                ActiveTarget = newTarget;
            };
        }
    }
}
