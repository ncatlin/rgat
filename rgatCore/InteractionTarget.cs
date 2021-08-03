using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{
    public class InteractionTarget
    {
        public enum EntityType { File, Network, RegistryKey, Mutex }

        public EntityType TargetType;

    }
}
