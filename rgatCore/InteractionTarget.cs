using System;
using System.Collections.Generic;
using System.Text;

namespace rgat
{
    public class InteractionTarget
    {
        public enum EntityType { File, Network, RegistryKey, Mutex }

        public EntityType TargetType;

    }
}
