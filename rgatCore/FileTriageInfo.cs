using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{
    class FileTriageInfo
    {
        public string OriginalPath { get; private set; } = null;
        FileTriageInfo(string path)
        {
            OriginalPath = path;
        }
    }
}
