namespace rgat
{
    class FileTriageInfo
    {
        public string? OriginalPath { get; private set; } = null;
        FileTriageInfo(string path)
        {
            OriginalPath = path;
        }
    }
}
