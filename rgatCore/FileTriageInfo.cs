namespace rgat
{
    internal class FileTriageInfo
    {
        public string? OriginalPath { get; private set; } = null;

        private FileTriageInfo(string path)
        {
            OriginalPath = path;
        }
    }
}
