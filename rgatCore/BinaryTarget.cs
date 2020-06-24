using SharpDX;
using SharpDX.Direct3D;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace rgatCore
{
    class ExclusionList
    {
        public bool inWhitelistMode = false;
        public List<string> whitelistedDirs;
        public List<string> whitelistedFiles;
        public List<string> blacklistedDirs;
        public List<string> blacklistedFiles;
    }

    class BinaryTarget
    {
        private string _sha1hash = "";
        private string _sha256hash = "";
        private long fileSize = 0;
        ExclusionList excludedLibs = new ExclusionList();
        private Byte[] startbytes = null;

        public string FilePath { get; private set; } = "";
        public string FileName { get; private set; } = "";
        public string HexPreview { get; private set; } = "";
        public string ASCIIPreview { get; private set; } = "";

        public BinaryTarget(string filepath)
        {
            FilePath = filepath;
            FileName = Path.GetFileName(FilePath);
            if (File.Exists(filepath))
            {
                try
                {
                    FileInfo fileinfo = new FileInfo(filepath);
                    fileSize = fileinfo.Length;
                    ParseFile();
                }
                catch { }
            }
        }
        public string GetSHA1Hash()
        {
            if (_sha1hash.Length > 0) return _sha1hash;
            if (File.Exists(FilePath)) ParseFile();
            return _sha1hash;
        }

        public string GetSHA256Hash()
        {
            if (_sha256hash.Length > 0) return _sha256hash;
            if (File.Exists(FilePath)) ParseFile();
            return _sha1hash;
        }




        private void ParseFile()
        {
            try
            {
                using (FileStream fs = File.OpenRead(FilePath))
                {
                    startbytes = new byte[Math.Min(1024, fileSize)];
                    int bytesread = fs.Read(startbytes, 0, startbytes.Length);
                    int previewSize = Math.Min(16, bytesread);
                    if (fileSize == 0)
                    {
                        HexPreview = "[Empty File] ";
                        ASCIIPreview = "[Empty File] ";
                    }
                    else
                    {
                        HexPreview = BitConverter.ToString(startbytes, 0, previewSize).Replace("-", " ");
                        ASCIIPreview = TextUtils.IllustrateASCIIBytes(startbytes, previewSize);
                    }

                    SHA1 sha1 = new SHA1Managed();
                    _sha1hash = BitConverter.ToString(sha1.ComputeHash(fs)).Replace("-","");
                    SHA256 sha256 = new SHA256Managed();
                    _sha256hash = BitConverter.ToString(sha256.ComputeHash(fs)).Replace("-", "");
                }
            } catch {
                Console.WriteLine("Error: Exception reading binary data");
                _sha1hash = "Error";
                _sha256hash = "Error";
                HexPreview = "Error";
            }
        }

        public string GetFileSizeString()
        {
            return String.Format(new FileSizeFormatProvider(), "{0:fs}", fileSize);
        }


        public void AddDefaultExclusions()
        {
            excludedLibs.blacklistedDirs.Append(@"C:\\Windows");
        }
    }
}
