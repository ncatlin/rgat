using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using static rgat.RGAT_CONSTANTS;

namespace rgat
{
    public partial class GlobalConfig
    {
        /************* Signature sources ***************/

        public sealed class SignatureSourcesSection : ConfigurationSection
        {

            public SignatureSourcesSection()
            {
                _Properties = new ConfigurationPropertyCollection();
                _Properties.Add(_sourcesJSON);
            }

            private static ConfigurationPropertyCollection _Properties;
            private static readonly ConfigurationProperty _sourcesJSON = new ConfigurationProperty(
                "SignatureSources",
                typeof(JArray),
                new JArray(),
                new GlobalConfig.JSONBlobConverter(),
                null,
                ConfigurationPropertyOptions.None);

            protected override object GetRuntimeObject() => base.GetRuntimeObject();
            protected override ConfigurationPropertyCollection Properties => _Properties;


            public JArray SignatureSources
            {
                get => (JArray)this["SignatureSources"];
                set
                {
                    this["SignatureSources"] = value;
                }
            }
        }


        public struct SignatureSource
        {
            public string RepoName;
            public string OrgName;
            public string SubDir;
            //when rgat last checked the repo
            public DateTime LastCheck;
            //when the repo itself was last updated
            public DateTime LastUpdate;
            //when rgat last downloaded the repo
            public DateTime LastFetch;
            public int RuleCount;

            public RGAT_CONSTANTS.eSignatureType SignatureType;// probably no point, done by extension?

            //ephemeral data
            public string LastRefreshError;
            public string LastDownloadError;
            public string FetchPath;

            public JObject ToJObject()
            {
                JObject result = new JObject();
                result.Add("OrgName", OrgName);
                result.Add("RepoName", RepoName);
                result.Add("SubDir", SubDir);
                result.Add("LastCheck", LastCheck);
                result.Add("LastUpdate", LastUpdate);
                result.Add("LastFetch", LastFetch);
                result.Add("RuleCount", RuleCount);
                result.Add("SignatureType", SignatureType.ToString());
                return result;
            }

            public void InitFetchPath()
            {
                FetchPath = GlobalConfig.RepoComponentsToPath(OrgName, RepoName, SubDir);
            }
        }


        static Dictionary<string, SignatureSource> _signatureSources = null;

        public static void SaveSignatureSources()
        {
            lock (_settingsLock)
            {
                var configFile = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);

                SignatureSourcesSection sec = null;
                try
                {
                    sec = (SignatureSourcesSection)configFile.GetSection("SignatureSources");
                }
                catch (Exception e)
                {
                    Logging.RecordError($"Error loading SignatureSources section: {e.Message}");
                    InitSignatureSources();
                }


                if (sec == null)
                {
                    sec = new SignatureSourcesSection();
                    sec.SignatureSources = new JArray();
                    try
                    {
                        configFile.Sections.Remove("SignatureSources");
                    }
                    catch (Exception) { }
                    configFile.Sections.Add("SignatureSources", sec);
                }

                sec.SignatureSources.Clear();

                foreach (SignatureSource item in _signatureSources.Values)
                {
                    sec.SignatureSources.Add(item.ToJObject());
                }
                sec.SectionInformation.ForceSave = true;
                configFile.Save();
            }
        }

        public void ReplaceSignatureSources(List<SignatureSource> sources)
        {
            lock (_settingsLock)
            {
                _signatureSources = new Dictionary<string, SignatureSource>();
                foreach (var src in sources)
                {
                    _signatureSources[src.FetchPath] = src;
                }
                SaveSignatureSources();
            }
        }

        public static void UpdateSignatureSource(SignatureSource source)
        {
            lock (_settingsLock)
            {
                if (_signatureSources == null) _signatureSources = new Dictionary<string, SignatureSource>();
                _signatureSources[source.FetchPath] = source;
                SaveSignatureSources();
            }
        }


        public static void AddSignatureSource(SignatureSource source)
        {
            lock (_settingsLock)
            {
                if (_signatureSources == null) _signatureSources = new Dictionary<string, SignatureSource>();
                _signatureSources[source.FetchPath] = source;
            }
        }

        public static void DeleteSignatureSource(string sourcePath)
        {
            lock (_settingsLock)
            {
                if (_signatureSources == null) _signatureSources = new Dictionary<string, SignatureSource>();
                //there is no way to re-add the DIE path other than manually editing the config, so disallow deletion
                if (_signatureSources.ContainsKey(sourcePath))
                {
                    _signatureSources.Remove(sourcePath);
                }
            }
        }

        public static SignatureSource? GetSignatureRepo(string path)
        {
            lock (_settingsLock)
            {
                if (_signatureSources != null && _signatureSources.TryGetValue(path, out SignatureSource value)) return value;
                return null;
            }
        }


        public static SignatureSourcesSection InitSignatureSourcesToDefault()
        {
            SignatureSourcesSection result = new SignatureSourcesSection();
            result.SignatureSources = new JArray();

            JObject item = new JObject();
            item.Add("OrgName", "horsicq");
            item.Add("RepoName", "Detect-It-Easy");
            item.Add("SubDir", "db");
            item.Add("LastUpdate", DateTime.MinValue);
            item.Add("LastCheck", DateTime.MinValue);
            item.Add("LastFetch", DateTime.MinValue);
            item.Add("RuleCount", -1);
            item.Add("SignatureType", eSignatureType.DIE.ToString());
            result.SignatureSources.Add(item);

            item = new JObject();
            item.Add("OrgName", "h3x2b");
            item.Add("RepoName", "yara-rules");
            item.Add("SubDir", "malware");
            item.Add("LastUpdate", DateTime.MinValue);
            item.Add("LastCheck", DateTime.MinValue);
            item.Add("LastFetch", DateTime.MinValue);
            item.Add("RuleCount", -1);
            item.Add("SignatureType", eSignatureType.YARA.ToString());
            result.SignatureSources.Add(item);
            return result;
        }


        public static void InitSignatureSources()
        {
            if (_signatureSources != null) return;

            lock (_settingsLock)
            {
                var configFile = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
                SignatureSourcesSection sec;
                try
                {
                    sec = (SignatureSourcesSection)configFile.GetSection("SignatureSources");
                    if (sec == null || sec.SignatureSources.Type != JTokenType.Array)
                    {
                        sec = InitSignatureSourcesToDefault();
                    }
                }
                catch (Exception e)
                {
                    Logging.RecordError($"Error: {e.Message} when loading SignatureSources config");
                    sec = InitSignatureSourcesToDefault();
                }

                _signatureSources = new Dictionary<string, SignatureSource>();
                List<JToken> badSources = new List<JToken>();
                foreach (var entry in sec.SignatureSources)
                {
                    if (entry.Type != JTokenType.Object) continue;
                    JObject data = (JObject)entry;
                    if (!data.TryGetValue("OrgName", out JToken orgTok) || orgTok.Type != JTokenType.String ||
                        !data.TryGetValue("RepoName", out JToken repoTok) || repoTok.Type != JTokenType.String ||
                        !data.TryGetValue("SubDir", out JToken dirTok) || dirTok.Type != JTokenType.String ||
                        !data.TryGetValue("LastUpdate", out JToken modifiedTok) || modifiedTok.Type != JTokenType.Date ||
                        !data.TryGetValue("LastFetch", out JToken fetchTok) || fetchTok.Type != JTokenType.Date ||
                        !data.TryGetValue("LastCheck", out JToken checkTok) || checkTok.Type != JTokenType.Date ||
                        !data.TryGetValue("RuleCount", out JToken countTok) || countTok.Type != JTokenType.Integer ||
                        !data.TryGetValue("SignatureType", out JToken typeTok) || typeTok.Type != JTokenType.String
                        )
                    {
                        Logging.RecordError($"Signature repo entry had invalid data");
                        continue;
                    }


                    SignatureSource src = new SignatureSource
                    {
                        OrgName = orgTok.ToString(),
                        RepoName = repoTok.ToString(),
                        SubDir = dirTok.ToString(),
                        LastCheck = modifiedTok.ToObject<DateTime>(),
                        LastFetch = fetchTok.ToObject<DateTime>(),
                        LastUpdate = modifiedTok.ToObject<DateTime>(),
                        RuleCount = countTok.ToObject<int>()
                    };
                    src.InitFetchPath();

                    if (Enum.TryParse(typeof(eSignatureType), typeTok.ToString(), out object setType))
                    {
                        src.SignatureType = (eSignatureType)setType;
                        _signatureSources[src.FetchPath] = src;
                    }
                    else
                    {
                        Logging.RecordError($"Unable to parse signature set type for {src.RepoName}: {typeTok}");
                    }

                }
                SaveSignatureSources();
            }
        }

        public static SignatureSource[] GetSignatureSources()
        {
            lock (_settingsLock)
            {
                return _signatureSources.Values.ToArray();
            }
        }

        public static string RepoComponentsToPath(string org, string repo, string directory = "")
        {
            if (org.Length == 0 || repo.Length == 0) return "";
            string result = $"https://github.com/{org}/{repo}";
            if (directory.Any())
            {
                result += "/tree/master/" + directory;
            }
            return result;
        }

        public static bool RepoExists(string githubPath)
        {
            lock (_settingsLock)
            {
                return _signatureSources.ContainsKey(githubPath);
            }
        }
    }
}
