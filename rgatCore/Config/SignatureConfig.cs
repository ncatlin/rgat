using System.Text.Json;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using static rgat.RGAT_CONSTANTS;
using System.Text.Json.Serialization;
using System.Diagnostics;

namespace rgat
{
    public partial class GlobalConfig
    {
        /************* Signature sources ***************/
        public class SignatureSource
        {
            
            public string RepoName { get; set; }
            public string OrgName { get; set; }
            public string SubDir { get; set; }
            //when rgat last checked the repo
            public DateTime LastCheck { get; set; }
            //when the repo itself was last updated
            public DateTime LastUpdate { get; set; }
            //when rgat last downloaded the repo
            public DateTime LastFetch { get; set; }
            public int RuleCount { get; set; }

            public RGAT_CONSTANTS.eSignatureType SignatureType { get; set; }// probably no point, done by extension?

            //ephemeral data

            public string LastRefreshError;
            public string LastDownloadError;

            string _fetchPath = null;

            [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
            public string FetchPath
            {
                get
                {
                    if (_fetchPath == null) _fetchPath = RepoComponentsToPath(OrgName, RepoName, SubDir);
                    return _fetchPath;
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


        }


    }
}
