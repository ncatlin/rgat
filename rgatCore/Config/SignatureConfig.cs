using System;
using System.Linq;
using System.Text.Json.Serialization;

namespace rgat
{
    public partial class GlobalConfig
    {
        /// <summary>
        /// Github signature sources
        /// </summary>
        public class SignatureSource
        {
            /// <summary>
            /// Create a github signature source
            /// </summary>
            public SignatureSource() { }

            /// <summary>
            /// Name of the github repo
            /// </summary>
            public string RepoName { get; set; } = "";
            /// <summary>
            /// Name of the repo organisation
            /// </summary>
            public string OrgName { get; set; } = "";
            /// <summary>
            /// Subdirectory of the downloaded archive to use
            /// </summary>
            public string SubDir { get; set; } = "";

            /// <summary>
            ///  when rgat last checked the repo for updates
            /// </summary>
            public DateTime LastCheck { get; set; }

            /// <summary>
            /// when the repo itself was last updated
            /// </summary>
            public DateTime LastUpdate { get; set; }

            /// <summary>
            /// when rgat last downloaded the repo
            /// </summary>
            public DateTime LastFetch { get; set; }

            /// <summary>
            /// How many rules were found in the repo
            /// </summary>
            public int RuleCount { get; set; }

            /// <summary>
            /// The type of signatures expected in the repo
            /// </summary>
            public CONSTANTS.eSignatureType SignatureType { get; set; }// probably no point, done by extension?

            //ephemeral data
            /// <summary>
            /// Last error encountered checking the repo for updates
            /// </summary>
            public string? LastRefreshError;
            /// <summary>
            /// Last error encountered downloading the repo
            /// </summary>
            public string? LastDownloadError;

            /// <summary>
            /// Where to fetch the download to
            /// </summary>
            string? _fetchPath = null;

            /// <summary>
            /// The github path for the repo
            /// </summary>
            [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
            public string FetchPath
            {
                get
                {
                    if (_fetchPath == null)
                    {
                        _fetchPath = RepoComponentsToPath(OrgName, RepoName, SubDir);
                    }

                    return _fetchPath;
                }
            }

            /// <summary>
            /// Convert repo data to a github URL
            /// </summary>
            /// <param name="org">The repo org</param>
            /// <param name="repo">The repo name</param>
            /// <param name="directory">The subdirectory of the repo to store</param>
            /// <returns></returns>
            public static string RepoComponentsToPath(string org, string repo, string directory = "")
            {
                if (org.Length == 0 || repo.Length == 0)
                {
                    return "";
                }

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
