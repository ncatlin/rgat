using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace rgat
{
    public class GithubSignatureManager
    {
        System.Collections.Concurrent.BlockingCollection<GlobalConfig.SignatureSource> _repos = new System.Collections.Concurrent.BlockingCollection<GlobalConfig.SignatureSource>();

        CancellationToken _token;
        public bool Running { get; private set; }
        public string TaskType { get; private set; } = "";

        public int InitialTaskCount { get; private set; }
        public int CompletedTaskCount { get; private set; }
        int _activeWorkers = 0;
        readonly object _lock = new object();
        readonly List<string> _currentRepos = new List<string>();
        Action<GlobalConfig.SignatureSource> activeTaskAction;

        public List<string> GetActive()
        {
            lock (_lock)
            {
                return _currentRepos.ToList();
            }
        }

        public void StartRefresh(List<GlobalConfig.SignatureSource> repos, int workerCount, CancellationToken cancelToken)
        {
            TaskType = "Refresh";
            activeTaskAction = GetRepoLastUpdated;
            StartWorkers(repos, workerCount, cancelToken);
        }

        public void StartDownloads(List<GlobalConfig.SignatureSource> repos, int workerCount, CancellationToken cancelToken)
        {
            TaskType = "Download";
            activeTaskAction = DownloadRepo;
            StartWorkers(repos, workerCount, cancelToken);
        }

        void StartWorkers(List<GlobalConfig.SignatureSource> repos, int workerCount, CancellationToken cancelToken)
        {
            _repos = new System.Collections.Concurrent.BlockingCollection<GlobalConfig.SignatureSource>();
            repos.ForEach(x => _repos.Add(x));
            _repos.CompleteAdding();
            Running = true;
            _token = cancelToken;
            InitialTaskCount = repos.Count;
            CompletedTaskCount = 0;

            _activeWorkers = workerCount;
            for (var i = 0; i < workerCount; i++)
            {
                Task.Factory.StartNew(StartWork);
            }
        }

        void StartWork()
        {
            foreach (GlobalConfig.SignatureSource repo in _repos.GetConsumingEnumerable())
            {

                lock (_lock)
                {
                    _currentRepos.Add(repo.FetchPath);
                }
                activeTaskAction(repo);
                lock (_lock)
                {
                    _currentRepos.Remove(repo.FetchPath);
                    CompletedTaskCount += 1;
                }
            }
            lock (_lock)
            {
                _activeWorkers -= 1;
                if (_activeWorkers == 0) Running = false;
            }
        }

        void GetRepoLastUpdated(GlobalConfig.SignatureSource repo)
        {
            System.Net.Http.HttpClient client = new HttpClient();
            client.DefaultRequestHeaders.UserAgent.Add(new System.Net.Http.Headers.ProductInfoHeaderValue("rgat", CONSTANTS.PROGRAMVERSION.RGAT_VERSION_SEMANTIC.ToString()));
            try
            {
                string commitsPath = $"https://api.github.com/repos/{repo.OrgName}/{repo.RepoName}/commits/master";

                Task<HttpResponseMessage> request = client.GetAsync(commitsPath, _token);
                request.Wait(_token);
                if (request.Result.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    Task<string> content = request.Result.Content.ReadAsStringAsync();
                    content.Wait(_token);

                    if (JObject.Parse(content.Result).TryGetValue("commit", out JToken? tok1) &&
                        tok1.Type == JTokenType.Object &&
                        ((JObject)tok1).TryGetValue("committer", out JToken? tok2) &&
                        tok2.Type == JTokenType.Object &&
                        ((JObject)tok2).TryGetValue("date", out JToken? updateTok))
                    {
                        if (updateTok.Type == Newtonsoft.Json.Linq.JTokenType.Date)
                        {
                            repo.LastUpdate = updateTok.ToObject<DateTime>();
                            repo.LastCheck = DateTime.Now;
                            repo.LastRefreshError = null;
                            GlobalConfig.Settings.Signatures.UpdateSignatureSource(repo);
                            return;
                        }
                    }
                    Logging.RecordError($"No valid 'updated_at' field in repo response from github while refreshing {repo.FetchPath}");
                    repo.LastRefreshError = "Github Error";
                    GlobalConfig.Settings.Signatures.UpdateSignatureSource(repo);
                    return;
                }
                repo.LastRefreshError = $"{request.Result.StatusCode}";
                Logging.RecordError($"Error updating {repo.FetchPath} => {request.Result.StatusCode}:{request.Result.ReasonPhrase}");
                return;
            }
            catch (Exception e)
            {
                if (e.InnerException != null && e.InnerException.GetType() == typeof(HttpRequestException))
                {
                    string message = ((HttpRequestException)e.InnerException).Message;
                    repo.LastRefreshError = message;
                }
                else
                {
                    repo.LastRefreshError = "See Logs";
                }
                GlobalConfig.Settings.Signatures.UpdateSignatureSource(repo);
                Logging.RecordError($"Exception updating {repo.FetchPath} => {e.Message}");
            }
        }


        string? GetRepoDirectory(ref GlobalConfig.SignatureSource repo, string sigsdir)
        {

            try
            {
                if (!Directory.Exists(sigsdir))
                {
                    Logging.RecordError($"Base signatures directory {sigsdir} does not exist");
                    return null;
                }

                if (!sigsdir.ToLower().Contains("signature"))
                {
                    Logging.RecordError($"Base signatures directory {sigsdir} does not contain the word 'signature' anywhere in the path." +
                        $" This is a safety measure as the contents will be deleted on download. Please change it in the Settings->Files menu");
                    return null;
                }

                string repoSpecific = repo.RepoName + repo.SubDir;
                string repoDirectory = Path.Combine(sigsdir, repo.OrgName + "_" + MurmurHash.MurmurHash2.Hash(repoSpecific));

                if (!new Uri(GlobalConfig.GetSettingPath(CONSTANTS.PathKey.YaraRulesDirectory)).IsBaseOf(new Uri(repoDirectory)))
                {
                    repo.LastDownloadError = "Bad Repo Name";
                    Logging.RecordError($"Repo download directory {repoDirectory} is not in the signatures directory {sigsdir}");
                    GlobalConfig.Settings.Signatures.UpdateSignatureSource(repo);
                    return null;
                }

                return repoDirectory;
            }
            catch (Exception e)
            {
                Logging.RecordError($"Error initing signature directory for repo {repo.FetchPath}: {e.Message}");
                return null;
            }
        }

        bool PurgeDirectory(string repoDirectory)
        {
            Logging.RecordLogEvent($"Deleting existing contents of directory {repoDirectory}", filter: Logging.LogFilterType.TextDebug);
            try
            {
                System.IO.DirectoryInfo di = new DirectoryInfo(repoDirectory);
                if (Directory.Exists(repoDirectory))
                {
                    foreach (FileInfo file in di.EnumerateFiles())
                    {
                        file.Delete();
                    }
                    foreach (DirectoryInfo dir in di.EnumerateDirectories())
                    {
                        dir.Delete(true);
                    }
                    Directory.Delete(repoDirectory);
                }
            }
            catch (Exception e)
            {
                Logging.RecordError($"Error: {e.Message} when cleaning directory {repoDirectory}");
                return false;
            }
            return true;
        }


        void DownloadRepo(GlobalConfig.SignatureSource repo)
        {
            System.Net.Http.HttpClient client = new HttpClient();
            string rgatVersion = CONSTANTS.PROGRAMVERSION.RGAT_VERSION_SEMANTIC.ToString();
            client.DefaultRequestHeaders.UserAgent.Add(new System.Net.Http.Headers.ProductInfoHeaderValue("rgat", rgatVersion));
            try
            {
                string? repoDirectory = null;

                if (repo.SignatureType == CONSTANTS.eSignatureType.YARA)
                {
                    repoDirectory = GetRepoDirectory(ref repo, GlobalConfig.GetSettingPath(CONSTANTS.PathKey.YaraRulesDirectory));
                }
                else if (repo.SignatureType == CONSTANTS.eSignatureType.DIE)
                {
                    repoDirectory = GetRepoDirectory(ref repo, GlobalConfig.GetSettingPath(CONSTANTS.PathKey.DiESigsDirectory));
                }
                if (repoDirectory == null)
                {
                    repo.LastDownloadError = "Can't Get Save Dir";
                    GlobalConfig.Settings.Signatures.UpdateSignatureSource(repo);
                    return;
                }

                Task<byte[]> repobytes = client.GetByteArrayAsync($"https://api.github.com/repos/{repo.OrgName}/{repo.RepoName}/zipball");
                repobytes.Wait(cancellationToken: _token);
                Console.WriteLine($"Downloaded {repobytes.Result.Length} bytes of signaturedata");
                string tempname = Path.GetTempFileName();
                using (var fs = new FileStream(tempname, FileMode.Open, FileAccess.Write, FileShare.None, 4096))
                {
                    fs.Write(repobytes.Result);
                }

                if (!PurgeDirectory(repoDirectory))
                {
                    repo.LastDownloadError = "Can't Delete Existing";
                    GlobalConfig.Settings.Signatures.UpdateSignatureSource(repo);
                    return;
                }

                string tempExtractDir = Path.Combine(Path.GetTempPath(), "repoDL_" + Path.GetFileNameWithoutExtension(Path.GetRandomFileName()));
                System.IO.Compression.ZipFile.ExtractToDirectory(tempname, tempExtractDir, true);
                File.Delete(tempname);

                //should only be one
                string exdir = Directory.GetDirectories(tempExtractDir)[0];

                if (repo.SubDir == "")
                {
                    Directory.Move(exdir, repoDirectory);
                }
                else
                {
                    string subDirPath = Path.Combine(exdir, repo.SubDir);
                    if (Directory.Exists(subDirPath))
                    {
                        Directory.CreateDirectory(repoDirectory);
                        string targDirPath = Path.Combine(repoDirectory, Path.GetFileName(subDirPath));
                        Directory.CreateDirectory(repoDirectory);

                        Directory.Move(subDirPath, targDirPath);

                    }
                    else
                    {
                        Logging.RecordError($"Downloaded repo did not contain the path '{subDirPath}'");
                    }
                }

                repo.LastFetch = DateTime.Now;
                repo.LastDownloadError = null;
                GlobalConfig.Settings.Signatures.UpdateSignatureSource(repo);
            }
            catch (Exception e)
            {
                if (e.InnerException != null && e.InnerException.GetType() == typeof(HttpRequestException))
                {
                    string message = ((HttpRequestException)e.InnerException).Message;
                    repo.LastDownloadError = message;
                }
                else
                {
                    repo.LastDownloadError = "See Logs";
                }
                GlobalConfig.Settings.Signatures.UpdateSignatureSource(repo);
                Logging.RecordError($"Exception downloading {repo.FetchPath} => {e.Message}");
            }
        }


        /// <summary>
        /// Remove the associated signature download directory for this repo
        /// Must be called before the removal of the repo metadata via DeleteSignatureSource
        /// </summary>
        /// <param name="repopath">Repo key</param>
        public void PurgeRepoFiles(GlobalConfig.SignatureSource repo)
        {
            string? repoDirectory = null;
            if (repo.SignatureType == CONSTANTS.eSignatureType.YARA)
            {
                repoDirectory = GetRepoDirectory(ref repo, GlobalConfig.GetSettingPath(CONSTANTS.PathKey.YaraRulesDirectory));
            }
            else if (repo.SignatureType == CONSTANTS.eSignatureType.DIE)
            {
                repoDirectory = GetRepoDirectory(ref repo, GlobalConfig.GetSettingPath(CONSTANTS.PathKey.DiESigsDirectory));
            }
            else
            {
                Logging.RecordError("unknown signature type " + repo.SignatureType + " in purgeRepofiles for path " + repo.FetchPath);
                return;
            }
            try
            {
                PurgeDirectory(repoDirectory);
            }
            catch (Exception e)
            {
                Logging.RecordError($"Failed to purge signatures folder {repoDirectory} for path {repo.FetchPath}: {e.Message}");
            }

        }
    }

}
