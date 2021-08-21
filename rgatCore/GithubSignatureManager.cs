using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
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
        List<string> _currentRepos = new List<string>();
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
                    _currentRepos.Add(repo.GithubPath);
                }
                activeTaskAction(repo);
                lock (_lock)
                {
                    _currentRepos.Remove(repo.GithubPath);
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
            client.DefaultRequestHeaders.UserAgent.Add(new System.Net.Http.Headers.ProductInfoHeaderValue("rgat", RGAT_CONSTANTS.RGAT_VERSION));
            try
            {
                Task<HttpResponseMessage> request = client.GetAsync("https://api.github.com/repos/" + repo.GithubPath, _token);
                request.Wait(_token);
                if (request.Result.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    Task<string> content = request.Result.Content.ReadAsStringAsync();
                    content.Wait(_token);
                    if (Newtonsoft.Json.Linq.JObject.Parse(content.Result).TryGetValue("updated_at", out Newtonsoft.Json.Linq.JToken updateTok))
                    {
                        if (updateTok.Type == Newtonsoft.Json.Linq.JTokenType.Date)
                        {
                            repo.LastUpdate = updateTok.ToObject<DateTime>();
                            repo.LastCheck = DateTime.Now;
                            repo.LastRefreshError = null;
                            GlobalConfig.UpdateSignatureSource(repo);
                            return;
                        }
                    }
                    Logging.RecordError($"No valid 'updated_at' field in repo response from github while refreshing {repo.GithubPath}");
                    repo.LastRefreshError = "Github Error";
                    GlobalConfig.UpdateSignatureSource(repo);
                    return;
                }
                repo.LastRefreshError = $"{request.Result.StatusCode}";
                Logging.RecordError($"Error updating {repo.GithubPath} => {request.Result.StatusCode}:{request.Result.ReasonPhrase}");
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
                GlobalConfig.UpdateSignatureSource(repo);
                Logging.RecordError($"Exception updating {repo.GithubPath} => {e.Message}");
            }
        }


        string GetRepoDirectory(ref GlobalConfig.SignatureSource repo, string sigsdir)
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

                string repoDirectory = Path.Combine(sigsdir, repo.RepoName);
                if (!new Uri(GlobalConfig.YARARulesDir).IsBaseOf(new Uri(repoDirectory)))
                {
                    repo.LastDownloadError = "Bad Repo Name";
                    Logging.RecordError($"Repo download directory {repoDirectory} is not in the signatures directory {sigsdir}");
                    GlobalConfig.UpdateSignatureSource(repo);
                    return null;
                }

                return repoDirectory;
            }
            catch (Exception e)
            {
                Logging.RecordError($"Error initing signature directory for repo {repo.GithubPath}: {e.Message}");
                return null;
            }
            return null;
        }

        bool CleanDirectory(string repoDirectory)
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
            client.DefaultRequestHeaders.UserAgent.Add(new System.Net.Http.Headers.ProductInfoHeaderValue("rgat", RGAT_CONSTANTS.RGAT_VERSION));
            try
            {
                string repoDirectory = null;

                if (repo.SignatureType == RGAT_CONSTANTS.eSignatureType.YARA)
                {
                    repoDirectory = GetRepoDirectory(ref repo, GlobalConfig.YARARulesDir);
                }
                else if (repo.SignatureType == RGAT_CONSTANTS.eSignatureType.DIE)
                {
                    repoDirectory = GetRepoDirectory(ref repo, GlobalConfig.DiESigsPath);
                }
                if (repoDirectory == null)
                {
                    repo.LastDownloadError = "Can't Get Save Dir";
                    GlobalConfig.UpdateSignatureSource(repo);
                    return;
                }

                Task<byte[]> repobytes = client.GetByteArrayAsync("https://api.github.com/repos/" + repo.GithubPath + "/zipball");
                repobytes.Wait(cancellationToken: _token);
                Console.WriteLine($"Downloaded {repobytes.Result.Length} bytes of signaturedata");
                string tempname = Path.GetTempFileName();
                using (var fs = new FileStream(tempname, FileMode.Open, FileAccess.Write, FileShare.None, 4096))
                {
                    fs.Write(repobytes.Result);
                }

                if (!CleanDirectory(repoDirectory))
                {
                    repo.LastDownloadError = "Can't Delete Existing";
                    GlobalConfig.UpdateSignatureSource(repo);
                    return;
                }

                System.IO.Compression.ZipFile.ExtractToDirectory(tempname, repoDirectory, true);
                File.Delete(tempname);

                repo.LastFetch = DateTime.Now;
                repo.LastDownloadError = null;
                GlobalConfig.UpdateSignatureSource(repo);
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
                GlobalConfig.UpdateSignatureSource(repo);
                Logging.RecordError($"Exception downloading {repo.GithubPath} => {e.Message}");
            }
        }
    }

}
