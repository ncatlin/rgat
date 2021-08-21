using System;
using System.Collections.Generic;
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
            client.DefaultRequestHeaders.UserAgent.Add(new System.Net.Http.Headers.ProductInfoHeaderValue("rgat", RGAT_CONSTANTS.RGAT_VERSION)); // set your own values here
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

        void DownloadRepo(GlobalConfig.SignatureSource repo)
        {
            try
            {
                Task.Delay(new Random().Next(1000, 4000)).Wait(_token);
                DateTime result = DateTime.Now.AddDays(-1 * new Random().Next(30, 100));
                repo.LastFetch = result;
                GlobalConfig.UpdateSignatureSource(repo);
            }
            catch
            {
                return;
            }
        }
    }

}
