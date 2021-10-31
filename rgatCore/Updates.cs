using Humanizer;
using ImGuiNET;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace rgat
{
    internal class Updates
    {

        public static string? PendingInstallPath = null;

        public static void CheckForUpdates()
        {
            //already checked recently
            DateTime nextCheckMinimum = GlobalConfig.Settings.Updates.UpdateLastCheckTime.AddMinutes(CONSTANTS.NETWORK.UpdateCheckMinimumDelayMinutes);
            if (nextCheckMinimum > DateTime.Now)
            {
                Logging.RecordLogEvent($"Not checking for updates, next check will be next time rgat is launched after {nextCheckMinimum.Humanize()}", Logging.LogFilterType.Debug);
                return;
            }

            if (!System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable())
            {
                Logging.RecordLogEvent("Not checking for updates, no network connection available", Logging.LogFilterType.Debug);
                return;
            }

            //https://docs.github.com/en/rest/reference/repos#list-releases
            System.Net.Http.HttpClient client = new System.Net.Http.HttpClient();
            System.Net.Http.Headers.ProductInfoHeaderValue versionHeader = new System.Net.Http.Headers.ProductInfoHeaderValue("rgat", CONSTANTS.PROGRAMVERSION.RGAT_VERSION_SEMANTIC.ToString());
            client.DefaultRequestHeaders.UserAgent.Add(versionHeader);
            client.DefaultRequestHeaders.Add("accept", "application/vnd.github.v3+json");
            client.DefaultRequestHeaders.Add("per_page", "1");
            client.DefaultRequestHeaders.Add("page", "0");

            try
            {
                //string releasesPath = $"https://api.github.com/repos/olivierlacan/keep-a-changelog/releases";
                string releasesPath = $"https://api.github.com/repos/ncatlin/rgat/releases";
                CancellationToken exitToken = rgatState.ExitToken;
                Task<HttpResponseMessage> response = client.GetAsync(releasesPath, exitToken);
                response.Wait(exitToken);
                if (response.Result.IsSuccessStatusCode)
                {
                    Task<string> content = response.Result.Content.ReadAsStringAsync();
                    content.Wait(exitToken);
                    JArray responseArr = JArray.Parse(content.Result);
                    Version latestVersion = CONSTANTS.PROGRAMVERSION.RGAT_VERSION_SEMANTIC;
                    string latestZip = "";
                    bool newVersion = false;
                    foreach (JToken releaseTok in responseArr)
                    {
                        if (releaseTok.Type != JTokenType.Object)
                        {
                            continue;
                        }

                        if (((JObject)releaseTok).TryGetValue("tag_name", out JToken? releaseTagTok)
                            &&
                            ((JObject)releaseTok).TryGetValue("zipball_url", out JToken? zipUrlTok)
                            )
                        {
                            string tagString = releaseTagTok.ToString();
                            if (tagString.StartsWith('v'))
                            {
                                tagString = tagString.Substring(1);
                            }

                            if (tagString.Count(x => x == '.') >= 2)
                            {
                                Version releaseVersion = new Version(tagString);
                                //todo replace these lines when dev is done
                                if ((releaseVersion != null) && (releaseVersion > latestVersion))
                                {
                                    newVersion = true;
                                    latestVersion = releaseVersion;
                                    latestZip = zipUrlTok.ToString();
                                }
                            }
                        }
                    }

                    if (newVersion && latestVersion > GlobalConfig.Settings.Updates.UpdateLastCheckVersion)
                    {
                        client = new System.Net.Http.HttpClient();
                        client.DefaultRequestHeaders.UserAgent.Add(versionHeader);
                        client.DefaultRequestHeaders.Add("accept", "application/vnd.github.v3+json");

                        //string changelogPath = $"https://api.github.com/repos/olivierlacan/keep-a-changelog/contents/CHANGELOG.md";
                        string changelogPath = $"https://api.github.com/repos/ncatlin/rgat/contents/CHANGELOG.md";

                        response = client.GetAsync(changelogPath, exitToken);
                        response.Wait(exitToken);

                        if (response.Result.IsSuccessStatusCode)
                        {
                            content = response.Result.Content.ReadAsStringAsync();
                            content.Wait(exitToken);
                            JObject changelogObj = JObject.Parse(content.Result);
                            if (changelogObj.TryGetValue("content", out JToken? b64ChangelogTok) && b64ChangelogTok.Type == JTokenType.String)
                            {
                                string parsedChangelogChanges = ParseChangelogChanges(b64ChangelogTok.ToString());
                                GlobalConfig.RecordAvailableUpdateDetails(latestVersion, parsedChangelogChanges, latestZip);
                            }
                            else
                            {
                                Logging.RecordLogEvent("Update Check: No valid content in changelog content request", Logging.LogFilterType.Debug);
                            }
                        }
                    }
                    GlobalConfig.Settings.Updates.UpdateLastCheckTime = DateTime.Now;
                }
            }
            catch (Exception e)
            {
                if (!rgatState.rgatIsExiting)
                {
                    // not important enough to be an error display on the UI
                    Logging.RecordLogEvent($"Update check failed: {e.Message}");
                }
            }
        }


        /// <summary>
        /// Teturns a list of changes from the current version to a given changelog
        /// </summary>
        /// <param name="b64ChangelogMDContent">base64 encoded changelog.md file</param>
        /// <returns>plaintext formatted list of change types and changes</returns>
        private static string ParseChangelogChanges(string b64ChangelogMDContent)
        {
            Version currentVersion = CONSTANTS.PROGRAMVERSION.RGAT_VERSION_SEMANTIC;
            string raw = ASCIIEncoding.ASCII.GetString(Convert.FromBase64String(b64ChangelogMDContent));
            string[] versionSections = raw.Split("\n## ");
            int totalChangeCount = 0;
            int totalNewVersionCount = 0;

            if (versionSections.Length < 2)
            {
                Logging.RecordLogEvent("Bad changelog received");
                return "";
            }

            Dictionary<string, List<string>> changesDict = new Dictionary<string, List<string>>();

            for (var verSectionI = 1; verSectionI < versionSections.Length; verSectionI++)
            {
                string[] versionSectionLines = versionSections[verSectionI].Split("\n### ");
                if (versionSectionLines.Length < 2)
                {
                    continue;
                }

                string line = versionSectionLines[0].Trim();
                string versionString = line.Substring(1, line.IndexOf(']') - 1);
                if (!System.Version.TryParse(versionString, out Version? newChangeVersion))
                {
                    continue; //'Unreleased'
                }

                if (newChangeVersion <= currentVersion)
                {
                    break;
                }

                totalNewVersionCount += 1;

                for (var changeTypeI = 1; changeTypeI < versionSectionLines.Length; changeTypeI++)
                {
                    string[] changeItems = versionSectionLines[changeTypeI].Split("\n- ");
                    if (changeItems.Length < 2)
                    {
                        continue;
                    }

                    string changeType = changeItems[0].Trim();
                    if (!changesDict.ContainsKey(changeType))
                    {
                        changesDict.Add(changeType, new List<string>());
                    }
                    for (var changeI = 1; changeI < changeItems.Length; changeI++)
                    {
                        string change = changeItems[changeI].Replace("\n", "");
                        changesDict[changeType].Add(change);
                    }
                }
            }

            List<string> expectedChangeTypes = new List<string>() { "Added", "Changed", "Fixed", "Removed", "Security", "Deprecated" };
            string result = "";
            foreach (string expectedChangeType in expectedChangeTypes)
            {
                if (changesDict.TryGetValue(expectedChangeType, out List<string>? changes))
                {
                    result += $"####{expectedChangeType}\n";
                    foreach (string change in changes)
                    {
                        result += change + "\n";
                    }

                    totalChangeCount += changes.Count;
                }
            }

            return $"CHANGES#{totalChangeCount}#VERSIONS#{totalNewVersionCount}#####\n" + result; ;
        }


        public static void ChangesCounts(out int changes, out int versions)
        {
            changes = 0;
            versions = 0;
            if (TotalChanges == -1)
            {
                string line = GlobalConfig.Settings.Updates.UpdateLastChanges;
                if (line != null && line.Contains("####\n"))
                {
                    line = line.Substring(0, line.IndexOf("####\n"));
                    string[] items = line.Split("#");
                    if (items[0] == "CHANGES" && items[2] == "VERSIONS")
                    {
                        TotalChanges = int.Parse(items[1]);
                        NewVersions = int.Parse(items[3]);
                        changes = TotalChanges;
                        versions = NewVersions;
                    }
                }
            }
            else
            {
                changes = TotalChanges;
                versions = NewVersions;
            }
        }

        private static int TotalChanges = -1;
        private static int NewVersions = -1;

        public static void DrawChangesDialog()
        {
            ImGui.PushStyleColor(ImGuiCol.Text, 0xffffffff);
            ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xff000000);
            Version currentVersion = CONSTANTS.PROGRAMVERSION.RGAT_VERSION_SEMANTIC;
            Version newVersion = GlobalConfig.Settings.Updates.UpdateLastCheckVersion;
            ImGui.Text($"Current Version: {currentVersion}. New Version: {newVersion}");
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 5);

            string[] changes = GlobalConfig.Settings.Updates.UpdateLastChanges.Split('\n');

            if (ImGui.BeginTabBar("#ChangesTabs"))
            {
                for (var i = 0; i < changes.Length; i++)
                {
                    string item = changes[i].Trim();
                    if (item.StartsWith("####"))
                    {
                        string category = item.Substring(4, item.Length - 4);
                        if (category.StartsWith("CHANGES"))
                        {
                            continue;
                        }

                        GetChangeIcon(category, out char icon, out WritableRgbaFloat colour);
                        ImGui.PushStyleColor(ImGuiCol.Tab, colour.ToUint(customAlpha: 150));
                        ImGui.PushStyleColor(ImGuiCol.TabHovered, colour.ToUint(customAlpha: 190));
                        ImGui.PushStyleColor(ImGuiCol.TabActive, colour.ToUint(customAlpha: 255));
                        if (ImGui.BeginTabItem($"{icon} {category}##{i}"))
                        {
                            ImGuiTableFlags tableFlags = ImGuiTableFlags.ScrollY | ImGuiTableFlags.ScrollX | ImGuiTableFlags.RowBg;
                            if (ImGui.BeginTable("#ChangesDlgChild", 1, flags: tableFlags, ImGui.GetContentRegionAvail() - new System.Numerics.Vector2(0, 30)))
                            {
                                i += 1;
                                while (i < changes.Length)
                                {
                                    string text = changes[i].Trim();
                                    if (text.Length < 2)
                                    {
                                        i += 1;
                                        continue;
                                    }

                                    ImGui.TableNextRow();
                                    ImGui.TableNextColumn();
                                    ImGui.Text(text);

                                    i += 1;
                                    if (i < (changes.Length - 1) && changes[i + 1].StartsWith("####"))
                                    {
                                        break;
                                    }
                                }
                                ImGui.EndTable();
                            }
                            ImGui.EndTabItem();
                        }
                        ImGui.PopStyleColor(3);
                    }
                }
                ImGui.EndTabBar();
            }
            ImGui.PopStyleColor(2);

            if (_update_in_progress is false)
            {
                if (ImGui.Button($"{ImGuiController.FA_ICON_DOWNLOAD} Download and Install now"))
                {
                    StartUpdater(delayed_install: false);
                }
                ImGui.SameLine();
                if (ImGui.Button($"{ImGuiController.FA_ICON_CLOCK} Download now, Install on exit"))
                {
                    StartUpdater(delayed_install: true);
                }
            }
            else
            {
                if (_download_complete)
                {
                    if (Updates.PendingInstallPath != null)
                    {
                        ImGui.AlignTextToFramePadding();
                        ImGui.Text("Update will be installed on exit");
                        ImGui.SameLine();
                        if (ImGui.Button("Cancel"))
                        {
                            Updates.PendingInstallPath = null;
                            _update_in_progress = false;
                        }
                    }
                    else if (_update_style == "ONDOWNLOAD")
                    {
                        ImGui.AlignTextToFramePadding();
                        ImGui.Text("Exiting...");
                    }
                }
                else
                {
                    if (_download_progress != -1)
                    {
                        ImGui.AlignTextToFramePadding();
                        ImGui.Text("Download Progress: ");
                        ImGui.SameLine();
                        ImGui.ProgressBar(_download_progress, new System.Numerics.Vector2(80, 25));
                        ImGui.SameLine();
                        if (ImGui.Button("Cancel", new System.Numerics.Vector2(50, 25)))
                        {
                            _download_progress = -1;
                            _update_in_progress = false;
                            _download_cancel_tokensrc.Cancel();
                        }
                    }
                }
            }
        }

        private static bool _update_in_progress;
        private static string _update_style = "";
        private static float _download_progress = -1;
        private static bool _download_complete;
        private static readonly CancellationTokenSource _download_cancel_tokensrc = new CancellationTokenSource();

        private static void StartUpdater(bool delayed_install = false)
        {
            _update_in_progress = true;

            if (delayed_install)
            {
                _update_style = "ONEXIT";
            }
            else
            {
                _update_style = "ONDOWNLOAD";
            }

            try
            {
                //first check for a staged download 
                if (Version.TryParse(GlobalConfig.Settings.Updates.StagedDownloadVersion, out Version? stagedVersion))
                {
                    if (stagedVersion == GlobalConfig.Settings.Updates.UpdateLastCheckVersion)
                    {
                        string stagedrgat = Path.Combine(GlobalConfig.Settings.Updates.StagedDownloadPath, "rgat.exe");
                        if (File.Exists(stagedrgat) && GlobalConfig.PreviousSignatureCheckPassed(stagedrgat, out string? error, out bool timeWarning))
                        {
                            if (timeWarning)
                            {
                                Logging.RecordError("Refusing to install fetched update: expired signature");
                                File.Delete(stagedrgat);
                                Directory.Delete(GlobalConfig.Settings.Updates.StagedDownloadPath);
                            }
                            _download_complete = true;
                            InitiateFileSwap(stagedrgat);
                            return;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.RecordException($"Update from staged download failed: {e.Message}", e);
                GlobalConfig.Settings.Updates.StagedDownloadPath = "";
                GlobalConfig.Settings.Updates.UpdateLastCheckVersion = new Version("0");
            }

            Task.Run(() => { UpdateDownloader(_download_cancel_tokensrc.Token); });
        }

        private static void DownloadProgressCallback4(object sender, DownloadProgressChangedEventArgs e)
        {
            _download_progress = e.BytesReceived / (float)e.TotalBytesToReceive;
        }

        private static async void UpdateDownloader(CancellationToken cancelToken)
        {
            try
            {
                WebClient client = new WebClient();
                client.Headers.Add(HttpRequestHeader.UserAgent, $"rgat {CONSTANTS.PROGRAMVERSION.RGAT_VERSION_SEMANTIC}");
                client.Headers.Add(HttpRequestHeader.Accept, "application/vnd.github.v3+json");

                Logging.RecordLogEvent($"Starting download: {GlobalConfig.Settings.Updates.UpdateDownloadLink}", filter: Logging.LogFilterType.Debug);
                Uri downloadAddr = new Uri(GlobalConfig.Settings.Updates.UpdateDownloadLink);
                string tempDirectory = Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(Path.GetRandomFileName()));
                Directory.CreateDirectory(tempDirectory);
                string zipfilepath = Path.Combine(tempDirectory, "newversion.zip");
                client.DownloadProgressChanged += DownloadProgressCallback4;
                Task downloadTask = client.DownloadFileTaskAsync(downloadAddr, zipfilepath);

                await downloadTask;

                if (downloadTask.IsCompleted)
                {
                    _download_progress = 1;
                    _download_complete = true;
                    ZipArchive arch = ZipFile.OpenRead(zipfilepath);
                    var rgatExes = arch.Entries.Where(x => x.Name == "rgat.exe");

                    if (rgatExes.Count() == 1)
                    {
                        var rgatExe = rgatExes.First();
                        string downloadedExe = Path.Combine(tempDirectory, "rgat.exe");
                        rgatExe.ExtractToFile(downloadedExe);
                        InitiateFileSwap(downloadedExe);
                    }
                    else
                    {
                        Logging.RecordError($"Expected 1 rgat.exe in release but found {rgatExes.Count()}");
                        _update_in_progress = false;
                    }

                    arch.Dispose();
                    File.Delete(zipfilepath);
                }
            }
            catch (Exception e)
            {
                if (e.InnerException != null)
                {
                    Logging.RecordException($"Download Failed: {e.InnerException.Message}", e.InnerException);
                }
                else
                {
                    Logging.RecordException($"Download Failed: {e.Message}", e);
                }
                _update_in_progress = false;

            }
            finally
            {
                _download_progress = -1;
            }
        }

        private static void InitiateFileSwap(string new_rgatPath)
        {
            Logging.RecordLogEvent($"Initialising update called with new rgat version {new_rgatPath}", filter: Logging.LogFilterType.Debug);
            bool failed = false;
            if (File.Exists(new_rgatPath))
            {
                if (GlobalConfig.VerifyCertificate(new_rgatPath, CONSTANTS.SIGNERS.RGAT_SIGNERS, out string? error, out string? timeWarning))
                {
                    if (timeWarning != null)
                    {
                        Logging.RecordError("Refusing to install fetched update: expired signature");
                        failed = true;
                    }
                }
                else
                {
                    Logging.RecordError($"Refusing to install fetched update: Bad Signature ({error})");
                    failed = true;
                }
                if (failed)
                {
                    Logging.RecordLogEvent($"Deleting bad update at {new_rgatPath}", filter: Logging.LogFilterType.Debug);
                    try
                    {
                        File.Delete(new_rgatPath);
                        string? filedir = Path.GetDirectoryName(new_rgatPath);
                        if (filedir is not null && Directory.GetFiles(filedir).Length == 0)
                        {
                            Directory.Delete(filedir);
                        }
                    }
                    catch (Exception e)
                    {
                        Logging.RecordException($"Exception deleting bad update: {e.Message}", e);
                    }
                }
            }
            else
            {
                Logging.RecordError($"Unable to install {new_rgatPath}: Does not exist");
                failed = true;
            }

            if (failed)
            {
                Logging.RecordLogEvent($"Abandoning failed update", filter: Logging.LogFilterType.Debug);
                GlobalConfig.Settings.Updates.StagedDownloadPath = "";
                GlobalConfig.Settings.Updates.UpdateLastCheckVersion = new Version("0.0.0");
                _update_in_progress = false;
                _download_complete = false;
                return;
            }

            GlobalConfig.Settings.Updates.StagedDownloadPath = new_rgatPath;
            GlobalConfig.Settings.Updates.StagedDownloadVersion = GlobalConfig.Settings.Updates.UpdateLastCheckVersionString;

            Updates.PendingInstallPath = new_rgatPath;
            if (_update_style == "ONDOWNLOAD")
            {
                Logging.RecordLogEvent($"Requesting exit to begin update");
                rgatUI.RequestExit();
            }
            else
            {
                Logging.RecordLogEvent($"Update staged for install on exit");
            }
        }


        public static void PerformFileSwap(string new_rgatPath)
        {
            Logging.RecordLogEvent("Performing fileswap of old rgat with " + new_rgatPath);

            string exeName = Path.Combine(GlobalConfig.BaseDirectory, "UpdateFinaliser.exe");
            try
            {
                byte[]? installFinaliserEXE = global::rgat.Properties.Resources.UpdateFinaliserEXE;
                File.WriteAllBytes(exeName, installFinaliserEXE);
                string dllName = Path.Combine(GlobalConfig.BaseDirectory, "UpdateFinaliser.dll");
                byte[]? installFinaliserDLL = global::rgat.Properties.Resources.UpdateFinaliserDLL;
                File.WriteAllBytes(dllName, installFinaliserEXE);
                string runconfig = Path.Combine(GlobalConfig.BaseDirectory, "UpdateFinaliser.runtimeconfig.json");
                byte[]? runconfigJson = global::rgat.Properties.Resources.UpdateFinaliser_runtimeconfig;
                File.WriteAllBytes(runconfig, runconfigJson);
            }
            catch (Exception e)
            {
                Logging.RecordException($"Failed to write update finaliser to disk directory: {e.Message}", e);
                return;
            }

            System.Diagnostics.Process.Start(exeName, new List<string>(){
                System.Diagnostics.Process.GetCurrentProcess().Id.ToString(), //wait for this process to be gone
                GlobalConfig.BaseDirectory, //put the update here
                new_rgatPath, //the downloaded update
                "true" //relaunch rgat after the update
            });
            rgatUI.RequestExit();
        }

        private static void GetChangeIcon(string changeType, out char icon, out WritableRgbaFloat colour)
        {
            switch (changeType)
            {
                case "Added":
                    icon = ImGuiController.FA_ICON_PLUS;
                    colour = new WritableRgbaFloat(System.Drawing.Color.Green);
                    break;
                case "Changed":
                    icon = ImGuiController.FA_ICON_RIGHT;
                    colour = new WritableRgbaFloat(System.Drawing.Color.Blue);
                    break;
                case "Fixed":
                    icon = ImGuiController.FA_ICON_WRENCH;
                    colour = new WritableRgbaFloat(System.Drawing.Color.Blue);
                    break;
                case "Security":
                    icon = ImGuiController.FA_ICON_WARNING;
                    colour = new WritableRgbaFloat(System.Drawing.Color.Red);
                    break;
                case "Deprecated":
                    icon = ImGuiController.FA_ICON_DOWN;
                    colour = new WritableRgbaFloat(0xff131313);
                    break;
                case "Removed":
                    icon = ImGuiController.FA_ICON_CROSS;
                    colour = new WritableRgbaFloat(0x00737373);
                    break;
                default:
                    icon = '?';
                    colour = new WritableRgbaFloat(0xff353535);
                    break;
            }
        }

    }
}
