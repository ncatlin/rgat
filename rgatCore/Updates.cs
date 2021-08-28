using ImGuiNET;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace rgat
{
    class Updates
    {
        public static void CheckForUpdates()
        {
            //already checked recently
            DateTime nextCheckMinimum = GlobalConfig.UpdateLastCheckTime.AddMinutes(RGAT_CONSTANTS.NETWORK.UpdateCheckMinimumDelayMinutes);
            if (nextCheckMinimum > DateTime.Now)
            {
                Logging.RecordLogEvent($"Not checking for updates, next check will be next time rgat is launched after {nextCheckMinimum}", Logging.LogFilterType.TextDebug);
                return;
            }

            if (!System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable())
            {
                Logging.RecordLogEvent("Not checking for updates, no network connection available", Logging.LogFilterType.TextDebug);
                return;
            }

            //https://docs.github.com/en/rest/reference/repos#list-releases
            System.Net.Http.HttpClient client = new System.Net.Http.HttpClient();
            System.Net.Http.Headers.ProductInfoHeaderValue versionHeader = new System.Net.Http.Headers.ProductInfoHeaderValue("rgat", RGAT_CONSTANTS.RGAT_VERSION_SEMANTIC.ToString());
            client.DefaultRequestHeaders.UserAgent.Add(versionHeader);
            client.DefaultRequestHeaders.Add("accept", "application/vnd.github.v3+json");
            client.DefaultRequestHeaders.Add("per_page", "1");
            client.DefaultRequestHeaders.Add("page", "0");

            try
            {
                string releasesPath = $"https://api.github.com/repos/ncatlin/rgat/releases";
                CancellationToken exitToken = rgatState.ExitToken;
                Task<HttpResponseMessage> response = client.GetAsync(releasesPath, exitToken);
                response.Wait(exitToken);
                if (response.Result.IsSuccessStatusCode)
                {
                    Task<string> content = response.Result.Content.ReadAsStringAsync();
                    content.Wait(exitToken);
                    JArray responseArr = JArray.Parse(content.Result);
                    Version latestVersion = RGAT_CONSTANTS.RGAT_VERSION_SEMANTIC;
                    bool newVersion = false;
                    foreach (JToken releaseTok in responseArr)
                    {
                        if (releaseTok.Type == JTokenType.Object && ((JObject)releaseTok).TryGetValue("name", out JToken releaseNameTok))
                        {
                            string name = releaseNameTok.ToString();
                            string[] parts = name.Split(" ");
                            if (parts.Length >= 1)
                            {
                                Version releaseVersion = new Version(parts[0]);
                                //todo replace these lines when dev is done
                                if ((releaseVersion != null) && (releaseVersion > latestVersion))
                                {
                                    newVersion = true;
                                    latestVersion = releaseVersion;
                                }
                            }
                        }
                    }

                    if (newVersion && latestVersion > GlobalConfig.UpdateLastCheckVersion)
                    {
                        client = new System.Net.Http.HttpClient();
                        client.DefaultRequestHeaders.UserAgent.Add(versionHeader);
                        client.DefaultRequestHeaders.Add("accept", "application/vnd.github.v3+json");

                        string changelogPath = $"https://api.github.com/repos/ncatlin/rgat/contents/CHANGELOG.md";

                        response = client.GetAsync(changelogPath, exitToken);
                        response.Wait(exitToken);

                        if (response.Result.IsSuccessStatusCode)
                        {
                            content = response.Result.Content.ReadAsStringAsync();
                            content.Wait(exitToken);
                            JObject changelogObj = JObject.Parse(content.Result);
                            if (changelogObj.TryGetValue("content", out JToken b64ChangelogTok) && b64ChangelogTok.Type == JTokenType.String)
                            {
                                string parsedChangelogChanges = ParseChangelogChanges(b64ChangelogTok.ToString());
                                GlobalConfig.RecordAvailableUpdateDetails(latestVersion, parsedChangelogChanges);
                            }
                            else
                            {
                                Logging.RecordLogEvent("Update Check: No valid content in changelog content request", Logging.LogFilterType.TextDebug);
                            }
                        }
                    }
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
        static string ParseChangelogChanges(string b64ChangelogMDContent)
        {
            Version currentVersion = RGAT_CONSTANTS.RGAT_VERSION_SEMANTIC;
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
                if (versionSectionLines.Length < 2) continue;
                string line = versionSectionLines[0].Trim();
                string versionString = line.Substring(1, line.IndexOf(']') - 1);
                if (!System.Version.TryParse(versionString, out Version newChangeVersion)) continue; //'Unreleased'
                if (newChangeVersion <= currentVersion) break;

                totalNewVersionCount += 1;

                for (var changeTypeI = 1; changeTypeI < versionSectionLines.Length; changeTypeI++)
                {
                    string[] changeItems = versionSectionLines[changeTypeI].Split("\n- ");
                    if (changeItems.Length < 2) continue;
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
                if (changesDict.TryGetValue(expectedChangeType, out List<string> changes))
                {
                    result += $"####{expectedChangeType}\n";
                    foreach (string change in changes) result += change + "\n";
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
                string line = GlobalConfig.UpdateLastChanges;
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

        static int TotalChanges = -1;
        static int NewVersions = -1;

        public static void DrawChangesDialog()
    {
        ImGui.PushStyleColor(ImGuiCol.Text, 0xffffffff);
        ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xff000000);
        Version currentVersion = RGAT_CONSTANTS.RGAT_VERSION_SEMANTIC;
        Version newVersion = GlobalConfig.UpdateLastCheckVersion;
        ImGui.Text($"Current Version: {currentVersion}. New Version: {newVersion}");

        string[] changes = GlobalConfig.UpdateLastChanges.Split('\n');

        if (ImGui.BeginTabBar("#ChangesTabs"))
        {
            for (var i = 0; i < changes.Length; i++)
            {
                string item = changes[i].Trim();
                if (item.StartsWith("####"))
                {
                    string category = item.Substring(4, item.Length - 4);
                    if (category.StartsWith("CHANGES")) continue;
                    GetChangeIcon(category, out char icon, out WritableRgbaFloat colour);
                    ImGui.PushStyleColor(ImGuiCol.Tab, colour.ToUint(customAlpha: 150));
                    ImGui.PushStyleColor(ImGuiCol.TabHovered, colour.ToUint(customAlpha: 190));
                    ImGui.PushStyleColor(ImGuiCol.TabActive, colour.ToUint(customAlpha: 255));
                    if (ImGui.BeginTabItem($"{icon} {category}##{i}"))
                    {
                        if (ImGui.BeginTable("#ChangesDlgChild", 1, flags: ImGuiTableFlags.ScrollY | ImGuiTableFlags.ScrollX | ImGuiTableFlags.RowBg, ImGui.GetContentRegionAvail()))
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
                                    break;
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
    }

    static void GetChangeIcon(string changeType, out char icon, out WritableRgbaFloat colour)
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
