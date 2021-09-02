/*
 * Adapted from https://gist.github.com/prime31/91d1582624eb2635395417393018016e
 * found via https://github.com/mellinoe/ImGui.NET/issues/22
 */

using ImGuiNET;
using Newtonsoft.Json.Linq;
using rgat;
using rgat.Config;
using rgat.Widgets;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading;

namespace rgatFilePicker
{
    public class FilePicker
    {
        FilePicker(BridgeConnection remoteMirror = null)
        {
            _remoteMirror = remoteMirror;
            Created = DateTime.Now;
            myID = Created.ToString();
            _refreshTimer = new System.Timers.Timer(2000);
            _refreshTimer.AutoReset = false;
            _refreshTimer.Elapsed += FireTimer;
            _refreshTimer.Start();
        }
        private void FireTimer(object sender, System.Timers.ElapsedEventArgs e)
        {
            _refreshTimerFired = true;

        }

        System.Timers.Timer _refreshTimer;
        bool _refreshTimerFired = false;

        BridgeConnection _remoteMirror;
        private const int RefreshThresholdSeconds = 2;
        public DateTime Created { get; private set; }
        string myID;

        private class FileMetadata
        {
            public FileMetadata(string _path)
            {
                path = _path;
                extension = Path.GetExtension(_path);
            }

            public string path = "";
            public string filename = "";
            public DateTime LastWriteTime;
            public float namewidth = 0;
            public string extension = "";
            public string size_str = "";
            public DateTime timeFound = DateTime.MinValue;
            public bool isDeleted = false;
            public bool isNew = false;
            public bool expired = false;
            public long FileSize = 0;
            public void refreshStates()
            {
                if (isNew && (DateTime.Now - timeFound).TotalSeconds > 5) isNew = false;
                if (isDeleted && (DateTime.Now - timeFound).TotalSeconds > 5)
                {
                    expired = true;
                }
            }

            public void SetFileSize(long size)
            {
                FileSize = size;
                size_str = String.Format("{0:n0}", size);
            }
            public void UpdateLocalFileMetadata()
            {
                if (isDeleted) return;
                if (Directory.Exists(path)) return;
                try
                {
                    FileInfo fileinfo = new FileInfo(path);
                    SetFileSize(fileinfo.Length);
                    LastWriteTime = fileinfo.LastWriteTime;

                    string ext = fileinfo.Extension;
                    if (ext.StartsWith('.')) ext = ext.Substring(1);
                    extension = ext;
                }
                catch { return; }

            }

            public uint ListingColour()
            {
                refreshStates();

                if (isNew)
                {
                    double secondsSince = (DateTime.Now - timeFound).TotalSeconds;
                    double intensity = 1 - (secondsSince / 20.0);
                    intensity = Math.Min(Math.Max(intensity, 0.3), 1.0);
                    uint red = (uint)Math.Floor(255.0 * (1 - intensity) * 3);
                    uint green = (uint)Math.Floor(255.0 * intensity) << 8;
                    uint blue = (uint)Math.Floor(255.0 * (1 - intensity) * 3) << 16;
                    return (uint)(0xff000000 | blue | green | red);
                }
                if (isDeleted)
                {
                    double secondsSince = (DateTime.Now - timeFound).TotalSeconds;
                    double alphaMul = 1 - (secondsSince / 20.0);
                    alphaMul = Math.Min(Math.Max(alphaMul, 0.6), 1.0);
                    uint alpha = (uint)Math.Floor(255.0 * alphaMul) << 24;
                    return (uint)((alpha) | 0x0000ff);
                }

                return 0xeeffffff;
            }
        }
        private class DirectoryContents
        {

            private DateTime lastRefreshed;
            private string basePath;
            private List<string> latestDirPaths = null;
            private List<string> latestFilePaths = null;
            private List<string> addedDirPaths = new List<string>();
            private List<string> addedFilePaths = new List<string>();
            private List<FileMetadata> lostDirs = new List<FileMetadata>();
            private List<FileMetadata> lostFiles = new List<FileMetadata>();
            public string ErrMsg = "";
            public Dictionary<string, FileMetadata> fileData { get; private set; } = null;
            public Dictionary<string, FileMetadata> dirData { get; private set; } = null;

            public DirectoryContents(string _path)
            {
                basePath = _path;
                fileData = new Dictionary<string, FileMetadata>();
                dirData = new Dictionary<string, FileMetadata>();
            }

            public List<Tuple<string, bool>> AllPaths()
            {
                List<Tuple<string, bool>> result = new List<Tuple<string, bool>>();
                foreach (var file in dirData)
                {
                    result.Add(new Tuple<string, bool>(file.Key, true));
                }
                foreach (var file in fileData)
                {
                    result.Add(new Tuple<string, bool>(file.Key, false));
                }
                return result;
            }

            public void IngestDirectories(List<string> dirs, DirectoryContents newContentsObj = null)
            {
                if (latestDirPaths != null)
                {
                    //flag new directories
                    dirs.Where(f => !dirData.ContainsKey(f)).ToList().ForEach(f => addedDirPaths.Add(f));

                    foreach (string dir in dirData.Keys.Where(dn => !dirs.Contains(dn)))
                    {
                        if (lostDirs.Count(m => m.filename == dir) == 0)
                        {
                            FileMetadata m = dirData[dir];
                            m.path = dir;
                            m.isDeleted = true;
                            m.isNew = false;
                            m.timeFound = DateTime.Now;
                            if (!m.expired) lostDirs.Add(m);
                            dirData.Remove(dir);
                        }
                    }
                }
                latestDirPaths = dirs;

                if (rgatState.ConnectedToRemote)
                {
                    if (newContentsObj != null)
                    {
                        TransferRemoteDirMetadata(newContentsObj);
                    }
                }
                else
                {
                    ExtractMetaData_Dirs();
                }

            }

            public void IngestFiles(List<string> files, DirectoryContents newContentsObj = null)
            {
                if (latestFilePaths != null)
                {
                    //flag new files
                    files.Where(f => !fileData.ContainsKey(f)).ToList().ForEach(f => addedFilePaths.Add(f));

                    //flag removed files
                    foreach (string file in fileData.Keys.Where(fn => !files.Contains(fn)))
                    {
                        if (lostFiles.Count(m => m.filename == file) == 0)
                        {
                            FileMetadata m = fileData[file];
                            if (!m.expired)
                            {
                                m.isDeleted = true;
                                m.isNew = false;
                                m.timeFound = DateTime.Now;
                                lostFiles.Add(m);
                            }
                        }
                    }
                }
                latestFilePaths = files;

                if (rgatState.ConnectedToRemote && newContentsObj != null)
                    TransferRemoteFileMetadata(newContentsObj);
                else
                    ExtractMetaData_Files();
            }


            private void TransferRemoteFileMetadata(DirectoryContents newContentsObj)
            {
                Dictionary<string, FileMetadata> newFileData = new Dictionary<string, FileMetadata>();
                foreach (string path in latestFilePaths)
                {
                    newFileData[path] = newContentsObj.fileData[path];

                    //newly created while window was open
                    if ((bool)addedFilePaths?.Contains(path))
                    {
                        newFileData[path].isNew = true;
                        newFileData[path].timeFound = DateTime.Now;
                    }
                }
                lostFiles.Where(lf => !lf.expired).ToList().ForEach(m => newFileData[m.filename] = m);
                fileData.Clear();
                fileData = newFileData;
            }

            private void ExtractMetaData_Files()
            {
                Debug.Assert(!rgatState.ConnectedToRemote);
                Dictionary<string, FileMetadata> newFileData = new Dictionary<string, FileMetadata>();
                foreach (string path in latestFilePaths)
                {
                    //not a new file, just update metadata like size/timestamps
                    if (fileData.ContainsKey(path))
                    {
                        newFileData[path] = fileData[path];
                        newFileData[path].UpdateLocalFileMetadata();
                        continue;
                    }

                    FileMetadata m = new FileMetadata(path);
                    m.filename = Path.GetFileName(path);
                    m.namewidth = ImGui.CalcTextSize(m.filename).X;

                    //newly created while window was open
                    if ((bool)addedFilePaths?.Contains(path))
                    {
                        m.isNew = true;
                        m.timeFound = DateTime.Now;
                    }
                    m.UpdateLocalFileMetadata();
                    newFileData[path] = m;
                }

                lostFiles.Where(lf => !lf.expired).ToList().ForEach(m => newFileData[m.filename] = m);
                fileData.Clear();
                fileData = newFileData;
            }

            private void ExtractMetaData_Dirs()
            {

                Dictionary<string, FileMetadata> newDirData = new Dictionary<string, FileMetadata>();
                foreach (string path in latestDirPaths)
                {
                    if ((bool)dirData?.ContainsKey(path))
                    {
                        newDirData[path] = dirData[path];
                        continue;
                    }

                    Debug.Assert(!rgatState.ConnectedToRemote);
                    FileMetadata m = new FileMetadata(path);
                    m.LastWriteTime = new FileInfo(path).LastWriteTime;
                    m.filename = Path.GetFileName(path);
                    m.namewidth = ImGui.CalcTextSize(m.filename).X;

                    if ((bool)addedDirPaths?.Contains(path))
                    {
                        m.isNew = true;
                        m.timeFound = DateTime.Now;
                    }
                    newDirData[path] = m;
                }


                foreach (FileMetadata m in lostDirs)
                {
                    m.refreshStates();
                    if (!m.expired)
                    {
                        newDirData[m.filename] = m;
                    }
                }

                dirData.Clear();
                dirData = newDirData;
            }


            private void TransferRemoteDirMetadata(DirectoryContents newContentsObj)
            {
                dirData = newContentsObj.dirData;
                foreach (string path in dirData.Keys)
                {
                    //newly created while window was open
                    if ((bool)addedDirPaths?.Contains(path))
                    {
                        dirData[path].isNew = true;
                        dirData[path].timeFound = DateTime.Now;
                    }
                }

            }




            public void RefreshDirectoryContents(List<Tuple<string, bool>> latest_dir_entires, DirectoryContents newContentsObj = null)
            {

                if (lostFiles.RemoveAll(s => s.expired) > 0)
                {
                    fileData.Where(kv => kv.Value.expired).ToList().ForEach(s => fileData.Remove(s.Key));
                }

                if (lostDirs.RemoveAll(s => s.expired) > 0)
                {
                    dirData.Where(kv => kv.Value.expired).ToList().ForEach(s => dirData.Remove(s.Key));
                }

                addedDirPaths.RemoveAll(s => !dirData.ContainsKey(s) || !dirData[s].isNew);
                addedFilePaths.RemoveAll(s => !fileData.ContainsKey(s) || !fileData[s].isNew);

                var files = new List<string>();
                var dirs = new List<string>();

                foreach (var path_isdir in latest_dir_entires)
                {
                    if (path_isdir.Item2)
                    {
                        dirs.Add(path_isdir.Item1);
                    }
                    else
                    {
                        files.Add(path_isdir.Item1);
                    }

                }

                IngestDirectories(dirs, newContentsObj);
                IngestFiles(files, newContentsObj);

                addedDirPaths.Clear();
                addedFilePaths.Clear();
                lastRefreshed = DateTime.Now;
            }

            public bool recentlyRefreshed()
            {
                return (DateTime.Now - lastRefreshed).TotalSeconds < RefreshThresholdSeconds;
            }
        }
        /*
 else if (!OnlyAllowFolders)
 {
     if (AllowedExtensions == null)
     {
         files.Add(fse);
     }
     else
     {
         var ext = Path.GetExtension(fse);
         if (AllowedExtensions.Contains(ext))
             files.Add(fse);
     }
 }
 */

        public enum PickerResult { eNoAction, eTrue, eFalse };
        static readonly Dictionary<object, FilePicker> _filePickers = new Dictionary<object, FilePicker>();
        static readonly Dictionary<object, FILEPICKER_DATA> _filePickerData = new Dictionary<object, FILEPICKER_DATA>();
        FILEPICKER_DATA Data = new FILEPICKER_DATA();
        public DateTime LastDriveListRefresh = DateTime.MinValue;
        public string SelectedFile;
        public List<string> SelectedFiles;
        public List<string> SelectedDirectories;
        public List<string> AllowedExtensions = new List<string>();
        public bool OnlyAllowFolders;
        public bool AllowMultiSelect;
        readonly object _lock = new object();


        class FILEPICKER_DATA
        {
            public List<Tuple<string, string>> AvailableDriveStrings = new List<Tuple<string, string>>();
            public DirectoryContents Contents;
            public string CurrentDirectory;
            public bool CurrentDirectoryExists;
            public string CurrentDirectoryParent;
            public string NextRemoteDirectory;
            public bool CurrentDirectoryParentExists;
            public string ErrMsg;
        }
        private bool _badDir = false;

        public static FilePicker GetDirectoryPicker(object o, string startingPath)
            => GetFilePicker(o, startingPath, null, true);

        //this feels like a very C way of doing things, the Imgui.InputText needs a byte array though
        public int SelectedFileBytes(ref byte[] result)
        {
            byte[] pathBytes = Encoding.ASCII.GetBytes(SelectedFile);
            int resultLen = Math.Min(pathBytes.Length + 1, result.Length - 1);
            Array.Copy(pathBytes, result, resultLen - 1);
            result[resultLen - 1] = 0;
            return resultLen;
        }


        public static FilePicker GetRemoteFilePicker(object o, BridgeConnection remoteMirror, string searchFilter = null, bool onlyAllowFolders = false, bool allowMulti = false)
        {

            if (!_filePickers.TryGetValue(o, out FilePicker fp) || fp._remoteMirror.LastAddress != remoteMirror.LastAddress)
            {
                fp = new FilePicker(remoteMirror: remoteMirror);
                fp.Data.CurrentDirectory = RemoteDataMirror.RootDirectory;
                fp.OnlyAllowFolders = onlyAllowFolders;
                fp.AllowMultiSelect = allowMulti;
                if (fp.AllowMultiSelect)
                {
                    fp.SelectedFiles = new List<string>();
                    fp.SelectedDirectories = new List<string>();
                }

                if (searchFilter != null)
                {
                    if (fp.AllowedExtensions != null)
                        fp.AllowedExtensions.Clear();
                    else
                        fp.AllowedExtensions = new List<string>();

                    fp.AllowedExtensions.AddRange(searchFilter.Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries));
                }

                _filePickers.Add(o, fp);
            }

            return fp;
        }


        public static FilePicker GetFilePicker(object o, string startingPath, string searchFilter = null, bool onlyAllowFolders = false, bool allowMulti = false)
        {

            if (!_filePickers.TryGetValue(o, out FilePicker fp) || fp._remoteMirror != null)
            {
                fp = new FilePicker(remoteMirror: null);
                fp.OnlyAllowFolders = onlyAllowFolders;

                if (searchFilter != null)
                {
                    if (fp.AllowedExtensions != null)
                        fp.AllowedExtensions.Clear();
                    else
                        fp.AllowedExtensions = new List<string>();

                    fp.AllowedExtensions.AddRange(searchFilter.Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries));
                }
                fp.AllowMultiSelect = allowMulti;
                if (fp.AllowMultiSelect)
                {
                    fp.SelectedFiles = new List<string>();
                    fp.SelectedDirectories = new List<string>();
                }

                fp.SetActiveDirectory(startingPath);
                _filePickers.Add(o, fp);
            }

            return fp;
        }


        public static void RemoveFilePicker(object o) => _filePickers.Remove(o);

        /// <summary>
        /// Draw a non-directory file in the file list
        /// </summary>
        /// <param name="path">Full path of the file</param>
        /// <param name="filemeta">FileMetadata information for the file</param>
        /// <returns>True if the entry was activated (select+enter or double clicked)</returns>
        private bool EmitFileSelectableEntry(string path, FileMetadata filemeta)
        {
            bool wasActivated = false;
            ImGui.TableNextRow();
            ImGui.TableNextColumn();
            ImGui.PushStyleColor(ImGuiCol.Text, filemeta.ListingColour());
            bool isSelected = SelectedFile == path || (AllowMultiSelect && SelectedFiles.Contains(path));
            string label = filemeta.filename;
            if (filemeta.extension == "exe" || filemeta.extension == "dll")
            {
                label = $"{ImGuiController.FA_ICON_FILECODE} {label}";
            }
            else if (filemeta.extension == "rgat")
            {
                label = $"{ImGuiController.FA_ICON_FILEPLAIN} {label}";
            }


            if (ImGui.Selectable(label, isSelected, ImGuiSelectableFlags.SpanAllColumns) 
                || ImGui.IsItemClicked(ImGuiMouseButton.Right))
            {
                if (!isSelected)
                {
                    if (this.AllowMultiSelect && !this.SelectedFiles.Contains(path))
                    {
                        this.SelectedFiles.Add(path);
                    }
                    else
                    {
                        this.SelectedFile = path;
                    }
                }
                else
                {
                    if (this.AllowMultiSelect)
                    {
                        this.SelectedFiles.RemoveAll(x => x == path);
                    }
                    else
                    {
                        this.SelectedFile = null;
                    }
                }
            }
            wasActivated = (ImGui.IsItemHovered() && ImGui.IsMouseDoubleClicked(0));
            wasActivated = wasActivated || (isSelected && ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.Enter)));
            ImGui.TableNextColumn();
            ImGui.Text(filemeta.extension);
            ImGui.TableNextColumn();
            ImGui.Text(filemeta.size_str);
            ImGui.TableNextColumn();
            string modified = filemeta.LastWriteTime.ToShortTimeString() + " " + filemeta.LastWriteTime.ToShortDateString();
            ImGui.Text(modified);
            ImGui.TableNextColumn();

            ImGui.PopStyleColor();
            return wasActivated;
        }



        /// <summary>
        /// Fill out the listing of the remote directory
        /// lock must be held
        /// </summary>
        /// <param name="responseTok">JToken containing information about the current directory</param>
        /// <returns>true if the data was valid</returns>
        bool InitCurrentDirInfo(JToken responseTok)
        {
            if (responseTok.Type != JTokenType.Object) return false;
            JObject response = responseTok.ToObject<JObject>();

            if (!response.TryGetValue("Current", out JToken currentDirTok) || currentDirTok.Type != JTokenType.String) return false;
            string path = currentDirTok.ToString();
            if (!response.TryGetValue("CurrentExists", out JToken ctokexists) || ctokexists.Type != JTokenType.Boolean) return false;
            if (!response.TryGetValue("Parent", out JToken parentTok) || parentTok.Type != JTokenType.String) return false;
            if (!response.TryGetValue("ParentExists", out JToken ptokexists) || ptokexists.Type != JTokenType.Boolean) return false;
            if (!response.TryGetValue("Error", out JToken errTok) || errTok.Type != JTokenType.String) return false;
            if (!response.TryGetValue("Contents", out JToken contentsTok) || contentsTok.Type != JTokenType.Object) return false;

            if (!ParseRemoteDirectoryContents(path, contentsTok.ToObject<JObject>(), out DirectoryContents newDirContents)) return false;


            if (Data.Contents != null && Data.CurrentDirectory == currentDirTok.ToString() && Data.NextRemoteDirectory == Data.CurrentDirectory)
            {
                _sortedDirs = null;
                _sortedFiles = null;
                Data.Contents.RefreshDirectoryContents(newDirContents.AllPaths(), newDirContents);
            }
            else
            {
                Data.CurrentDirectory = currentDirTok.ToString();
                Data.CurrentDirectoryExists = ctokexists.ToObject<bool>();

                Data.CurrentDirectoryParent = parentTok.ToString();
                Data.CurrentDirectoryParentExists = ptokexists.ToObject<bool>();
                SetFileSystemEntries(Data.CurrentDirectory, newDirContents.AllPaths(), newDirContents);
            }


            Data.ErrMsg = errTok.ToString();
            return true;
        }


        bool ParseRemoteDirectoryContents(string dirpath, JObject remoteData, out DirectoryContents contents)
        {
            contents = new DirectoryContents(dirpath);
            if (!remoteData.TryGetValue("Files", out JToken filesTok) || filesTok.Type != JTokenType.Array
                || !remoteData.TryGetValue("Dirs", out JToken dirsTok) || dirsTok.Type != JTokenType.Array)
            {
                return false;
            }

            foreach (JToken fileTok in (JArray)filesTok)
            {
                if (fileTok.Type == JTokenType.Array)
                {
                    JArray fileitem = (JArray)fileTok;
                    if (fileitem.Count == 4 &&
                        fileitem[0].Type == JTokenType.String &&
                        fileitem[1].Type == JTokenType.Boolean &&
                        fileitem[2].Type == JTokenType.Integer &&
                        fileitem[3].Type == JTokenType.Date
                        )
                    {
                        string itempath = Path.Combine(dirpath, fileitem[0].ToString());
                        FileMetadata m = new FileMetadata(itempath);
                        m.filename = Path.GetFileName(itempath);
                        m.namewidth = ImGui.CalcTextSize(m.filename).X;
                        m.LastWriteTime = fileitem[3].ToObject<DateTime>();
                        m.SetFileSize(fileitem[2].ToObject<long>());
                        contents.fileData.Add(itempath, m);
                    }
                }
            }

            foreach (JToken fileTok in (JArray)dirsTok)
            {
                if (fileTok.Type == JTokenType.Array)
                {
                    JArray fileitem = (JArray)fileTok;
                    if (fileitem.Count == 4 &&
                        fileitem[0].Type == JTokenType.String &&
                        fileitem[1].Type == JTokenType.Boolean &&
                        fileitem[2].Type == JTokenType.Integer &&
                        fileitem[3].Type == JTokenType.Date
                        )
                    {
                        string itempath = Path.Combine(dirpath, fileitem[0].ToString());
                        FileMetadata m = new FileMetadata(itempath);
                        m.filename = Path.GetFileName(itempath);
                        m.namewidth = ImGui.CalcTextSize(m.filename).X;
                        m.LastWriteTime = fileitem[3].ToObject<DateTime>();
                        contents.dirData.Add(itempath, m);
                    }
                }
            }

            return true;
        }

        bool HandleRemoteDirInfoCallback(JToken response)
        {
            lock (_lock)
            {
                pendingCmdCount -= 1;
                if (InitCurrentDirInfo(response))
                {
                    if (Data.CurrentDirectory == Data.NextRemoteDirectory)
                        Data.NextRemoteDirectory = null;
                }
                else
                {
                    Logging.RecordLogEvent($"Bad DirectoryInfo response", Logging.LogFilterType.TextError);
                    rgatState.NetworkBridge.Teardown("Bad DirectoryInfo response");
                    SetActiveDirectory(Environment.CurrentDirectory);
                }

                if (pendingCmdCount == 0) _refreshTimer.Start();
                return true;
            }
        }

        int pendingCmdCount = 0;

        public unsafe PickerResult Draw(object objKey)
        {
            if (Data.CurrentDirectory == null || Data.NextRemoteDirectory != null)
            {
                Debug.Assert(_remoteMirror != null);
                string myID = this.Created.ToString();

                RemoteDataMirror.ResponseStatus status = RemoteDataMirror.CheckTaskStatus("DirectoryInfo", myID);
                switch (status)
                {
                    case RemoteDataMirror.ResponseStatus.eNoRecord:
                        string param = (Data.NextRemoteDirectory != null) ? Data.NextRemoteDirectory : Data.CurrentDirectory;
                        int cmdid = rgatState.NetworkBridge.SendCommand("DirectoryInfo", recipientID: this.myID, callback: HandleRemoteDirInfoCallback, param: param);
                        lock (_lock)
                        {
                            _refreshTimer.Stop();
                            _refreshTimerFired = false;
                            pendingCmdCount += 1;
                        }
                        if (Data.CurrentDirectory == null)
                        {
                            ImGui.Text("Loading from remote...");
                            return PickerResult.eNoAction;
                        }
                        else break;

                    case RemoteDataMirror.ResponseStatus.eWaiting:
                        if (Data.CurrentDirectory == null)
                        {
                            ImGui.Text("Loading from remote...");
                            return PickerResult.eNoAction;
                        }
                        else break;

                    default:
                        Logging.RecordLogEvent($"Bad response status {status}", filter: Logging.LogFilterType.TextError);
                        rgatState.NetworkBridge.Teardown($"Bad response status { status}");
                        SetActiveDirectory(Environment.CurrentDirectory);
                        return PickerResult.eNoAction;
                }
            }

            lock (_lock)
            {
                if (_refreshTimerFired && pendingCmdCount == 0)
                {
                    if (_remoteMirror != null)
                    {
                        Data.NextRemoteDirectory = Data.CurrentDirectory;
                        _refreshTimerFired = false;
                    }
                    else
                    {
                        _sortedDirs = null;
                        _sortedFiles = null;
                        SetFileSystemEntries(Data.CurrentDirectory, GetFileSystemEntries());
                    }

                }
            }


            DrawPickerControlsBar();
            PickerResult result = DrawFilesContents(objKey);
            if (result != PickerResult.eNoAction && SelectedFile == null) result = PickerResult.eFalse;
            return result;
        }

        void DrawPickerControlsBar()
        {
            string root = Path.GetPathRoot(Data.CurrentDirectory);
            bool enabled = _directoryHistoryPosition < (_directoryHistory.Count - 1);
            if (SmallWidgets.DisableableButton($"{ImGuiController.FA_ICON_LEFT}", enabled: enabled))
            {
                _directoryHistoryPosition += 1;
                SetActiveDirectory(_directoryHistory.ToArray()[_directoryHistoryPosition], false);
            }
            if (enabled && ImGui.IsItemHovered())
            {
                ShowDirectoryHistory();
            }
            ImGui.SameLine();
            if (ImGui.Button($"{ImGuiController.FA_ICON_UP}"))
            {
                SetActiveDirectory(Directory.GetParent(Data.CurrentDirectory).FullName);
            }
            SmallWidgets.MouseoverText("Parent Directory");
            ImGui.SameLine();
            enabled = _directoryHistoryPosition > 0;
            if (SmallWidgets.DisableableButton($"{ImGuiController.FA_ICON_RIGHT}", enabled: enabled))
            {
                _directoryHistoryPosition -= 1;
                SetActiveDirectory(_directoryHistory.ToArray()[_directoryHistoryPosition], false);
            }
            if (enabled && ImGui.IsItemHovered())
            {
                ShowDirectoryHistory();
            }
            ImGui.SameLine();
            string currentDirString = Data.CurrentDirectory;
            ImGuiInputTextFlags flags = ImGuiInputTextFlags.EnterReturnsTrue;
            if (ImGui.InputText("Path", ref currentDirString, 4096, flags))
            {
                if (Path.GetDirectoryName(currentDirString + "\\") != Data.CurrentDirectory)
                {
                    SetActiveDirectory(currentDirString);
                }
            }
            
            if (AllowMultiSelect && (SelectedFiles.Count+SelectedDirectories.Count) > 0)
            {
                ImGui.SameLine(ImGui.GetContentRegionMax().X - 85);
                if (ImGui.Button("Clear Selected"))
                {
                    this.SelectedFiles.Clear();
                    this.SelectedDirectories.Clear();
                }
                if (ImGui.IsItemHovered())
                {
                    const int maxlen = 65;
                    const int maxcount = 3;
                    List<Tuple<string, bool>> allSelected = new List<Tuple<string, bool>>();
                    allSelected.AddRange(SelectedDirectories.Select(dir => new Tuple<string, bool>(dir, true)));
                    allSelected.AddRange(SelectedFiles.Select(file => new Tuple<string, bool>(file, false)));

                    ImGui.BeginTooltip();
                    for (var i = 0; i < allSelected.Count; i++)
                    {
                        if (i >= maxcount)
                        {
                            ImGui.Text($"...and {allSelected.Count - i} more");
                            break;
                        }
                        Tuple<string, bool> item = allSelected[i];
                        string path = item.Item1;
                        int showLen = Math.Min(maxlen, path.Length);
                        int start = Math.Max(0, path.Length - showLen);
                        string label = path.Substring(start, showLen);
                        if (path.Length > showLen)
                            label = "..." + label;
                        if (item.Item2)
                            label = $"{ImGuiController.FA_ICON_DIRECTORY} {label}";
                        else
                            label = $"{ImGuiController.FA_ICON_FILEPLAIN} {label}";
                        ImGui.Text(label);
                    }
                    ImGui.EndTooltip();
                }
            }
        }

        PickerResult DrawFilesContents(object objKey)
        {
            const int LEFTCOLWIDTH = 150;

            float BTNSGRPHEIGHT = 28;
            float Yavail = ImGui.GetContentRegionAvail().Y;
            float FILEPANEHEIGHT = Yavail;
            float DRIVEPANEHEIGHT = (Yavail / 2) - 12;
            float RECENTPANEHEIGHT = (Yavail / 2) - (BTNSGRPHEIGHT);

            ImGui.BeginGroup();
            {
                DrawDrivesList(new Vector2(LEFTCOLWIDTH, DRIVEPANEHEIGHT), objKey);
                DrawRecentDirsList(new Vector2(LEFTCOLWIDTH, RECENTPANEHEIGHT));
                PickerResult btnResult = DrawButtons(BTNSGRPHEIGHT);
                if (btnResult != PickerResult.eNoAction)
                    return btnResult;

            }
            ImGui.EndGroup();
            ImGui.SameLine();
            PickerResult result = DrawFilesList(FILEPANEHEIGHT, objKey);

            return result;
        }

        void ShowDirectoryHistory()
        {
            ImGui.BeginTooltip();
            ImGui.Text($"Directory History");
            ImGui.Separator();
            ImGui.Indent(6);
            for (var historyi = 0; historyi < _directoryHistory.Count; historyi++)
            {
                string dir = _directoryHistory[historyi];
                uint textcolour = historyi == _directoryHistoryPosition ? Themes.GetThemeColourUINT(Themes.eThemeColour.eTextEmphasis1) : Themes.GetThemeColourImGui(ImGuiCol.Text);
                ImGui.PushStyleColor(ImGuiCol.Text, textcolour);
                ImGui.Text(dir);
                ImGui.PopStyleColor();
            }
            ImGui.Indent(-6);
            ImGui.EndTooltip();
        }



        PickerResult DrawButtons(float btnHeight)
        {
            ImGui.BeginGroup();
            {
                ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourUINT(Themes.eThemeColour.eTextDull2));
                if (ImGui.Button("Cancel", new Vector2(50, btnHeight)))
                {
                    ImGui.CloseCurrentPopup();
                    return PickerResult.eFalse;
                }
                ImGui.PopStyleColor();

                if (AllowMultiSelect)
                {
                    int selectedCount = SelectedDirectories.Count + SelectedFiles.Count;
                    if (selectedCount > 0)
                    {
                        ImGui.SameLine();
                        if (ImGui.Button($"Select {selectedCount}", new Vector2(80, btnHeight)))
                        {
                            SelectedFile = Data.CurrentDirectory;
                            ImGui.CloseCurrentPopup();
                            return PickerResult.eTrue;
                        }
                    }
                }
                else
                {
                    if (OnlyAllowFolders)
                    {
                        ImGui.SameLine();
                        if (ImGui.Button("Select Folder", new Vector2(80, btnHeight)))
                        {
                            SelectedFile = Data.CurrentDirectory;
                            ImGui.CloseCurrentPopup();
                            return PickerResult.eTrue;
                        }
                        if (ImGui.IsItemHovered())
                        {
                            ImGui.SetTooltip("Choose the current folder: " + Data.CurrentDirectory);
                        }
                    }
                    else if (SelectedFile != null)
                    {
                        ImGui.SameLine();
                        if (ImGui.Button("Select File", new Vector2(80, btnHeight)))
                        {
                            ImGui.CloseCurrentPopup();
                            return PickerResult.eTrue;
                        }
                        if (ImGui.IsItemHovered())
                        {
                            ImGui.SetTooltip("Choose the selected file: " + SelectedFile);
                        }
                    }
                }
            }
            ImGui.EndGroup();
            return PickerResult.eNoAction;
        }

        List<string> _directoryHistory = new List<string>();
        int _directoryHistoryPosition = 0;

        void SetActiveDirectory(string dir, bool modifyHistory = true)
        {
            if (_remoteMirror == null)
            {
                Data.Contents = new DirectoryContents(dir);
            }
            else
            {
                Data.NextRemoteDirectory = dir;
                _refreshTimer.Stop();
                _refreshTimerFired = false;
                return;
            }

            DirectoryInfo thisdir = new DirectoryInfo(dir);
            Data.CurrentDirectory = thisdir.FullName;
            Data.CurrentDirectoryExists = Directory.Exists(Data.CurrentDirectory);
            if (modifyHistory && Data.CurrentDirectoryExists)
            {
                if (_directoryHistory.Contains(dir))
                    _directoryHistory.Remove(dir);
                _directoryHistory.Insert(0, dir);
                if (_directoryHistory.Count > RGAT_CONSTANTS.UI.FILEPICKER_HISTORY_MAX)
                {
                    _directoryHistory.RemoveRange(RGAT_CONSTANTS.UI.FILEPICKER_HISTORY_MAX, _directoryHistory.Count - RGAT_CONSTANTS.UI.FILEPICKER_HISTORY_MAX);
                }
            }

            Data.CurrentDirectoryParentExists = thisdir.Parent != null && Directory.Exists(thisdir.Parent.FullName);
            if (Data.CurrentDirectoryParentExists)
            {
                Data.CurrentDirectoryParent = thisdir.Parent.FullName;
            }
            else
            {
                Data.CurrentDirectoryParent = "";
            }
            Data.ErrMsg = "";


            SetFileSystemEntries(thisdir.FullName, GetFileSystemEntries());
        }


        List<KeyValuePair<string, FileMetadata>> _sortedDirs;
        List<KeyValuePair<string, FileMetadata>> _sortedFiles;
        PickerResult DrawFilesList(float height, object objKey)
        {
            PickerResult result = PickerResult.eNoAction;
            bool currentBadDir = !Data.CurrentDirectoryExists;

            if (currentBadDir) ImGui.PushStyleColor(ImGuiCol.ChildBg, 0x55000040);

            uint width = (uint)ImGui.GetContentRegionAvail().X;
            Vector2 listSize = new Vector2(width, height);
            if (ImGui.BeginChildFrame(1, listSize, ImGuiWindowFlags.AlwaysAutoResize))
            {

                if (!Data.CurrentDirectoryExists)
                {
                    string[] msgs = new string[] {
                        $"{ImGuiController.FA_ICON_WARNING} Not Found",
                        $"Directory '{Data.CurrentDirectory}' does not exist"
                    };
                    ImguiUtils.DrawRegionCenteredText(msgs);
                }
                else
                {
                    Vector2 sz = ImGui.GetContentRegionAvail();

                    if (Data.ErrMsg != null && Data.ErrMsg.Length > 0)
                    {
                        string[] msgs = new string[] { $"{ImGuiController.FA_ICON_WARNING} Error", Data.ErrMsg };
                        ImguiUtils.DrawRegionCenteredText(msgs);
                    }
                    else
                    {
                        if (ImGui.BeginTable("FileTable", 4, ImGuiTableFlags.ScrollY | ImGuiTableFlags.Sortable, sz))
                        {
                            ImGui.TableSetupScrollFreeze(0, 2);
                            ImGui.TableSetupColumn("File", ImGuiTableColumnFlags.DefaultSort);
                            ImGui.TableSetupColumn("Type", ImGuiTableColumnFlags.WidthFixed, 80);
                            ImGui.TableSetupColumn("Size");
                            ImGui.TableSetupColumn("Modified");
                            ImGui.TableHeadersRow();

                            if (Data.CurrentDirectoryParent != null && Data.CurrentDirectory != Path.GetPathRoot(Data.CurrentDirectory))
                            {
                                ImGui.TableNextRow();
                                ImGui.TableNextColumn();
                                if (ImGui.Selectable("../", false, ImGuiSelectableFlags.SpanAllColumns))
                                {
                                    SetActiveDirectory(Data.CurrentDirectoryParent);
                                }
                                ImGui.TableNextColumn();
                                ImGui.TableNextColumn();
                                ImGui.TableNextColumn();
                            }


                            if (Data.Contents != null)
                            {
                                var ss = ImGui.TableGetSortSpecs();
                                if (_sortedDirs == null || _sortedFiles == null || ss.SpecsDirty)
                                {
                                    SortDisplayFiles(ss.Specs);
                                }

                                result = DrawDirsFilesList();
                            }

                            ImGui.EndTable();
                        }
                    }
                    //ImGui.SetColumnWidth(0, longestFilename + 20);

                }
            }

            ImGui.EndChildFrame();

            if (currentBadDir) ImGui.PopStyleColor();

            if (ImGui.IsAnyMouseDown())
            {
                _filePickers.TryGetValue(objKey, out FilePicker thisFilePicker);
                if (thisFilePicker?.Created.AddMilliseconds(800) < DateTime.Now) //ignore clicks very shortly after creation
                {
                    if (!ImGui.IsMouseHoveringRect(ImGui.GetWindowPos(), ImGui.GetWindowPos() + ImGui.GetWindowSize()) && !ImGui.IsWindowHovered())
                    {
                        result = PickerResult.eFalse;
                        ImGui.CloseCurrentPopup();
                    }
                }
            }
            return result;
        }

        void SortDisplayFiles(ImGuiTableColumnSortSpecsPtr sortSpecs)
        {
            _sortedDirs = new List<KeyValuePair<string, FileMetadata>>();
            switch (sortSpecs.ColumnIndex)
            {
                case 0:
                    if (sortSpecs.SortDirection == ImGuiSortDirection.Ascending)
                        _sortedDirs = Data.Contents.dirData.OrderBy(o => o.Value.filename.ToLower()).ToList();
                    else
                        _sortedDirs = Data.Contents.dirData.OrderByDescending(o => o.Value.filename.ToLower()).ToList();
                    break;
                default:
                    _sortedDirs = Data.Contents.dirData.ToList();
                    break;
            }

            _sortedFiles = new List<KeyValuePair<string, FileMetadata>>();
            switch (sortSpecs.ColumnIndex)
            {
                case 0:
                    if (sortSpecs.SortDirection == ImGuiSortDirection.Ascending)
                        _sortedFiles = Data.Contents.fileData.OrderBy(o => o.Value.filename.ToLower()).ToList();
                    else
                        _sortedFiles = Data.Contents.fileData.OrderByDescending(o => o.Value.filename.ToLower()).ToList();
                    break;
                case 1:
                    if (sortSpecs.SortDirection == ImGuiSortDirection.Ascending)
                        _sortedFiles = Data.Contents.fileData.OrderBy(o => o.Value.extension.ToLower()).ToList();
                    else
                        _sortedFiles = Data.Contents.fileData.OrderByDescending(o => o.Value.extension.ToLower()).ToList();
                    break;
                case 2:
                    if (sortSpecs.SortDirection == ImGuiSortDirection.Ascending)
                        _sortedFiles = Data.Contents.fileData.OrderBy(o => o.Value.FileSize).ToList();
                    else
                        _sortedFiles = Data.Contents.fileData.OrderByDescending(o => o.Value.FileSize).ToList();
                    break;
                case 3:
                    if (sortSpecs.SortDirection == ImGuiSortDirection.Ascending)
                        _sortedFiles = Data.Contents.fileData.OrderBy(o => o.Value.LastWriteTime).ToList();
                    else
                        _sortedFiles = Data.Contents.fileData.OrderByDescending(o => o.Value.LastWriteTime).ToList();
                    break;
                default:
                    _sortedFiles = Data.Contents.fileData.ToList();
                    break;
            }



        }


        PickerResult DrawDirsFilesList()
        {
            PickerResult result = PickerResult.eNoAction;
            float longestFilename = 100;
            foreach (var path_data in _sortedDirs)
            {
                ImGui.TableNextRow();
                ImGui.TableNextColumn();

                FileMetadata md = path_data.Value;
                string path = path_data.Key;
                ImGui.PushStyleColor(ImGuiCol.Text, md.ListingColour());
                bool selected = AllowMultiSelect && SelectedDirectories.Contains(path);
                ImGui.Selectable($"{ImGuiController.FA_ICON_DIRECTORY} {path_data.Value.filename}/", selected, ImGuiSelectableFlags.SpanAllColumns);

                if (AllowMultiSelect &&
                    (ImGui.IsItemClicked(ImGuiMouseButton.Right) ||
                    (ImGui.IsItemClicked(ImGuiMouseButton.Left) && ImGui.GetIO().KeyCtrl)))
                {
                    if (selected)
                    {
                        this.SelectedDirectories.RemoveAll(x => x == path);
                    }
                    else
                    {
                        this.SelectedDirectories.Add(path);
                    }
                }
                else
                {
                    if (ImGui.IsItemClicked(ImGuiMouseButton.Left))
                    {
                        SetActiveDirectory(path);
                    }
                }
                SmallWidgets.MouseoverText("Ctrl-left click or right click to select directories.");

                if (path_data.Value.namewidth > longestFilename)
                    longestFilename = path_data.Value.namewidth;

                ImGui.TableNextColumn();
                ImGui.TableNextColumn();
                //size
                ImGui.Text(path_data.Value.size_str);
                ImGui.TableNextColumn();
                ImGui.Text("");
                ImGui.TableNextColumn();
                ImGui.PopStyleColor();
            }

            foreach (var path_data in _sortedFiles)
            {
                FileMetadata filemd = path_data.Value;
                if (EmitFileSelectableEntry(path: path_data.Key, filemeta: filemd))
                {
                    this.SelectedFile = path_data.Key;
                    ImGui.CloseCurrentPopup();
                    result = PickerResult.eTrue;
                }
                if (path_data.Value.namewidth > longestFilename)
                    longestFilename = path_data.Value.namewidth;
                if (ImGui.IsItemHovered() && ImGui.IsMouseDoubleClicked(0))
                {
                    result = PickerResult.eTrue;
                    ImGui.CloseCurrentPopup();
                }
            }
            return result;
        }


        void DrawRecentDirsList(Vector2 framesize)
        {
            if (ImGui.BeginChildFrame(ImGui.GetID("#RecentDirListFrm"), framesize, ImGuiWindowFlags.AlwaysAutoResize))
            {
                if (ImGui.BeginTable("##RecentPathsTab", 1))
                {
                    ImGui.PushStyleColor(ImGuiCol.HeaderHovered, Themes.GetThemeColourImGui(ImGuiCol.TableHeaderBg));
                    ImGui.PushStyleColor(ImGuiCol.HeaderActive, Themes.GetThemeColourImGui(ImGuiCol.TableHeaderBg));
                    ImGui.TableSetupScrollFreeze(0, 1);
                    ImGui.TableSetupColumn("Recent Places");
                    ImGui.TableHeadersRow();
                    ImGui.PopStyleColor(2);

                    var recentDirs = GlobalConfig.RecentDirectories;
                    foreach (var dir in recentDirs)
                    {
                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        string label = Path.GetFileName(dir.path);
                        if (ImGui.Selectable(label, false, ImGuiSelectableFlags.SpanAllColumns))
                        {
                            SetActiveDirectory(dir.path);
                        }
                        SmallWidgets.MouseoverText(dir.path);
                    }
                    ImGui.EndTable();
                }
                ImGui.EndChildFrame();
            }
        }

        bool TryGetFileInfo(string fileName, out FileInfo realFile)
        {
            try
            {
                realFile = new FileInfo(fileName);
                return true;
            }
            catch
            {
                realFile = null;
                return false;
            }
        }



        List<Tuple<string, bool>> GetFileSystemEntries()
        {
            List<Tuple<string, bool>> newFileListing = new List<Tuple<string, bool>>();
            try
            {
                string[] allpaths = Directory.GetFileSystemEntries(Data.CurrentDirectory);
                foreach (string path in allpaths)
                {
                    if (Directory.Exists(path)) newFileListing.Add(new Tuple<string, bool>(path, true));
                    if (File.Exists(path)) newFileListing.Add(new Tuple<string, bool>(path, false));
                }
            }
            catch (Exception e)
            {
                Data.ErrMsg = $"Failed to list directory '{Data.CurrentDirectory}' contents: {e.Message}";
                Logging.RecordLogEvent(Data.ErrMsg);
            }
            return newFileListing;
        }

        DirectoryContents SetFileSystemEntries(string fullName, List<Tuple<string, bool>> newFileListing, DirectoryContents newDirContentsObj = null)
        {
            if (newDirContentsObj == null)
            {
                if (Data.Contents == null)
                    Data.Contents = new DirectoryContents(fullName);
                Data.Contents.RefreshDirectoryContents(newFileListing, newDirContentsObj);
            }
            else
            {
                Data.Contents = new DirectoryContents(fullName);
                Data.Contents.RefreshDirectoryContents(newFileListing, newDirContentsObj);
                if (Data.Contents.ErrMsg != null && Data.Contents.ErrMsg.Length > 0)
                    Data.ErrMsg = Data.Contents.ErrMsg;
            }
            return Data.Contents;
        }


        /*
         * Drives
         */
        private List<Tuple<string, string>> GetDriveListStrings()
        {
            if ((DateTime.Now - LastDriveListRefresh).TotalSeconds < RefreshThresholdSeconds)
            {
                return Data.AvailableDriveStrings;
            }


            if (_remoteMirror != null && _remoteMirror.Connected)
            {
                RemoteDataMirror.ResponseStatus status = RemoteDataMirror.CheckTaskStatus("GetDrives", myID);
                switch (status)
                {
                    case RemoteDataMirror.ResponseStatus.eNoRecord:
                        _remoteMirror.SendCommand("GetDrives", recipientID: myID, callback: InitRemoteDriveStringsCallback);
                        pendingCmdCount += 1;
                        return Data.AvailableDriveStrings;

                    case RemoteDataMirror.ResponseStatus.eWaiting:
                        return Data.AvailableDriveStrings;

                    default:
                        Logging.RecordLogEvent($"GetDriveListStrings Bad remote response state: {status}", Logging.LogFilterType.TextError);
                        _remoteMirror.Teardown("Bad status in GetDriveListStrings");
                        InitLocalDriveStrings();
                        return Data.AvailableDriveStrings;
                }
            }
            else
            {
                InitLocalDriveStrings();
                return Data.AvailableDriveStrings;
            }
        }

        bool InitRemoteDriveStringsCallback(JToken remoteResponse)
        {
            if (remoteResponse.Type != JTokenType.Array) return false;
            List<Tuple<string, string>> result = new List<Tuple<string, string>>();
            foreach (var dir_drive in (JArray)remoteResponse)
            {
                if (dir_drive.Type != JTokenType.Object) return false;
                JObject drivetuple = (JObject)dir_drive;
                if (drivetuple.TryGetValue("Item1", out JToken val1) && val1.Type == JTokenType.String &&
                     drivetuple.TryGetValue("Item2", out JToken val2) && val2.Type == JTokenType.String)
                {
                    result.Add(new Tuple<string, string>(val1.ToString(), val2.ToString()));
                }
                else
                {
                    return false;
                }
            }
            lock (_lock)
            {
                Data.AvailableDriveStrings = result;
                LastDriveListRefresh = DateTime.Now;
                pendingCmdCount -= 1;
                if (pendingCmdCount == 0) _refreshTimer.Start();
            }
            return true;
        }

        void InitLocalDriveStrings()
        {
            Data.AvailableDriveStrings = GetLocalDriveStrings();
            LastDriveListRefresh = DateTime.Now;
        }


        public static List<Tuple<string, string>> GetLocalDriveStrings()
        {
            List<Tuple<string, string>> result = new List<Tuple<string, string>>();
            DriveInfo[] allDrives = DriveInfo.GetDrives();
            foreach (DriveInfo d in allDrives)
            {
                if (!d.IsReady) continue;
                string driveName = d.Name;
                if (driveName.EndsWith('\\') || driveName.EndsWith('/'))
                {
                    driveName = d.Name.Substring(0, d.Name.Length - 1);
                }
                if (d.VolumeLabel.Length > 0)
                    driveName += " (" + d.VolumeLabel + ")";
                result.Add(new Tuple<string, string>(d.RootDirectory.Name, driveName));
            }
            return result;
        }

        void DrawDrivesList(Vector2 framesize, object objKey)
        {
            if (ImGui.BeginChildFrame(ImGui.GetID("#DrvListFrm"), framesize, ImGuiWindowFlags.AlwaysAutoResize))
            {
                List<Tuple<string, string>> drives = GetDriveListStrings();
                if (ImGui.BeginTable("##DrivesTable", 1))
                {
                    ImGui.PushStyleColor(ImGuiCol.HeaderHovered, Themes.GetThemeColourImGui(ImGuiCol.TableHeaderBg));
                    ImGui.PushStyleColor(ImGuiCol.HeaderActive, Themes.GetThemeColourImGui(ImGuiCol.TableHeaderBg));
                    ImGui.TableSetupScrollFreeze(0, 1);
                    ImGui.TableSetupColumn("Drives");
                    ImGui.TableHeadersRow();
                    ImGui.PopStyleColor(2);

                    foreach (Tuple<string, string> d_l in drives)
                    {
                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        if (ImGui.Selectable(d_l.Item2, false, ImGuiSelectableFlags.SpanAllColumns))
                        {
                            SetActiveDirectory(d_l.Item1);
                        }
                    }
                    ImGui.EndTable();
                }
                ImGui.EndChildFrame();
            }
        }



    }
}