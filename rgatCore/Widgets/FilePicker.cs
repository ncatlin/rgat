/*
 * Adapted from https://gist.github.com/prime31/91d1582624eb2635395417393018016e
 * found via https://github.com/mellinoe/ImGui.NET/issues/22
 */

using ImGuiNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.InteropServices;
using Vulkan.Xlib;
using Num = System.Numerics;

namespace rgatFilePicker
{
	public class FilePicker
	{

		private const int RefreshThresholdSeconds = 2;
		private class FileMetadata
		{
			public FileMetadata(string _path) { path = _path; }
			public FileInfo fileinfo = null;
			public string path = "";
			public string filename = "";
			public float namewidth = 0;
			public string extension = "";
			public string size_str = "";
			public DateTime timeFound = DateTime.MinValue;
			public bool isDeleted = false;
			public bool isNew = false;
			public bool expired = false;
			public void refreshStates()
            {
				if (isNew && (DateTime.Now - timeFound).TotalSeconds > 5) isNew = false;
				if (isDeleted && (DateTime.Now - timeFound).TotalSeconds > 5)
				{
					expired = true;
				}
			}

			public void Enrich()
            {
				if (isDeleted) return;
				if (Directory.Exists(path)) return;
                try
                {
					fileinfo = new FileInfo(path);
					size_str = String.Format("{0:n0}", fileinfo.Length);

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
					uint blue = (uint)Math.Floor(255.0 * (1- intensity) *3) << 16;
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

			public DirectoryContents(string _path) {
				basePath = _path;
				fileData = new Dictionary<string, FileMetadata>();
				dirData = new Dictionary<string, FileMetadata>();
				Refresh();
			}

			public void IngestDirectories(List<string> dirs)
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
				ExtractMetaData_Dirs();
			}

			public void IngestFiles(List<string> files)
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

				ExtractMetaData_Files();
			}

			private void ExtractMetaData_Files()
            {
				Dictionary<string, FileMetadata> newFileData = new Dictionary<string, FileMetadata>();
				foreach (string path in latestFilePaths)
				{
					//not a new file, just update metadata like size/timestamps
					if (fileData.ContainsKey(path))
                    {
						newFileData[path] = fileData[path];
						newFileData[path].Enrich();
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
					m.Enrich();
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

					FileMetadata m = new FileMetadata(path);
					m.fileinfo = new FileInfo(path);
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


			public void Refresh()
            {
				if(lostFiles.RemoveAll(s => s.expired) > 0)
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
				string[] entries = null;
				try
				{
					entries = Directory.GetFileSystemEntries(basePath, "");
					ErrMsg = "";
				}
				catch (Exception e)
				{
					ErrMsg = e.Message;
					return;
				}

				foreach (var fse in entries)
				{
					if (Directory.Exists(fse))
					{
						dirs.Add(fse);
					}
                    else
                    {
						files.Add(fse);
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
				}

				IngestDirectories(dirs);
				IngestFiles(files);
				lastRefreshed = DateTime.Now;
			}

			public bool recentlyRefreshed()
            {
				return (DateTime.Now - lastRefreshed).TotalSeconds < RefreshThresholdSeconds;
            }
		}

		public enum PickerResult { eNoAction, eTrue, eFalse};
		static readonly Dictionary<object, FilePicker> _filePickers = new Dictionary<object, FilePicker>();
		Dictionary<object, DirectoryContents> _currentDirContents = new Dictionary<object, DirectoryContents>();
		private List<Tuple<string, string>> _availableDriveStrings = new List<Tuple<string, string>>();
		private DateTime _lastDriveListRefresh = DateTime.MinValue;

		public string RootFolder;
		public string CurrentFolder;
		public string SelectedFile;
		public List<string> AllowedExtensions;
		public bool OnlyAllowFolders;

		private bool _badDir = false;

		public static FilePicker GetFolderPicker(object o, string startingPath)
			=> GetFilePicker(o, startingPath, null, true);

		public static FilePicker GetFilePicker(object o, string startingPath, string searchFilter = null, bool onlyAllowFolders = false)
		{

			if (!_filePickers.TryGetValue(o, out FilePicker fp))
			{
				fp = new FilePicker();
				fp.RootFolder = Path.GetPathRoot(startingPath);
				fp.CurrentFolder = startingPath;
				fp.OnlyAllowFolders = onlyAllowFolders;

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


		public static void RemoveFilePicker(object o) => _filePickers.Remove(o);


		private void EmitFileSelectableEntry(string path, FileMetadata data)
        {
			ImGui.PushStyleColor(ImGuiCol.Text, data.ListingColour());
			bool isSelected = SelectedFile == path;
			if (ImGui.Selectable(data.filename, isSelected, ImGuiSelectableFlags.SpanAllColumns))
				SelectedFile = path;
			ImGui.NextColumn();
			ImGui.Text(data.extension); ImGui.NextColumn();
			ImGui.Text(data.size_str); ImGui.NextColumn();
			string modified = data.fileinfo.LastWriteTime.ToShortDateString() + " " + data.fileinfo.LastWriteTime.ToShortTimeString();
			ImGui.Text(modified); ImGui.NextColumn();

			ImGui.PopStyleColor();
		}


		private List<Tuple<string, string>> GetDriveListStrings()
		{
			if ((DateTime.Now - _lastDriveListRefresh).TotalSeconds < RefreshThresholdSeconds)
            {
				return _availableDriveStrings;
            }

			_availableDriveStrings.Clear();

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
				_availableDriveStrings.Add(new Tuple<string, string>(d.RootDirectory.Name, driveName));
			}

			_lastDriveListRefresh = DateTime.Now;
			return _availableDriveStrings;
		}


		public PickerResult Draw(object o)
		{


			const int LEFTCOLWIDTH = 150;

			float Yavail = ImGui.GetContentRegionAvail().Y - 30;
			float FILEPANEHEIGHT = Yavail;
			float DRIVEPANEHEIGHT = Yavail/2;
			float BTNSGRPHEIGHT = 28;
			float RECENTPANEHEIGHT = Yavail / 2 - BTNSGRPHEIGHT;

			PickerResult result = PickerResult.eNoAction;
			ImGuiWindowFlags windowflags = ImGuiWindowFlags.AlwaysAutoResize;



			ImGui.Text("Path: " + RootFolder + CurrentFolder.Replace(RootFolder, ""));

			ImGui.BeginGroup();
			//Drive list
			if (ImGui.BeginChildFrame(2, new Num.Vector2(LEFTCOLWIDTH, DRIVEPANEHEIGHT), windowflags))
			{
				

				ImGui.Text("Drives");
				ImGui.Separator();


				List<Tuple<string, string>> drives = GetDriveListStrings();

				foreach (Tuple<string, string> d_l in drives)
				{
					if (ImGui.Selectable(d_l.Item2, false, ImGuiSelectableFlags.DontClosePopups))
					{
						CurrentFolder = d_l.Item1;
						RootFolder = d_l.Item1;
						_currentDirContents.Remove(o);
					}
				}
				ImGui.EndChildFrame();
			}

			//Recent Dirs list
			if (ImGui.BeginChildFrame(3, new Num.Vector2(LEFTCOLWIDTH, RECENTPANEHEIGHT), windowflags))
			{
				ImGui.Text("Recent Places");
				ImGui.Separator();
				ImGui.Text("Snap/");
				ImGui.Text("Snap/");
				ImGui.Text("Snap/");
				ImGui.EndChildFrame();
			}


			ImGui.BeginGroup();
			ImGui.PushStyleColor(ImGuiCol.Button, 0xee555555);
			if (ImGui.Button("Cancel", new Vector2(50, BTNSGRPHEIGHT)))
			{
				result = PickerResult.eFalse;
				ImGui.CloseCurrentPopup();
			}
			ImGui.PopStyleColor();

			if (OnlyAllowFolders)
			{
				ImGui.SameLine();
				if (ImGui.Button("Open", new Vector2(50, BTNSGRPHEIGHT)))
				{
					result = PickerResult.eTrue;
					SelectedFile = CurrentFolder;
					ImGui.CloseCurrentPopup();
				}
			}
			else if (SelectedFile != null)
			{
				ImGui.SameLine();
				if (ImGui.Button("Open", new Vector2(50, BTNSGRPHEIGHT)))
				{
					result = PickerResult.eTrue;
					ImGui.CloseCurrentPopup();
				}
			}
			ImGui.EndGroup();

			ImGui.EndGroup();

			ImGui.SameLine();

			if (_badDir) ImGui.PushStyleColor(ImGuiCol.FrameBg, 0x55000040);
			uint width = (uint) ImGui.GetContentRegionAvail().X; 
			Vector2 listSize = new Vector2(width, FILEPANEHEIGHT);
			if (ImGui.BeginChildFrame(1, listSize, windowflags))
			{
				if (_badDir) ImGui.PopStyleColor();

				var di = new DirectoryInfo(CurrentFolder);
				if (!di.Exists)
				{
					_badDir = true;
				}
				else
				{ 
					if (di.Parent != null && CurrentFolder != RootFolder)
					{
						ImGui.PushStyleColor(ImGuiCol.Text, 0xefffffff);
						if (ImGui.Selectable("../", false, ImGuiSelectableFlags.DontClosePopups))
						{ 
							CurrentFolder = di.Parent.FullName;
							di = new DirectoryInfo(CurrentFolder);
							_currentDirContents.Remove(o);
						}
						ImGui.PopStyleColor();
					}



					DirectoryContents contents = GetFileSystemEntries(di.FullName, o);
					if (contents.ErrMsg.Length > 0)
					{
						ImGui.TextWrapped("Failed to read directory: "+ contents.ErrMsg);
						_badDir = true;
					}
					else
					{
						_badDir = false;
						ImGui.Columns(4, "fileentrycolumns");
						ImGui.Separator();
						ImGui.Text("File"); ImGui.NextColumn();
						ImGui.Text("Type"); ImGui.NextColumn();
						ImGui.Text("Size"); ImGui.NextColumn();
						ImGui.Text("Modified"); ImGui.NextColumn();
						ImGui.SetColumnWidth(1, 80);
						ImGui.Separator();

						float longestFilename = 100;
						foreach (var path_data in contents.dirData)
						{
							FileMetadata md = path_data.Value;
							ImGui.PushStyleColor(ImGuiCol.Text, md.ListingColour());
							if (ImGui.Selectable(path_data.Value.filename + "/", false, ImGuiSelectableFlags.SpanAllColumns))
							{
								CurrentFolder = path_data.Key;
								_currentDirContents.Remove(o);
							}
							if (path_data.Value.namewidth > longestFilename)
								longestFilename = path_data.Value.namewidth;
							ImGui.NextColumn();

							ImGui.Text("");
							ImGui.NextColumn();
							ImGui.Text(path_data.Value.size_str);
							ImGui.NextColumn();
							ImGui.NextColumn();
							ImGui.PopStyleColor();
						}

						foreach (var path_data in contents.fileData)
						{
							EmitFileSelectableEntry(path_data.Key, path_data.Value);
							if (path_data.Value.namewidth > longestFilename)
								longestFilename = path_data.Value.namewidth;
							if (ImGui.IsMouseDoubleClicked(0))
							{
								result = PickerResult.eTrue;
								ImGui.CloseCurrentPopup();
							}
						}

						ImGui.SetColumnWidth(0, longestFilename + 20);
					}
				}
			}
			else
            {
				if (_badDir) ImGui.PopStyleColor();
			}
			ImGui.EndChildFrame();

			if (ImGui.IsAnyMouseDown()) 
			{
				if (!ImGui.IsMouseHoveringRect(ImGui.GetWindowPos(), ImGui.GetWindowPos() + ImGui.GetWindowSize()))
				{
					result = PickerResult.eFalse;
					ImGui.CloseCurrentPopup();
				} 
			}

			if (result != PickerResult.eNoAction && SelectedFile == null) result = PickerResult.eFalse;
			return result;
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


		DirectoryContents GetFileSystemEntries(string fullName, object o)
		{
			DirectoryContents contents = null;

			if (_currentDirContents.TryGetValue(o, out contents))
            {
				if (contents != null)
                {
					if (!contents.recentlyRefreshed()) contents.Refresh();
					return contents;
                }
            }

			_currentDirContents[o] = new DirectoryContents(fullName);
			return _currentDirContents[o];	
		}

	}
}