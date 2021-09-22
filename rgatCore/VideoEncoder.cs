using FFMpegCore;
using FFMpegCore.Enums;
using FFMpegCore.Extend;
using FFMpegCore.Pipes;
using ImGuiNET;
using rgat.Widgets;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace rgat
{
    public class VideoEncoder
    {
        public bool Loaded { get; private set; }
        public bool Initialised { get; private set; }
        public string Error { get; private set; } = "";

        readonly bool _ignoreSignatureError = false;
        readonly bool _signatureError = false;
        readonly System.Drawing.Imaging.ImageCodecInfo[] _imageCodecs;

        public VideoEncoder()
        {

            _imageCodecs = ImageCodecInfo.GetImageEncoders();

        }


        ~VideoEncoder()
        {
        }


        static readonly BinaryWriter stream = null;

        public int CurrentVideoWidth { get; private set; }
        public int CurrentVideoHeight { get; private set; }


        public string CurrentRecordingFile = "";
        ulong _recordedFrameCount = 0;
        public bool Recording => _recording;
        public bool CapturePaused = false;
        bool _recording = false;
        readonly ConcurrentQueue<Bitmap> _bmpQueue = new ConcurrentQueue<Bitmap>();
        public int FrameQueueSize => _bmpQueue.Count;

        CaptureContent _capturedContent = CaptureContent.Invalid;
        public enum CaptureContent { Graph, GraphAndPreviews, Window, Invalid };

        public CaptureContent GetCapturedContent()
        {
            if (_capturedContent == CaptureContent.Invalid)
            {
                string setting = GlobalConfig.Settings.Media.VideoCodec_Content.ToUpper();
                if (setting.Contains("PREVIEW"))
                {
                    _capturedContent = CaptureContent.GraphAndPreviews;
                }
                else if (setting.Contains("GRAPH"))
                {
                    _capturedContent = CaptureContent.Graph;
                }
                else
                {
                    _capturedContent = CaptureContent.Window;
                }
            }
            return _capturedContent;

        }

        public void Load(string dllpath = "")
        {
            if (File.Exists(GlobalConfig.GetSettingPath(CONSTANTS.PathKey.FFmpegPath)))
            {
                Loaded = true;
            }
            else if (DetectFFmpeg(out string? path))
            {
                Loaded = true;
                GlobalConfig.SetBinaryPath(CONSTANTS.PathKey.FFmpegPath, path);
            }
        }

        DateTime _recordingStateChanged = DateTime.MinValue;
        public bool StartRecording()
        {
            System.Diagnostics.Debug.Assert(!_recording);
            _recording = true;
            _recordingStateChanged = DateTime.Now;
            return true;
        }

        public void StopRecording()
        {
            _recordingStateChanged = DateTime.Now;
            _recording = false;
        }


        /// <summary>
        /// How long ago the recording stopped/started in milliseconds
        /// </summary>
        public double RecordingStateChangeTimeAgo => (DateTime.Now - _recordingStateChanged).TotalMilliseconds;

        IEnumerable<IVideoFrame> GetNextFrame()
        {
            while (_recording || _bmpQueue.Count > 0)
            {
                if (_bmpQueue.Any())
                {
                    if (_bmpQueue.Count > 1024)
                    {
                        Logging.RecordLogEvent($"Warning: Recording has amassed {_bmpQueue.Count} frames in backlog, stopping recording");
                        StopRecording();
                    }
                    if (_bmpQueue.TryDequeue(out Bitmap? frame) && frame is not null)
                    {
                        System.Diagnostics.Debug.Assert(frame.Width == CurrentVideoWidth && frame.Height == CurrentVideoHeight, "Can't change frame dimensions during recording");

                        _recordedFrameCount += 1;
                        yield return new BitmapVideoFrameWrapper(frame);
                    }
                }
                Thread.Sleep(15);
            }
            yield break;
        }

        public static string GetCaptureDirectory()
        {
            string result;
            string currentPath = GlobalConfig.GetSettingPath(CONSTANTS.PathKey.MediaCapturePath);
            if (Directory.Exists(currentPath)) return currentPath;


            if (currentPath != null && currentPath.Length > 0)
            {
                try
                {
                    Directory.CreateDirectory(currentPath);
                    return currentPath;
                }
                catch (Exception e)
                {
                    Logging.RecordLogEvent($"Unable to use configured media path {currentPath}: {e.Message}");
                }
            }

            result = GlobalConfig.GetStorageDirectoryPath(GlobalConfig.BaseDirectory, "media");
            if (result != "" && Directory.Exists(result))
            {
                GlobalConfig.SetDirectoryPath(CONSTANTS.PathKey.MediaCapturePath, result);
                return result;
            }

            return Path.GetTempPath();

        }



        public string GenerateVideoFilepath(PlottedGraph graph)
        {
            string storedir = GetCaptureDirectory();
            string targetname, vidname;
            if (graph != null)
            {
                targetname = Path.GetFileNameWithoutExtension(graph.InternalProtoGraph.TraceData.binaryTarg.FilePath);
                vidname = $"rgat_{targetname}_{graph.pid}_{DateTime.Now.ToString("MMdd_HHMMss")}";
            }
            else
            {
                vidname = $"rgat_nograph_{DateTime.Now.ToString("MMdd_HHMMss")}";
            }
            string targetfile = Path.Combine(storedir, $"{vidname}.mp4");
            int attempt = 1;
            while (File.Exists(targetfile))
            {
                targetfile = Path.Combine(storedir, $"{vidname}({attempt++}).mp4");
                if (attempt == 255)
                {
                    Logging.RecordLogEvent("Bizarre error finding place to store media.", filter: Logging.LogFilterType.TextError);
                    StopRecording();
                    return Path.GetRandomFileName();
                }
            }
            return targetfile;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="graph"></param>
        /// <param name="bmp"></param>
        /// <returns></returns>
        public string SaveImage(PlottedGraph graph, Bitmap bmp)
        {
            if (GlobalConfig.Settings.Media.ImageCapture_Format == null || GlobalConfig.Settings.Media.ImageCapture_Format.Length < 2)
            {
                GlobalConfig.Settings.Media.ImageCapture_Format = "PNG";
            }

            //todo this is windows only apparently
            ImageFormat format = ImageFormat.Bmp;
            string extension = ".bmp";
            foreach (var codec in _imageCodecs)
            {
                if (codec is not null &&
                    codec.FilenameExtension is not null &&
                    codec.FormatDescription == GlobalConfig.Settings.Media.ImageCapture_Format)
                {
                    extension = codec.FilenameExtension.Split(';')[0].Split('.')[1];
                    switch (GlobalConfig.Settings.Media.ImageCapture_Format)
                    {
                        case "BMP":
                            format = ImageFormat.Bmp;
                            break;
                        case "PNG":
                            format = ImageFormat.Png;
                            break;
                        case "JPEG":
                            format = ImageFormat.Jpeg;
                            break;
                        case "TIFF":
                            format = ImageFormat.Tiff;
                            break;
                        case "GIF":
                            format = ImageFormat.Gif;
                            break;
                        default:
                            Logging.RecordError("Unhandled image format: " + GlobalConfig.Settings.Media.ImageCapture_Format);
                            return "bad format";
                    }
                }
            }

            string storedir = GetCaptureDirectory();
            string vidname;
            if (graph == null)
            {
                vidname = $"rgat_NoGraph_{DateTime.Now.ToString("MMdd_HHMMss")}";
            }
            else
            {
                string targetname = Path.GetFileNameWithoutExtension(graph.InternalProtoGraph.TraceData.binaryTarg.FilePath);
                vidname = $"rgat_{targetname}_{graph.pid}_{DateTime.Now.ToString("MMdd_HHMMss")}";
            }
            string targetfile = Path.Combine(storedir, $"{vidname}.{extension}");
            int attempt = 1;
            while (File.Exists(targetfile))
            {
                targetfile = Path.Combine(storedir, $"{vidname}({attempt++}).{extension}");
                if (attempt == 255)
                {
                    Logging.RecordLogEvent("Bizarre error finding place to store iamge.", filter: Logging.LogFilterType.TextError);
                }
            }

            try
            {
                bmp.Save(targetfile, format: format);
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Error saving image {targetfile} as format {format}: {e.Message}");
            }
            return targetfile;
        }


        Speed GetVideoSpeed()
        {
            Speed result;
            try
            {
                result = (Speed)Enum.Parse(typeof(Speed), GlobalConfig.Settings.Media.VideoCodec_Speed, ignoreCase: true);
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Unable to parse video speed setting '{GlobalConfig.Settings.Media.VideoCodec_Speed}' into a speed preset: {e.Message}");
                result = Speed.Medium;
                GlobalConfig.Settings.Media.VideoCodec_Speed = GlobalConfig.Settings.Media.VideoCodec_Speed.ToString();
            }
            return result;
        }


        async public void Go(PlottedGraph graph)
        {
            if (!File.Exists(GlobalConfig.GetSettingPath(CONSTANTS.PathKey.FFmpegPath)))
            {
                Logging.RecordLogEvent($"Unable to start recording: Path to ffmpeg.exe not configured");
                StopRecording();
                Loaded = false;
                return;
            }

            try
            {
                GlobalFFOptions.Configure(new FFOptions { BinaryFolder = Path.GetDirectoryName(GlobalConfig.GetSettingPath(CONSTANTS.PathKey.FFmpegPath)) });
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Unable to start recording: Exception '{e.Message}' configuring recorder");
                StopRecording();
                Loaded = false;
                return;
            }


            CurrentRecordingFile = GenerateVideoFilepath(graph);
            _recordedFrameCount = 0;
            Logging.RecordLogEvent("Recording video to " + CurrentRecordingFile);
            var videoFramesSource = new RawVideoPipeSource(GetNextFrame());
            try
            {
                //https://trac.ffmpeg.org/wiki/Encode/H.264
                await FFMpegArguments
                    .FromPipeInput(videoFramesSource)
                    .OutputToFile(CurrentRecordingFile, false, opt => opt
                        .WithFramerate(GlobalConfig.Settings.Media.VideoCodec_FPS)
                        .WithConstantRateFactor(28 - GlobalConfig.Settings.Media.VideoCodec_Quality)
                        .WithSpeedPreset(GetVideoSpeed())
                        .WithVideoCodec(VideoCodec.LibX264)
                        )
                    .ProcessAsynchronously();
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent("FFMpeg Record Error: " + e.Message, Logging.LogFilterType.TextError);
                Console.WriteLine("-----------FFMPEG EXCEPTION-------------");
                Console.WriteLine(e);
                Console.WriteLine("-----------FFMPEG EXCEPTION-------------");
            }


            Initialised = false;
            StopRecording();
            CapturePaused = false;
            _bmpQueue.Clear();

            Logging.RecordLogEvent($"Recorded {_recordedFrameCount} x {CurrentVideoWidth}*{CurrentVideoHeight} frames of video to " + CurrentRecordingFile);
            CurrentRecordingFile = "";
            _capturedContent = CaptureContent.Invalid;
        }


        public void QueueFrame(Bitmap frame, PlottedGraph graph)
        {
            if (frame != null && _recording)
            {
                if (!Initialised)
                {
                    CurrentVideoWidth = frame.Width;
                    CurrentVideoHeight = frame.Height;

                    Task.Run(() => { Go(graph); });
                    Initialised = true;
                }
                _bmpQueue.Enqueue(frame);

            }
        }



        public void DrawSettingsPane()
        {
            if (File.Exists(GlobalConfig.GetSettingPath(CONSTANTS.PathKey.FFmpegPath)))
            {
                DrawHaveLibSettingsPane();
            }
            else
            {
                if (DetectFFmpeg(out string? path))
                {
                    Loaded = true;
                    GlobalConfig.SetBinaryPath(CONSTANTS.PathKey.FFmpegPath, path);
                    DrawHaveLibSettingsPane();
                }
                else
                {
                    DrawNoLibSettingsPane();
                }
            }
        }


        DateTime _lastCheck = DateTime.MinValue;
        bool DetectFFmpeg(out string? path)
        {
            path = "";
            if (DateTime.Now < _lastCheck.AddSeconds(5)) return false;
            _lastCheck = DateTime.Now;

            string extension = "";
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                extension = ".exe";

            string[] matches = Directory.GetFiles(AppContext.BaseDirectory, "ffmpeg" + extension, SearchOption.AllDirectories);

            foreach (string match in matches)
            {
                string candidate = match;
                if (File.Exists(candidate))
                {
                    GlobalConfig.SetBinaryPath(CONSTANTS.PathKey.FFmpegPath, candidate);
                    return true;
                }
            }
            return false;
        }


        void DrawNoLibSettingsPane()
        {

            ImGui.Text("Use of video capture requires the FFmpeg.exe executable, which has to be downloaded seperately");

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ImGui.TextWrapped($"Go to https://ffmpeg.org/download.html to find downloads and place ffmpeg.exe in the relevant rgat directory or configure it in the Settings->Paths pane");
            }
            else
            {
                ImGui.TextWrapped($"Go to https://ffmpeg.org/download.html to find downloads and place ffmpeg in the relevant rgat directory or configure it in the Settings->Paths pane");
            }
            //todo downloader
        }


        void DrawHaveLibSettingsPane()
        {

            if (Error.Length > 0)
            {
                ImGui.Text(Error);
                return;
            }

            //settings
            if (ImGui.BeginTable("##VideoSettingsTable", 2, ImGuiTableFlags.Borders))
            {
                ImGui.TableNextRow();
                ImGui.TableNextColumn();

                ImguiUtils.DrawHorizCenteredText("Video Settings");

                ImGui.SetNextItemWidth(180);
                if (ImGui.BeginCombo("Quality", GlobalConfig.Settings.Media.VideoCodec_Quality.ToString()))
                {
                    foreach (int CRF_Modifier in Enumerable.Range(0, 11 + 1))
                    {
                        if (ImGui.Selectable(CRF_Modifier.ToString()))
                        {
                            GlobalConfig.Settings.Media.VideoCodec_Quality = CRF_Modifier;
                        }
                    }
                    ImGui.EndCombo();
                }
                SmallWidgets.MouseoverText("0 is bad quality, 11 is near lossless");

                ImGui.SetNextItemWidth(180);
                if (ImGui.BeginCombo("Compression Speed", GlobalConfig.Settings.Media.VideoCodec_Speed))
                {
                    foreach (var speed in Enum.GetNames(typeof(Speed)).Select(x => x.ToString()))
                    {
                        if (ImGui.Selectable(speed))
                        {
                            GlobalConfig.Settings.Media.VideoCodec_Speed = speed;
                        }
                    }
                    ImGui.EndCombo();
                }
                SmallWidgets.MouseoverText("Slower speed yields smaller video file sizes. Increase if you have performance issues");

                ImGui.SetNextItemWidth(180);
                double min = 0, max = 500;
                double current = GlobalConfig.Settings.Media.VideoCodec_FPS;
                if (ImguiUtils.DragDouble("Framerate", ref current, 0.25f, ref min, ref max))
                {
                    GlobalConfig.Settings.Media.VideoCodec_FPS = current;
                }
                SmallWidgets.MouseoverText("Number of frames to record per second of video. Increase to increase quality and file size");


                ImGui.SetNextItemWidth(180);
                if (ImGui.BeginCombo("Recorded Content", GlobalConfig.Settings.Media.VideoCodec_Content))
                {
                    foreach (var content in new string[] { "Graph", "Graph and previews", "Whole window" })
                    {
                        if (ImGui.Selectable(content))
                        {
                            GlobalConfig.Settings.Media.VideoCodec_Content = content;
                        }
                    }
                    ImGui.EndCombo();
                }
                SmallWidgets.MouseoverText("Slower speed yields smaller video file sizes. Increase if you have performance issues");




                ImGui.TableNextColumn();

                ImguiUtils.DrawHorizCenteredText("Image Settings");

                if (ImGui.BeginCombo("Image Format", GlobalConfig.Settings.Media.ImageCapture_Format))
                {
                    foreach (var codec in _imageCodecs)
                    {
                        if (ImGui.Selectable(codec.FormatDescription))
                        {
                            GlobalConfig.Settings.Media.ImageCapture_Format = codec.FormatDescription;
                        }
                    }

                    ImGui.EndCombo();
                }

                ImGui.EndTable();
            }
        }

    }
}
