using FFMpegCore;
using FFMpegCore.Arguments;
using FFMpegCore.Enums;
using FFMpegCore.Extend;
using FFMpegCore.Pipes;
using ImGuiNET;
using rgat.Properties;
using rgat.Widgets;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace rgat
{
    public class VideoEncoder
    {
        public bool Loaded { get; private set; }
        public bool Initialised { get; private set; }
        public string Error { get; private set; } = "";

        bool _ignoreSignatureError = false;
        bool _signatureError = false;

        System.Drawing.Imaging.ImageCodecInfo[] _imageCodecs;

        public VideoEncoder()
        {

            _imageCodecs = ImageCodecInfo.GetImageEncoders();

        }


        ~VideoEncoder()
        {
        }


        static BinaryWriter stream = null;

        public int CurrentVideoWidth { get; private set; }
        public int CurrentVideoHeight { get; private set; }


        public string CurrentRecordingFile = "";
        ulong _recordedFrameCount = 0;
        public bool Recording => _recording;
        public bool CapturePaused = false;
        bool _recording = false;
        ConcurrentQueue<Bitmap> _bmpQueue = new ConcurrentQueue<Bitmap>();
        public int FrameQueueSize => _bmpQueue.Count;

        CaptureContent _capturedContent = CaptureContent.Invalid;
        public enum CaptureContent { Graph, GraphAndPreviews, Window, Invalid };

        public CaptureContent GetCapturedContent()
        {
            if (_capturedContent == CaptureContent.Invalid)
            {
                string setting = GlobalConfig.VideoCodec_Content.ToUpper();
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
            if (File.Exists(GlobalConfig.FFmpegPath))
            {
                Loaded = true;
            }
            else if (DetectFFmpeg(out string path))
            {
                Loaded = true;
                GlobalConfig.FFmpegPath = path;
            }
        }

        public bool StartRecording()
        {
            System.Diagnostics.Debug.Assert(!_recording);
            _recording = true;
            return true;
        }


        IEnumerable<IVideoFrame> GetNextFrame()
        {
            while (_recording || _bmpQueue.Count > 0)
            {
                if (_bmpQueue.Any())
                {
                    if (_bmpQueue.Count > 1024)
                    {
                        Logging.RecordLogEvent($"Warning: Recording has amassed {_bmpQueue.Count} frames in backlog, stopping recording");
                        _recording = false;
                    }
                    if (_bmpQueue.TryDequeue(out Bitmap frame))
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

        public string GetCaptureDirectory()
        {
            string result;
            if (Directory.Exists(GlobalConfig.MediaCapturePath)) return GlobalConfig.MediaCapturePath;


            if (GlobalConfig.MediaCapturePath != null && GlobalConfig.MediaCapturePath.Length > 0)
            {
                try
                {
                    Directory.CreateDirectory(GlobalConfig.MediaCapturePath);
                    return GlobalConfig.MediaCapturePath;
                }
                catch (Exception e)
                {
                    Logging.RecordLogEvent($"Unable to use configured media path {GlobalConfig.MediaCapturePath}: {e.Message}");
                }
            }
            result = GlobalConfig.GetStorageDirectoryPath("media");
            if (result != "")
            {
                GlobalConfig.SetDirectoryPath("MediaCapturePath", result, true);
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
                    _recording = false;
                    return Path.GetRandomFileName();
                }
            }
            return targetfile;
        }

        public void TakeScreenshot(PlottedGraph graph, Bitmap bmp)
        {
            if (GlobalConfig.ImageCapture_Format == null || GlobalConfig.ImageCapture_Format.Length < 2)
                GlobalConfig.AddUpdateAppSettings("ImageCapture_Format", "PNG");

            ImageFormat format = ImageFormat.Bmp;
            string extension = ".bmp";
            foreach (var codec in _imageCodecs)
            {
                if (codec.FormatDescription == GlobalConfig.ImageCapture_Format)
                {
                    extension = codec.FilenameExtension.Split(';')[0].Split('.')[1];
                    switch (GlobalConfig.ImageCapture_Format)
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
                            Logging.RecordLogEvent("Unhandled image format: " + GlobalConfig.ImageCapture_Format);
                            return;
                            break;
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
        }


        Speed GetVideoSpeed()
        {
            Speed result;
            try
            {
                result = (Speed)Enum.Parse(typeof(Speed), GlobalConfig.VideoCodec_Speed, ignoreCase: true);
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Unable to parse video speed setting '{GlobalConfig.VideoCodec_Speed}' into a speed preset: {e.Message}");
                result = Speed.Medium;
                GlobalConfig.VideoCodec_Speed = GlobalConfig.VideoCodec_Speed.ToString();
                GlobalConfig.AddUpdateAppSettings("VideoCodec_Speed", GlobalConfig.VideoCodec_Speed);
            }
            return result;
        }


        async public void Go(PlottedGraph graph)
        {
            if (GlobalConfig.FFmpegPath == null ||
                GlobalConfig.FFmpegPath == "" ||
                !File.Exists(GlobalConfig.FFmpegPath))
            {
                Logging.RecordLogEvent($"Unable to start recording: FFmpeg path not configured");
                _recording = false;
                Loaded = false;
                return;
            }

            try
            {
                GlobalFFOptions.Configure(new FFOptions { BinaryFolder = Path.GetDirectoryName(GlobalConfig.FFmpegPath) });
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Unable to start recording: Exception '{e.Message}' configuring recorder");
                _recording = false;
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
                        .WithFramerate(GlobalConfig.VideoCodec_FPS)
                        .WithConstantRateFactor(28 - GlobalConfig.VideoCodec_Quality)
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
            _recording = false;
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

        public void Done()
        {
            _recording = false;
        }


        public void DrawSettingsPane()
        {
            if (File.Exists(GlobalConfig.FFmpegPath))
            {
                DrawHaveLibSettingsPane();
            }
            else
            {
                if (DetectFFmpeg(out string path))
                {
                    Loaded = true;
                    GlobalConfig.FFmpegPath = path;
                    DrawHaveLibSettingsPane();
                }
                else
                {
                    DrawNoLibSettingsPane();
                }
            }
        }


        DateTime _lastCheck = DateTime.MinValue;
        bool DetectFFmpeg(out string path)
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
                    if (GlobalConfig.SetBinaryPath("FFmpegPath", candidate, save: true))
                    {
                        path = candidate;
                        return true;
                    }
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
                if (ImGui.BeginCombo("Quality", GlobalConfig.VideoCodec_Quality.ToString()))
                {
                    foreach (int CRF_Modifier in Enumerable.Range(0, 11 + 1))
                    {
                        if (ImGui.Selectable(CRF_Modifier.ToString()))
                        {
                            GlobalConfig.VideoCodec_Quality = CRF_Modifier;
                            GlobalConfig.AddUpdateAppSettings("VideoCodec_Quality", CRF_Modifier.ToString());
                        }
                    }
                    ImGui.EndCombo();
                }
                SmallWidgets.MouseoverText("0 is bad quality, 11 is near lossless");

                ImGui.SetNextItemWidth(180);
                if (ImGui.BeginCombo("Compression Speed", GlobalConfig.VideoCodec_Speed))
                {
                    foreach (var speed in Enum.GetNames(typeof(Speed)).Select(x => x.ToString()))
                    {
                        if (ImGui.Selectable(speed))
                        {
                            GlobalConfig.VideoCodec_Speed = speed;
                            GlobalConfig.AddUpdateAppSettings("VideoCodec_Speed", speed);
                        }
                    }
                    ImGui.EndCombo();
                }
                SmallWidgets.MouseoverText("Slower speed yields smaller video file sizes. Increase if you have performance issues");

                ImGui.SetNextItemWidth(180);
                double min = 0, max = 500;
                if (ImguiUtils.DragDouble("Framerate", ref GlobalConfig.VideoCodec_FPS, 0.25f, ref min, ref max))
                {
                    GlobalConfig.AddUpdateAppSettings("VideoCodec_FPS", GlobalConfig.VideoCodec_FPS.ToString());
                }
                SmallWidgets.MouseoverText("Number of frames to record per second of video. Increase to increase quality and file size");


                ImGui.SetNextItemWidth(180);
                if (ImGui.BeginCombo("Recorded Content", GlobalConfig.VideoCodec_Content))
                {
                    foreach (var content in new string[] { "Graph", "Graph and previews", "Whole window" })
                    {
                        if (ImGui.Selectable(content))
                        {
                            GlobalConfig.VideoCodec_Content = content;
                            GlobalConfig.AddUpdateAppSettings("VideoCodec_Content", content);
                        }
                    }
                    ImGui.EndCombo();
                }
                SmallWidgets.MouseoverText("Slower speed yields smaller video file sizes. Increase if you have performance issues");




                ImGui.TableNextColumn();

                ImguiUtils.DrawHorizCenteredText("Image Settings");

                if (ImGui.BeginCombo("Image Format", GlobalConfig.ImageCapture_Format))
                {
                    foreach (var codec in _imageCodecs)
                    {
                        if (ImGui.Selectable(codec.FormatDescription))
                        {
                            GlobalConfig.ImageCapture_Format = codec.FormatDescription;
                            GlobalConfig.AddUpdateAppSettings("ImageCapture_Format", codec.FormatDescription);
                        }
                    }

                    ImGui.EndCombo();
                }

                ImGui.EndTable();
            }
        }

    }
}
