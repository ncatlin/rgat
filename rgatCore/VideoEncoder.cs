using FFMpegCore;
using FFMpegCore.Arguments;
using FFMpegCore.Enums;
using FFMpegCore.Extend;
using FFMpegCore.Pipes;
using ImGuiNET;
using rgatCore.Properties;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace rgatCore
{
    public class VideoEncoder
    {
        public bool Loaded { get; private set; }
        public bool Initialised { get; private set; }
        public string Error { get; private set; } = "";

        bool _ignoreSignatureError = false;
        bool _signatureError = false;

        public VideoEncoder()
        {


        }


        ~VideoEncoder()
        {
        }

        public void Load(string dllpath="")
        {
            if (File.Exists(GlobalConfig.VideoEncoderFFmpegPath))
            {
                Loaded = true;
            }
            else if (DetectFFmpeg(out string path))
            {
                Loaded = true;
                GlobalConfig.VideoEncoderFFmpegPath = path;
            }
        }

        static BinaryWriter stream = null;

        public int CurrentVideoWidth { get; private set; }
        public int CurrentVideoHeight { get; private set; }


        public bool StartRecording()
        {
            System.Diagnostics.Debug.Assert(!_recording);
            _recording = true;
            return true;
        }


        public bool Recording => _recording;
        public bool _recording = false;
        ConcurrentQueue<Bitmap> _bmpQueue = new ConcurrentQueue<Bitmap>();

        IEnumerable<IVideoFrame> CreateFrames()
        {
            while (_recording)
            {
                if (_bmpQueue.Any())
                {
                    if (_bmpQueue.TryDequeue(out Bitmap frame))
                    {
                        System.Diagnostics.Debug.Assert(frame.Width == CurrentVideoWidth && frame.Height == CurrentVideoHeight, "Can't change frame dimensions during recording");
                        yield return new BitmapVideoFrameWrapper(frame);
                    }
                }
                Thread.Sleep(15);
            }
            yield break;
        }


        async public void Go()
        {
            GlobalFFOptions.Configure(new FFOptions { BinaryFolder = @"C:\Users\nia\Desktop\rgatstuff\ffmpeg" });
            string outfile = Path.ChangeExtension(Path.GetTempFileName(), VideoType.Mp4.Extension);

            Console.WriteLine("Writing to " + outfile);
            var videoFramesSource = new RawVideoPipeSource(CreateFrames());
            try
            {
                await FFMpegArguments
                    .FromPipeInput(videoFramesSource)
                    .OutputToFile(outfile, false, opt => opt
                        .WithVideoCodec(VideoCodec.LibX264)

                        )

                    .ProcessAsynchronously();
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent("FFMpeg Record Error: " + e.Message);
                Console.WriteLine("-----------FFMPEG EXCEPTION-------------");
                Console.WriteLine(e);
                Console.WriteLine("-----------FFMPEG EXCEPTION-------------");
            }
            Initialised = false;
            _recording = false;
            _bmpQueue.Clear();
            Console.WriteLine("Done " + outfile);
        }



        public void QueueFrames(List<Bitmap> frames)
        {
            if (frames.Any())
            {
                if (!Initialised)
                {
                    CurrentVideoWidth = frames[0].Width;
                    CurrentVideoHeight = frames[0].Height;

                    Task.Run(() => { Go(); });
                    Initialised = true;
                }
                foreach (Bitmap frame in frames)
                {
                    _bmpQueue.Enqueue(frame);
                }
            }
        }

        public void QueueFrame(Bitmap frame)
        {
            if (frame != null)
            {
                if (!Initialised)
                {
                    CurrentVideoWidth = frame.Width;
                    CurrentVideoHeight = frame.Height;

                    Task.Run(() => { Go(); });
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
            if (File.Exists(GlobalConfig.VideoEncoderFFmpegPath))
            {
                DrawHaveLibSettingsPane();
            }
            else
            {
                if (DetectFFmpeg(out string path))
                {
                    Loaded = true;
                    GlobalConfig.VideoEncoderFFmpegPath = path;
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
                    if (GlobalConfig.SetBinaryPath("FFmpeg", candidate, save: true))
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
                ImGui.Text($"Go to https://ffmpeg.org/download.html to find downloads and place ffmpeg.exe in the relevant rgat directory or configure it in the Settings->Paths pane");
            }
            else
            {
                ImGui.Text($"Go to https://ffmpeg.org/download.html to find downloads and place ffmpeg in the relevant rgat directory or configure it in the Settings->Paths pane");
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

            bool settingChange = false;
            if (ImGui.InputInt("Frame Width", ref GlobalConfig.VideoCodec_Width)) settingChange = true;
            if (ImGui.InputInt("Frame Height", ref GlobalConfig.VideoCodec_Height)) settingChange = true;
            if (ImGui.InputInt("Target Bitrate", ref GlobalConfig.VideoCodec_Bitrate)) settingChange = true;
            if (ImGui.InputInt("Frame Per Second", ref GlobalConfig.VideoCodec_FPS)) settingChange = true;
            if (ImGui.InputInt("Key Frame Interval (Seconds)", ref GlobalConfig.VideoCodec_FrameInterval)) settingChange = true;

            if (settingChange)
            {
                GlobalConfig.AddUpdateAppSettings("VideoCodec_Height", GlobalConfig.VideoCodec_Width.ToString());
                GlobalConfig.AddUpdateAppSettings("VideoCodec_Width", GlobalConfig.VideoCodec_Height.ToString());
                GlobalConfig.AddUpdateAppSettings("VideoCodec_Bitrate", GlobalConfig.VideoCodec_Bitrate.ToString());
                GlobalConfig.AddUpdateAppSettings("VideoCodec_FPS", GlobalConfig.VideoCodec_FPS.ToString());
                GlobalConfig.AddUpdateAppSettings("VideoCodec_FrameInterval", GlobalConfig.VideoCodec_FrameInterval.ToString());
            }
        }

    }
}
