using ImGuiNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace rgatCore
{
    public class VideoEncoder
    {
        OpenH264Lib.Encoder _encoder;
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

        public bool Load(string dllpath)
        {
            GlobalConfig.CheckSignatureError(dllpath, out string error, out bool timeWarning);
            if (error.Length > 0 && !_ignoreSignatureError)
            {
                Error = error;
                _signatureError = true;
                return false;
            }

            try
            {
                _encoder = new OpenH264Lib.Encoder(GlobalConfig.VideoEncodeCiscoLibPath);
            }
            catch (Exception e)
            {
                Error = $"Failed to load OpenH264Lib {dllpath}: {e.Message}";
                Logging.RecordLogEvent(Error, Logging.LogFilterType.TextError);
                return false;
            }

            Loaded = true;
            return true;
        }

        int _frameWidth = 640;
        int _frameHeight = 640;
        int _targetBitRate = 5000 * 1000;
        int _fps = 10;
        int _frameIntervalSeconds = 2;

        /// <summary>
        /// Set H264 encoder settings
        /// </summary>
        /// <param name="width">Frame width in pixels</param>
        /// <param name="height">Frame height in pixels</param>
        /// <param name="bitrate">Target bitrate</param>
        /// <param name="fps">Frames Per Second</param>
        /// <param name="interval">Key frame interval (seconds)</param>
        public void SetSettings(int width, int height, int bitrate, int fps, int interval)
        {
            _frameWidth = width;
            _frameHeight = height;
            _targetBitRate = bitrate;
            _fps = fps;
            _frameIntervalSeconds = interval;
        }

        bool Initialise()
        {
            SetSettings(GlobalConfig.VideoCodec_Width, GlobalConfig.VideoCodec_Height, 
                GlobalConfig.VideoCodec_Bitrate, GlobalConfig.VideoCodec_FPS, 
                GlobalConfig.VideoCodec_FrameInterval);

            try
            {
                _encoder.Setup(_frameWidth, _frameHeight, _targetBitRate, _fps, _frameIntervalSeconds, (data, length, frameType) =>
                {
                    // called when each frame encoded.
                    Console.WriteLine("Encord {0} bytes, frameType:{1}", length, frameType);

                });
            }
            catch (Exception e)
            {
                Error = $"Failed to initialise OpenH264Lib: {e.Message}";
                Logging.RecordLogEvent(Error, Logging.LogFilterType.TextError);
                return false;
            }

            Initialised = true;
            return true;
        }

        public void DrawSettingsPane()
        {
            if (File.Exists(GlobalConfig.VideoEncodeCiscoLibPath))
            {
                DrawHaveLibSettingsPane();
            }
            else
            {
                if (DetectLibrary(out string path))
                {
                    GlobalConfig.VideoEncodeCiscoLibPath = path;
                    DrawHaveLibSettingsPane();
                }
                else
                {
                    DrawNoLibSettingsPane();
                }
            }
        }


        DateTime _lastCheck = DateTime.MinValue;
        bool DetectLibrary(out string path)
        {
            path = "";
            if (DateTime.Now < _lastCheck.AddSeconds(5)) return false;
            _lastCheck = DateTime.Now;

            string extension = "";

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                extension = ".dll";
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                extension = ".so";
                //todo - going to need to look at .sig file
            }
            else
                return false;

            string[] matches = Directory.GetFiles(AppContext.BaseDirectory, "openh264*" + extension, SearchOption.AllDirectories);

            foreach (string match in matches)
            {
                string candidate = match;
                if (File.Exists(candidate))
                {
                    if (GlobalConfig.SetBinaryPath("VideoCodec", candidate, save: true))
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

            ImGui.Text("Use of video capture requires the OpenH264 codec library from Cisco, which has to be downloaded seperately");
            ImGui.Text($"Download it from https://github.com/cisco/openh264/releases and place it in the rgat directory or configure it in the Settings->Paths pane");

            //todo downloader
        }


        void DrawHaveLibSettingsPane()
        {

            if (Error.Length > 0)
            {
                if (_signatureError)
                {
                    if (!_ignoreSignatureError)
                    {
                        ImGui.Text($"Could not validate the Codec signature");
                        ImGui.Indent(7);
                        ImGui.Text(GlobalConfig.VideoEncodeCiscoLibPath);
                        ImGui.Text(Error);

                        ImGui.SetCursorPosX((ImGui.GetWindowContentRegionMax().X / 2 - 100));
                        ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour));
                        if (ImGui.Button("I don't care, load it anyway", new System.Numerics.Vector2(200, 40)))
                        {
                            _ignoreSignatureError = true;
                        }
                        ImGui.PopStyleColor();
                        ImGui.Indent(0);

                        return;
                    }
                }
                else
                {
                    ImGui.Text(Error);
                    return;
                }
            }

            if (!Loaded)
            {
                ImGui.Text("Loading");
                Load(GlobalConfig.VideoEncodeCiscoLibPath);
                return;
            }


            if (!Initialised)
            {
                ImGui.Text("Initialising");
                Initialise();
                return;
            }

            bool val = GlobalConfig.VideoEncodeLoadOnStart;
            if(ImGui.Checkbox("Load on start", ref val))
            {
                GlobalConfig.VideoEncodeLoadOnStart = val;
                GlobalConfig.AddUpdateAppSettings("LoadVideoCodecOnStart", val ? "True" : "False");
            }


            //todo check update

            //settings

            bool settingChange = false;
            if (ImGui.InputInt("Frame Width", ref _frameWidth)) settingChange = true;
            if (ImGui.InputInt("Frame Height", ref _frameHeight)) settingChange = true;
            if (ImGui.InputInt("Target Bitrate", ref _targetBitRate)) settingChange = true;
            if (ImGui.InputInt("Frame Per Second", ref _fps)) settingChange = true;
            if (ImGui.InputInt("Key Frame Interval (Seconds)", ref _frameIntervalSeconds)) settingChange = true;

            if (settingChange)
            {
                GlobalConfig.AddUpdateAppSettings("VideoCodec_Height", _frameWidth.ToString());
                GlobalConfig.AddUpdateAppSettings("VideoCodec_Width", _frameHeight.ToString());
                GlobalConfig.AddUpdateAppSettings("VideoCodec_Bitrate", _targetBitRate.ToString());
                GlobalConfig.AddUpdateAppSettings("VideoCodec_FPS", _fps.ToString());
                GlobalConfig.AddUpdateAppSettings("VideoCodec_FrameInterval", _frameIntervalSeconds.ToString());
            }
        }

    }
}
