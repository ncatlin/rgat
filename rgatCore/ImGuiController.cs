using rgat;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Reflection;
using System.Runtime.CompilerServices;
using Veldrid;
using Veldrid.ImageSharp;

namespace ImGuiNET
{
    /// <summary>
    /// A modified version of Veldrid.ImGui's ImGuiRenderer.
    /// Manages input for ImGui and handles rendering ImGui's DrawLists with Veldrid.
    /// </summary>
    public class ImGuiController : IDisposable
    {
        private GraphicsDevice _gd;
        private bool _frameBegun;

        // Veldrid objects
        private DeviceBuffer? _vertexBuffer, _indexBuffer, _projMatrixBuffer;
        public Texture? _fontTexture;
        /// <summary>
        /// Shader accessible font texture
        /// </summary>
        public TextureView? _fontTextureView;
        private Shader? _vertexShader, _fragmentShader;
        private ResourceLayout? _layout, _textureLayout;
        private Pipeline? _pipeline;
        private ResourceSet? _mainResourceSet, _fontTextureResourceSet;
        private readonly Dictionary<string, Texture> _imageTextures = new Dictionary<string, Texture>();
        private readonly Dictionary<string, TextureView> _textureViews = new Dictionary<string, TextureView>();
        private Texture? _imagesTextureArray;

        private readonly IntPtr _fontAtlasID = (IntPtr)1;
        private bool _controlDown, _shiftDown, _altDown, _winKeyDown;

        /// <summary>
        /// Width of the main window
        /// </summary>
        public int WindowWidth;

        /// <summary>
        /// Height of the main window
        /// </summary>
        public int WindowHeight;
        private Vector2 _scaleFactor = Vector2.One;

        // Image trackers
        private readonly Dictionary<TextureView, ResourceSetInfo> _setsByView = new();
        private readonly Dictionary<Texture, TextureView> _autoViewsByTexture = new();
        private readonly Dictionary<IntPtr, ResourceSetInfo> _viewsById = new();
        private readonly List<IDisposable> _ownedResources = new List<IDisposable>();
        private int _lastAssignedID = 100;

        //private ImFontPtr _customFont = null;
        /// <summary>
        /// The main loaded font
        /// </summary>
        private ImFontPtr? _unicodeFont = null;

        /// <summary>
        /// The main loaded font
        /// </summary>
        public ImFontPtr UnicodeFont
        {
            get
            {
                return _unicodeFont.HasValue ? _unicodeFont.Value : _originalFont!.Value;
            }
            private set { _unicodeFont = value; }
        }



        private ImFontPtr? _splashButtonFont = null;
        /// <summary>
        /// The original imGui font
        /// </summary>
        public ImFontPtr? _originalFont = null;
        private int _dialogsOpen = 0;

        /// <summary>
        /// Is a dialog open
        /// </summary>
        public bool DialogOpen => _dialogsOpen > 0;

        /// <summary>
        /// Quickmenu issues sometimes leave this as 1 with all dialogs closed
        /// </summary>
        public void HackyResetDialogsCount() => _dialogsOpen = 0;

        //todo this is an awful system, maybe make it an event
        /// <summary>
        /// A dialog opened or closed
        /// </summary>
        /// <param name="opened">true if opened, false if closed</param>
        public void DialogChange(bool opened)
        {

            Debug.Assert(_dialogsOpen >= 0);
            if (_dialogsOpen < 0) _dialogsOpen = 0;
            if (_dialogsOpen is 0 && opened is false) return; //bug, quickmenu

            _dialogsOpen += opened ? 1 : -1;
        }

        /// <summary>
        /// Is the demo window open
        /// </summary>
        public bool ShowDemoWindow = false;

        /// <summary>
        /// A reference to a GPU graphics device for general use
        /// </summary>
        public GraphicsDevice GraphicsDevice => _gd;



        /// <summary>
        /// A general UI management class
        /// </summary>
        /// <param name="gd">GraphicsDevice for rendering</param>
        /// <param name="outputDescription">Framebuffer details</param>
        /// <param name="width">window width</param>
        /// <param name="height">window height</param>
        public unsafe ImGuiController(GraphicsDevice gd, OutputDescription outputDescription, int width, int height)
        {
            _gd = gd;
            WindowWidth = width;
            WindowHeight = height;

            IntPtr context = ImGui.CreateContext();
            ImGui.SetCurrentContext(context);

            SetKeyMappings();

            LoadImages();

            SetPerFrameImGuiData(1f / 60f);

            Logging.RecordLogEvent("Loading fonts", Logging.LogFilterType.Debug);
            var fonts = ImGui.GetIO().Fonts;


            //should be fixed now
            /*
            Debug.Assert(_unicodeFont.GetCharAdvance('a') == _unicodeFont.FindGlyph('a').AdvanceX,
                    "The ImGui.NET used is not handling bitfields properly, preventing fonts " +
                    "from rendering correctly in the graph. https://github.com/mellinoe/ImGui.NET/issues/206");
            */

            //OldBuildFonts();
            BuildFonts(false);
            _originalFont = fonts.AddFontDefault();
            CreateDeviceResources(gd, outputDescription);
            RecreateFontDeviceTexture(gd);

            Logging.RecordLogEvent("Done Loading fonts", Logging.LogFilterType.Debug);
        }


        unsafe ImFontConfigPtr CreateNewFontConfig()
        {
            ImFontConfigPtr fontConfig = ImGuiNative.ImFontConfig_ImFontConfig();
            fontConfig.MergeMode = false;
            fontConfig.FontDataOwnedByAtlas = false;
            fontConfig.OversampleH = 2;
            fontConfig.PixelSnapH = true;
            fontConfig.OversampleV = 1;
            fontConfig.GlyphOffset = new Vector2(0, 0);
            fontConfig.GlyphMaxAdvanceX = float.MaxValue;
            fontConfig.RasterizerMultiply = 1f;
            return fontConfig;
        }


        byte[]? notoFontBytes;

        int take = 0;

        /// <summary>
        /// Load the fonts
        /// </summary>
        public unsafe void BuildFonts(bool chooseGlyphsFromConfig)
        {
            take++;

            ImGuiIOPtr io = ImGui.GetIO();
            var fonts = io.Fonts;
            fonts.Clear();

            _originalFont = fonts.AddFontDefault();

            Logging.RecordLogEvent($"Loading Unicode fonts", Logging.LogFilterType.Debug);
            ImFontGlyphRangesBuilderPtr builder = new ImFontGlyphRangesBuilderPtr(ImGuiNative.ImFontGlyphRangesBuilder_ImFontGlyphRangesBuilder());

            builder.AddRanges(fonts.GetGlyphRangesDefault());
            builder.BuildRanges(out ImVector basicRanges);

            if (chooseGlyphsFromConfig)
            {
                AddConfiguredGlyphRanges(builder);
            }

            builder.BuildRanges(out ImVector fullRanges);

            notoFontBytes = global::rgat.Properties.Resources.NotoSansSC_Regular;
            if (notoFontBytes == null)
            {
                Logging.RecordError($"No font resouce: \"NotoSansSC_Regular\"");
                return;
            }

            fixed (byte* notoPtr = notoFontBytes)
            {
                // The order of adding is important here due to merging
                ImFontConfigPtr fontConfig = CreateNewFontConfig();
                ImFontPtr splashFont = fonts.AddFontFromMemoryTTF((IntPtr)notoPtr, notoFontBytes.Length, 40, fontConfig, basicRanges.Data);
                _fontNameByIndex.Add("NotoSansSC_Regular_40");

                fontConfig = CreateNewFontConfig();
                ImFontPtr unicodeFont = fonts.AddFontFromMemoryTTF((IntPtr)notoPtr, notoFontBytes.Length, 17, fontConfig, fullRanges.Data);

                byte[]? regularFontBytes = global::rgat.Properties.Resources.Font_Awesome_5_Free_Regular_400;
                byte[]? solidFontBytes = global::rgat.Properties.Resources.Font_Awesome_5_Free_Solid_900;

                if (regularFontBytes != null && solidFontBytes != null)
                {
                    Logging.RecordLogEvent($"Loading font resources", Logging.LogFilterType.Debug);

                    System.Runtime.InteropServices.GCHandle rangeHandle =
                        System.Runtime.InteropServices.GCHandle.Alloc(new ushort[]
                        { 0xe000,0xffff,0}, System.Runtime.InteropServices.GCHandleType.Pinned);
                    try
                    {
                        fixed (byte* solidPtr = solidFontBytes, regularPtr = regularFontBytes)
                        {
                            // FontAwesome icons, add to the unicode texture atlas to they can be used alongside text
                            fontConfig = CreateNewFontConfig();
                            fontConfig.MergeMode = true;
                            fontConfig.GlyphOffset = new Vector2(0, 2); //move them down a bit to align with button text
                            IntPtr glyphRange = rangeHandle.AddrOfPinnedObject();
                            _fafontSolid = fonts.AddFontFromMemoryTTF((IntPtr)solidPtr, solidFontBytes.Length, 17, fontConfig, glyphRange);

                            fontConfig = CreateNewFontConfig();
                            fontConfig.MergeMode = true;
                            fontConfig.GlyphOffset = new Vector2(0, 2); //move them down a bit to align with button text
                            _fontNameByIndex.Add("NotoSansSC_Solid_17");
                            _fafontRegular = fonts.AddFontFromMemoryTTF((IntPtr)regularPtr, regularFontBytes.Length, 17, fontConfig, glyphRange);
                            _fontNameByIndex.Add("NotoSansSC_Regular_17");

                            // Large icons for the title screen
                            fontConfig = CreateNewFontConfig();
                            builder.Clear();
                            builder.AddChar(ImGuiController.FA_ICON_SAMPLE);
                            builder.AddChar(ImGuiController.FA_ICON_LOADFILE);
                            builder.BuildRanges(out ImVector splashBigIconRanges);

                            _iconsLargeFont = fonts.AddFontFromMemoryTTF((IntPtr)solidPtr, solidFontBytes.Length, LargeIconSize.X, fontConfig, splashBigIconRanges.Data);
                            _fontNameByIndex.Add($"NotoSansSC_Solid_{LargeIconSize.X}");

                            // Large text for the title screen, load in its own texture
                            builder.Clear();
                            builder.AddChar('r');
                            builder.AddChar('g');
                            builder.AddChar('a');
                            builder.AddChar('t');
                            ImVector rangesTitle;
                            builder.BuildRanges(out rangesTitle);

                            fontConfig = CreateNewFontConfig();
                            _titleFont = fonts.AddFontFromMemoryTTF((IntPtr)notoPtr, notoFontBytes.Length, 70, fontConfig, rangesTitle.Data);
                            _fontNameByIndex.Add("NotoSansSC_Regular_70");

                            _unicodeFont = unicodeFont;
                            unsafe
                            {
                                io.NativePtr->FontDefault = _unicodeFont.Value;
                            }
                            bool built = fonts.Build();
                            RecreateFontDeviceTexture(_gd);
                        }
                    }
                    finally
                    {
                        if (rangeHandle.IsAllocated) //not sure this is a good idea. if font related crashing happens, purge this first
                        {
                            rangeHandle.Free();
                        }
                    }
                    _splashButtonFont = splashFont;
                }
                else
                {
                    Logging.RecordError("Error loading font resources");
                }
            }
        }


        void AddConfiguredGlyphRanges(ImFontGlyphRangesBuilderPtr builder)
        {
            var fonts = ImGui.GetIO().Fonts;
            if (GlobalConfig.Settings.UI.UnicodeLoad_ChineseSimplified)
                builder.AddRanges(fonts.GetGlyphRangesChineseSimplifiedCommon());
            if (GlobalConfig.Settings.UI.UnicodeLoad_ChineseFull)
                builder.AddRanges(fonts.GetGlyphRangesChineseFull());
            if (GlobalConfig.Settings.UI.UnicodeLoad_Cyrillic)
                builder.AddRanges(fonts.GetGlyphRangesCyrillic());
            if (GlobalConfig.Settings.UI.UnicodeLoad_Japanese)
                builder.AddRanges(fonts.GetGlyphRangesJapanese());
            if (GlobalConfig.Settings.UI.UnicodeLoad_Korean)
                builder.AddRanges(fonts.GetGlyphRangesKorean());
            if (GlobalConfig.Settings.UI.UnicodeLoad_Thai)
                builder.AddRanges(fonts.GetGlyphRangesThai());
            if (GlobalConfig.Settings.UI.UnicodeLoad_Vietnamese)
                builder.AddRanges(fonts.GetGlyphRangesVietnamese());
        }

        readonly List<string> _fontNameByIndex = new();


        /// <summary>
        /// Size of large splash screen icons
        /// </summary>
        public readonly Vector2 LargeIconSize = new Vector2(65, 65);
        private ImFontPtr? _fafontSolid;
        private ImFontPtr? _fafontRegular;
        private ImFontPtr? _iconsLargeFont;


        /// <summary>
        /// Was this font glyph loaded in the unicode font
        /// </summary>
        /// <param name="code">character code</param>
        /// <returns>the glyph is in the unicode font</returns>
        public unsafe bool GlyphExists(ushort code)
        {
            if (_unicodeFont is null) return false;
            ImFontGlyphPtr result = _unicodeFont.Value.FindGlyphNoFallback(code);
            return (ulong)result.NativePtr != 0;
        }

        /// <summary>
        /// Large font for splash screen buttons
        /// </summary>
        public ImFontPtr? SplashLargeFont
        {
            get { return _newFonts ? null : _splashButtonFont; }
            private set { _splashButtonFont = value; }
        }

        private ImFontPtr? _titleFont;
        /// <summary>
        /// Larger font for the splash screen title
        /// </summary>
        public ImFontPtr? rgatLargeFont
        {
            get { return _newFonts ? null : _titleFont; }
            private set { _titleFont = value; }
        }


        private void LoadImages()
        {
            Logging.RecordLogEvent("Loading textures", Logging.LogFilterType.Debug);

            ResourceFactory factory = _gd.ResourceFactory;
            //These icons are mostly for the visualiser menu buttons and shaders where we sometimes want something
            //a bit more custom than what FontAwesome can give us

            _imageTextures["Force3D"] = BitmapToTexture(global::rgat.Properties.Resources.forceDirectedPNG);
            _imageTextures["Cylinder"] = BitmapToTexture(global::rgat.Properties.Resources.springPNG);
            _imageTextures["Circle"] = BitmapToTexture(global::rgat.Properties.Resources.circlePNG);
            _imageTextures["Eye"] = BitmapToTexture(global::rgat.Properties.Resources.eyeWhitePNG);
            _imageTextures["Menu"] = BitmapToTexture(global::rgat.Properties.Resources.menuBlackLinesPNG);
            _imageTextures["Menu2"] = BitmapToTexture(global::rgat.Properties.Resources.menuWhiteLinesPNG);
            _imageTextures["Search"] = BitmapToTexture(global::rgat.Properties.Resources.searchPNG);
            _imageTextures["Crosshair"] = BitmapToTexture(global::rgat.Properties.Resources.crosshairPNG);
            _textureViews["Crosshair"] = factory.CreateTextureView(_imageTextures["Crosshair"]);
            _imageTextures["VertCircle"] = BitmapToTexture(global::rgat.Properties.Resources.vertexSpherePNG);
            _textureViews["VertCircle"] = factory.CreateTextureView(_imageTextures["VertCircle"]);

            //These are used in shaders
            uint textureCount = 2;
            TextureDescription td = new TextureDescription(64 * textureCount, 64, 1, 1, 1, PixelFormat.R8_G8_B8_A8_UNorm_SRgb, TextureUsage.Sampled, TextureType.Texture2D);
            _imagesTextureArray = factory.CreateTexture(td);
            CommandList cl = factory.CreateCommandList();
            cl.Begin();
            cl.CopyTexture(_imageTextures["VertCircle"], 0, 0, 0, 0, 0, _imagesTextureArray, 0, 0, 0, 0, 0, 64, 64, 1, 1);
            cl.CopyTexture(_imageTextures["Crosshair"], 0, 0, 0, 0, 0, _imagesTextureArray, 64, 0, 0, 0, 0, 64, 64, 1, 1);
            cl.End();
            _gd.SubmitCommands(cl);
            cl.Dispose();
        }

        //Todo: linux compatible
        Texture BitmapToTexture(System.Drawing.Bitmap bitmap)
        {
            //Not much we can do to keep rgat going if there is a bad image resource so let the outer exception handler deal with it
            using var memoryStream = new MemoryStream();
            bitmap.Save(memoryStream, System.Drawing.Imaging.ImageFormat.Png); //windows only?
            memoryStream.Seek(0, SeekOrigin.Begin);
            var img = SixLabors.ImageSharp.Image.Load<SixLabors.ImageSharp.PixelFormats.Rgba32>(memoryStream);
            return new ImageSharpTexture(img, true, true).CreateDeviceTexture(_gd, _gd.ResourceFactory);
        }


        /// <summary>
        /// Get an icon/image texture
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public Texture GetImage(string name) => _imageTextures[name];


        /// <summary>
        /// Get a shader accessible texture view of the loaded images
        /// </summary>
        public TextureView IconTexturesView => _gd.ResourceFactory.CreateTextureView(_imagesTextureArray);

        /// <summary>
        /// Callback for window resize
        /// </summary>
        /// <param name="width">New width</param>
        /// <param name="height">New height</param>
        public void WindowResized(int width, int height)
        {
            WindowWidth = width;
            WindowHeight = height;
        }


        /// <summary>
        /// Activate the base ImGui font
        /// </summary>
        public void PushOriginalFont()
        {
            ImGui.PushFont(_originalFont!.Value);
        }
        /// <summary>
        /// Activate the custom unicode font
        /// </summary>
        public void PushUnicodeFont()
        {
            ImGui.PushFont((_newFonts || _unicodeFont.HasValue is false) ? _originalFont!.Value : _unicodeFont.Value);
        }
        /// <summary>
        /// Activate the big title font
        /// </summary>
        public void PushBigIconFont()
        {
            ImGui.PushFont((_newFonts || _iconsLargeFont.HasValue is false) ? null : _iconsLargeFont.Value);
        }

        /// <summary>
        /// Create general GPU resources for UI drawing
        /// </summary>
        /// <param name="gd">Veldrid GraphicsDevice</param>
        /// <param name="outputDescription">Framebuffer description</param>
        public void CreateDeviceResources(GraphicsDevice gd, OutputDescription outputDescription)
        {
            _gd = gd;
            ResourceFactory factory = gd.ResourceFactory;
            //can fail if we run out of graphics memory
            _vertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(gd, 200000, BufferUsage.VertexBuffer | BufferUsage.Dynamic, name: "ImGui.NET Vertex Buffer");
            _indexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(gd, 2000, BufferUsage.IndexBuffer | BufferUsage.Dynamic, name: "ImGui.NET Index Buffer");
            _projMatrixBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(gd, 64, BufferUsage.UniformBuffer | BufferUsage.Dynamic, name: "ImGui.NET Projection Buffer");

            byte[]? vertexShaderBytes = LoadEmbeddedShaderCode(gd.ResourceFactory, "imgui-vertex", ShaderStages.Vertex);
            byte[]? fragmentShaderBytes = LoadEmbeddedShaderCode(gd.ResourceFactory, "imgui-frag", ShaderStages.Fragment);
            _vertexShader = factory.CreateShader(new ShaderDescription(ShaderStages.Vertex, vertexShaderBytes, "main"));
            _fragmentShader = factory.CreateShader(new ShaderDescription(ShaderStages.Fragment, fragmentShaderBytes, "main"));

            VertexLayoutDescription[] vertexLayouts = new VertexLayoutDescription[]
            {
                new VertexLayoutDescription(
                    new VertexElementDescription("in_position", VertexElementSemantic.Position, VertexElementFormat.Float2),
                    new VertexElementDescription("in_texCoord", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float2),
                    new VertexElementDescription("in_color", VertexElementSemantic.Color, VertexElementFormat.Byte4_Norm))
            };

            _layout = factory.CreateResourceLayout(new ResourceLayoutDescription(
                new ResourceLayoutElementDescription("ProjectionMatrixBuffer", ResourceKind.UniformBuffer, ShaderStages.Vertex),
                new ResourceLayoutElementDescription("MainSampler", ResourceKind.Sampler, ShaderStages.Fragment)));
            _textureLayout = factory.CreateResourceLayout(new ResourceLayoutDescription(
                new ResourceLayoutElementDescription("MainTexture", ResourceKind.TextureReadOnly, ShaderStages.Fragment)));

            GraphicsPipelineDescription pd = new GraphicsPipelineDescription(
                BlendStateDescription.SingleAlphaBlend,
                new DepthStencilStateDescription(false, false, ComparisonKind.Always),
                new RasterizerStateDescription(FaceCullMode.None, PolygonFillMode.Solid, FrontFace.Clockwise, false, true),
                PrimitiveTopology.TriangleList,
                new ShaderSetDescription(vertexLayouts, new[] { _vertexShader, _fragmentShader }),
                new ResourceLayout[] { _layout, _textureLayout },
                outputDescription);
            _pipeline = factory.CreateGraphicsPipeline(ref pd);

            _mainResourceSet = factory.CreateResourceSet(new ResourceSetDescription(_layout,
                _projMatrixBuffer,
                gd.PointSampler));
            _mainResourceSet.Name = "ImGuiControllerMain";
        }



        /// <summary>
        /// Gets or creates a handle for a texture to be drawn with ImGui.
        /// Pass the returned handle to Image() or ImageButton().
        /// </summary>
        public IntPtr GetOrCreateImGuiBinding(ResourceFactory factory, TextureView textureView, string name)
        {
            if (!_setsByView.TryGetValue(textureView, out ResourceSetInfo rsi))
            {
                ResourceSet resourceSet = factory.CreateResourceSet(new ResourceSetDescription(_textureLayout, textureView));
                rsi = new ResourceSetInfo(GetNextImGuiBindingID(), resourceSet);
                rsi.ResourceSet.Name = name + "_" + DateTime.Now.ToFileTime().ToString();

                _setsByView.Add(textureView, rsi);
                _viewsById.Add(rsi.ImGuiBinding, rsi);
                _ownedResources.Add(resourceSet);
            }

            return rsi.ImGuiBinding;
        }

        private IntPtr GetNextImGuiBindingID()
        {
            int newID = _lastAssignedID++;
            return (IntPtr)newID;
        }

        /// <summary>
        /// Gets or creates a handle for a texture to be drawn with ImGui.
        /// Pass the returned handle to Image() or ImageButton().
        /// </summary>
        public IntPtr GetOrCreateImGuiBinding(ResourceFactory factory, Texture texture, string name)
        {
            if (!_autoViewsByTexture.TryGetValue(texture, out TextureView? textureView))
            {
                //Debug.Assert(!texture.IsDisposed);
                textureView = factory.CreateTextureView(texture);
                textureView.Name = $"TV_BOUND_" + name;
                _autoViewsByTexture.Add(texture, textureView);
                _ownedResources.Add(textureView);
            }

            //Debug.Assert(!textureView.IsDisposed);
            return GetOrCreateImGuiBinding(factory, textureView, name);
        }

        /// <summary>
        /// Retrieves the shader texture binding for the given helper handle.
        /// </summary>
        public ResourceSet GetImageResourceSet(IntPtr imGuiBinding)
        {
            if (!_viewsById.TryGetValue(imGuiBinding, out ResourceSetInfo tvi))
            {
                throw new InvalidOperationException("No registered ImGui binding with id " + imGuiBinding.ToString());
            }

            return tvi.ResourceSet;
        }

        private readonly List<Tuple<IDisposable, DateTime>> expiredResources = new List<Tuple<IDisposable, DateTime>>();

        /// <summary>
        /// Occasionally dispose of expired resources
        /// </summary>
        public void ClearCachedImageResources()
        {
            for (int i = expiredResources.Count - 1; i >= 0; i--)
            {
                var r_time = expiredResources[i];
                if ((DateTime.Now - r_time.Item2).TotalSeconds > 10)//> 5)
                {
                    expiredResources.RemoveAt(i);
                    _ownedResources.Remove(r_time.Item1);
                    //Not doing this doesn't seem to cause a memory leak and calling dispose leads to crashes
                    //Presuming they are disposed by the ref counter?
                    r_time.Item1.Dispose();

                }
            }


            List<Texture> removed = new List<Texture>();
            foreach (KeyValuePair<Texture, TextureView> view_tview in _autoViewsByTexture)
            {

                Debug.Assert(!view_tview.Value.IsDisposed);
                if (view_tview.Key.IsDisposed)
                {
                    Texture staleTexture = view_tview.Key;
                    removed.Add(staleTexture);
                    TextureView staleTextureView = view_tview.Value;

                    ResourceSetInfo rset = _setsByView[staleTextureView];
                    _viewsById.Remove(rset.ImGuiBinding);
                    _setsByView.Remove(staleTextureView);

                    expiredResources.Add(new Tuple<IDisposable, DateTime>(staleTextureView, DateTime.Now));
                    expiredResources.Add(new Tuple<IDisposable, DateTime>(rset.ResourceSet, DateTime.Now));

                }

            }


            if (removed.Any())
            {
                removed.ForEach(r => _autoViewsByTexture.Remove(r));
                Logging.RecordLogEvent($"Housekeeping removed {removed.Count} cached items, {_autoViewsByTexture.Count} active remaining", Logging.LogFilterType.Debug);
                /*
                if (_viewsById.Any())
                {
                    _lastAssignedID = _viewsById.Keys.Select(x => (int)x).Max() + 1;
                }
                else
                {
                    _lastAssignedID = 100;
                }*/
            }
        }

        /// <summary>
        /// Load a shader from resources
        /// </summary>
        /// <param name="factory">Resource factory</param>
        /// <param name="name">shader name</param>
        /// <param name="stage">unused</param>
        /// <returns>shader bytes or null if not found</returns>
        public static byte[]? LoadEmbeddedShaderCode(ResourceFactory factory, string name, ShaderStages stage)
        {
            switch (factory.BackendType)
            {
                case GraphicsBackend.Direct3D11:
                    {
                        string resourceName = "rgat.Shaders.HLSL." + name + ".hlsl.bytes";
                        return GetEmbeddedResourceBytes(resourceName);
                    }
                case GraphicsBackend.OpenGL:
                    {
                        string resourceName = "rgat.Shaders.GLSL." + name + ".glsl";
                        return GetEmbeddedResourceBytes(resourceName);
                    }
                case GraphicsBackend.Vulkan:
                    {
                        string resourceName = "rgat.Shaders.SPIR_V." + name + ".spv";
                        return GetEmbeddedResourceBytes(resourceName);
                    }
                case GraphicsBackend.Metal:
                    {
                        string resourceName = "rgat.Shaders.Metal." + name + ".metallib";
                        return GetEmbeddedResourceBytes(resourceName);
                    }
                default:
                    throw new NotImplementedException();
            }
        }


        public static byte[]? GetEmbeddedResourceBytes(string resourceName)
        {
            Assembly assembly = typeof(ImGuiController).Assembly;

            using Stream? resourceStream = assembly.GetManifestResourceStream(resourceName);
            if (resourceStream == null)
            {
                Logging.RecordLogEvent("ERROR: Failed to find resource " + resourceName, filter: Logging.LogFilterType.Error);
                return null;
            }
            else
            {
                byte[] ret = new byte[resourceStream.Length];
                resourceStream.Read(ret, 0, (int)resourceStream.Length);
                return ret;
            }
        }


        /// <summary>
        /// Recreates the device texture used to render text.
        /// </summary>
        public void RecreateFontDeviceTexture(GraphicsDevice gd)
        {
            _gd.WaitForIdle();
            ImGuiIOPtr io = ImGui.GetIO();
            // Build
            //had a crash here on start up once, don't know why. added a waitforidle above in the hope it was just the earlier buffer operations being incomplete

            Logging.RecordLogEvent("About to fetch font data from ImGui. If there are no logs after this then this is what crashed us.", Logging.LogFilterType.BulkDebugLogFile);
            io.Fonts.GetTexDataAsRGBA32(out IntPtr pixels, out int width, out int height, out int bytesPerPixel);
            if (width == 0 || height == 0)
            {
                Logging.RecordError("Not recreating fonts - 0 texture size!");
                return;
            }
            Logging.RecordLogEvent("Sucessfully fetched font texture data", Logging.LogFilterType.BulkDebugLogFile);

            // Store our identifier
            io.Fonts.SetTexID(_fontAtlasID);
            _fontTexture?.Dispose();
            TextureDescription td = TextureDescription.Texture2D((uint)width, (uint)height, 1, 1, PixelFormat.R8_G8_B8_A8_UNorm, TextureUsage.Sampled);
            _fontTexture = gd.ResourceFactory.CreateTexture(td);
            _fontTexture.Name = "ImGui.NET Font Texture";

            gd.UpdateTexture(
                texture: _fontTexture, source: pixels, sizeInBytes: (uint)(bytesPerPixel * width * height),
                x: 0, y: 0, z: 0, width: (uint)width,
                height: (uint)height, depth: 1, mipLevel: 0, arrayLayer: 0);

            _fontTextureView?.Dispose();
            _fontTextureView = gd.ResourceFactory.CreateTextureView(_fontTexture);

            _fontTextureResourceSet?.Dispose();
            ResourceLayout _fontLayout = _gd.ResourceFactory.CreateResourceLayout(new ResourceLayoutDescription(
     new ResourceLayoutElementDescription("FontTexture", ResourceKind.TextureReadOnly, ShaderStages.Fragment)));
            _fontTextureResourceSet = _gd.ResourceFactory.CreateResourceSet(new ResourceSetDescription(_fontLayout, _fontTextureView));
            _fontTextureResourceSet.Name = "ImGuiControllerMainFont";

            _gd.WaitForIdle();
            io.Fonts.ClearTexData();


        }

        /// <summary>
        /// Renders the ImGui draw list data.
        /// This method requires a <see cref="Veldrid.GraphicsDevice"/> because it may create new DeviceBuffers if the size of vertex
        /// or index data has increased beyond the capacity of the existing buffers.
        /// A <see cref="CommandList"/> is needed to submit drawing and resource update commands.
        /// </summary>
        public void Render(GraphicsDevice gd, CommandList cl)
        {
            if (_frameBegun)
            {
                _frameBegun = false;
                ImGui.Render();
                RenderImDrawData(ImGui.GetDrawData(), gd, cl);
            }
        }


        /// <summary>
        /// Trigger recreation of font textures on the next UI frame
        /// </summary>
        public void RebuildFonts() => _newFonts = true;

        bool _newFonts = false;

        /// <summary>
        /// Updates ImGui input and IO configuration state.
        /// </summary>
        public void Update(float deltaSeconds, InputSnapshot snapshot)
        {
            if (_newFonts && rgatUI.StartupProgress >= 1)
            {
                Stopwatch sw = new Stopwatch();
                sw.Start();
                BuildFonts(true);
                Logging.RecordLogEvent($"Rebuilding fonts hung the UI for {sw.ElapsedMilliseconds} ms");
                //_originalFont = ImGui.GetIO().Fonts.AddFontDefault();

                _newFonts = false;

            }


            SetPerFrameImGuiData(deltaSeconds);
            UpdateImGuiInput(snapshot);
            _frameBegun = true;
            ImGui.NewFrame();

        }

        /// <summary>
        /// Sets per-frame data based on the associated window.
        /// This is called by Update(float).
        /// </summary>
        private void SetPerFrameImGuiData(float deltaSeconds)
        {
            ImGuiIOPtr io = ImGui.GetIO();
            io.DisplaySize = new Vector2(
                WindowWidth / _scaleFactor.X,
                WindowHeight / _scaleFactor.Y);
            io.DisplayFramebufferScale = _scaleFactor;
            io.DeltaTime = deltaSeconds; // DeltaTime is in seconds.
            io.ConfigFlags |= ImGuiConfigFlags.DockingEnable; //doesnt work yet?
        }

        public DateTime LastMouseMove { get; private set; } = DateTime.MinValue;
        public bool MousePresent { get; private set; } = false;
        public void SetMousePresent(bool state)
        {
            MousePresent = state;
            LastMouseMove = DateTime.Now;
        }
        public double LastMouseActivityMS => (DateTime.Now - LastMouseMove).TotalMilliseconds;

        private void UpdateImGuiInput(InputSnapshot snapshot)
        {
            ImGuiIOPtr io = ImGui.GetIO();

            Vector2 mousePosition = snapshot.MousePosition;

            // Determine if any of the mouse buttons were pressed during this snapshot period, even if they are no longer held.
            bool leftPressed = false;
            bool middlePressed = false;
            bool rightPressed = false;
            foreach (MouseEvent me in snapshot.MouseEvents)
            {
                if (me.Down)
                {
                    switch (me.MouseButton)
                    {
                        case MouseButton.Left:
                            leftPressed = true;
                            break;
                        case MouseButton.Middle:
                            middlePressed = true;
                            break;
                        case MouseButton.Right:
                            rightPressed = true;
                            break;
                    }
                }
            }

            io.MouseDown[0] = leftPressed || snapshot.IsMouseDown(MouseButton.Left);
            io.MouseDown[1] = rightPressed || snapshot.IsMouseDown(MouseButton.Right);
            io.MouseDown[2] = middlePressed || snapshot.IsMouseDown(MouseButton.Middle);
            io.MousePos = mousePosition;
            io.MouseWheel = snapshot.WheelDelta;

            IReadOnlyList<char> keyCharPresses = snapshot.KeyCharPresses;
            for (int i = 0; i < keyCharPresses.Count; i++)
            {
                char c = keyCharPresses[i];
                io.AddInputCharacter(c);
            }

            IReadOnlyList<KeyEvent> keyEvents = snapshot.KeyEvents;
            for (int i = 0; i < keyEvents.Count; i++)
            {
                KeyEvent keyEvent = keyEvents[i];
                io.KeysDown[(int)keyEvent.Key] = keyEvent.Down;
                if (keyEvent.Key == Key.ControlLeft || keyEvent.Key == Key.ControlRight)
                {
                    _controlDown = keyEvent.Down;
                }
                if (keyEvent.Key == Key.ShiftLeft || keyEvent.Key == Key.ShiftRight)
                {
                    _shiftDown = keyEvent.Down;
                }
                if (keyEvent.Key == Key.AltLeft || keyEvent.Key == Key.AltRight)
                {
                    _altDown = keyEvent.Down;
                }
                if (keyEvent.Key == Key.WinLeft)
                {
                    _winKeyDown = keyEvent.Down;
                }
            }

            io.KeyCtrl = _controlDown;
            io.KeyAlt = _altDown;
            io.KeyShift = _shiftDown;
            io.KeySuper = _winKeyDown;
        }

        private static void SetKeyMappings()
        {
            ImGuiIOPtr io = ImGui.GetIO();
            io.KeyMap[(int)ImGuiKey.Tab] = (int)Key.Tab;
            io.KeyMap[(int)ImGuiKey.LeftArrow] = (int)Key.Left;
            io.KeyMap[(int)ImGuiKey.RightArrow] = (int)Key.Right;
            io.KeyMap[(int)ImGuiKey.UpArrow] = (int)Key.Up;
            io.KeyMap[(int)ImGuiKey.DownArrow] = (int)Key.Down;
            io.KeyMap[(int)ImGuiKey.PageUp] = (int)Key.PageUp;
            io.KeyMap[(int)ImGuiKey.PageDown] = (int)Key.PageDown;
            io.KeyMap[(int)ImGuiKey.Home] = (int)Key.Home;
            io.KeyMap[(int)ImGuiKey.End] = (int)Key.End;
            io.KeyMap[(int)ImGuiKey.Delete] = (int)Key.Delete;
            io.KeyMap[(int)ImGuiKey.Backspace] = (int)Key.BackSpace;
            io.KeyMap[(int)ImGuiKey.Enter] = (int)Key.Enter;
            io.KeyMap[(int)ImGuiKey.KeyPadEnter] = (int)Key.KeypadEnter;
            io.KeyMap[(int)ImGuiKey.Escape] = (int)Key.Escape;
            io.KeyMap[(int)ImGuiKey.A] = (int)Key.A;
            io.KeyMap[(int)ImGuiKey.C] = (int)Key.C;
            io.KeyMap[(int)ImGuiKey.V] = (int)Key.V;
            io.KeyMap[(int)ImGuiKey.X] = (int)Key.X;
            io.KeyMap[(int)ImGuiKey.Y] = (int)Key.Y;
            io.KeyMap[(int)ImGuiKey.Z] = (int)Key.Z;
        }

        private void ExpandGraphicsBuffers(ImDrawDataPtr draw_data, GraphicsDevice gd)
        {
            uint totalVBSize = (uint)(draw_data.TotalVtxCount * Unsafe.SizeOf<ImDrawVert>());
            if (totalVBSize > _vertexBuffer!.SizeInBytes)
            {
                Logging.RecordLogEvent($"ExpandGraphicsBuffers() Resizing Vertex buffer from {_vertexBuffer.SizeInBytes} to {totalVBSize * 1.5f}", Logging.LogFilterType.Debug);
                gd.DisposeWhenIdle(_vertexBuffer);
                _vertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(gd, (uint)(totalVBSize * 1.5f), BufferUsage.VertexBuffer | BufferUsage.Dynamic, name: _vertexBuffer.Name);
            }

            uint totalIBSize = (uint)(draw_data.TotalIdxCount * sizeof(ushort));
            if (totalIBSize > _indexBuffer!.SizeInBytes)
            {
                Logging.RecordLogEvent($"ExpandGraphicsBuffers() Resizing Index buffer from {_indexBuffer.SizeInBytes} to {totalIBSize * 1.5f}", Logging.LogFilterType.Debug);
                gd.DisposeWhenIdle(_indexBuffer);
                _indexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(gd, (uint)(totalIBSize * 1.5f), BufferUsage.IndexBuffer | BufferUsage.Dynamic, name: _indexBuffer.Name);
            }
        }


        private void SetupUIProjection(ImDrawDataPtr draw_data, CommandList cl)
        {
            // Setup orthographic projection matrix into our constant buffer
            ImGuiIOPtr io = ImGui.GetIO();
            const float near = -1.0f;
            const float far = 1.0f;
            Matrix4x4 mvp = Matrix4x4.CreateOrthographicOffCenter(0f, io.DisplaySize.X, io.DisplaySize.Y, 0.0f, near, far);

            cl.UpdateBuffer(_projMatrixBuffer, 0, ref mvp);

            draw_data.ScaleClipRects(io.DisplayFramebufferScale);
        }


        private void LoadCommandBuffers(ImDrawDataPtr draw_data, CommandList cl)
        {
            uint vertexOffsetInVertices = 0;
            uint indexOffsetInElements = 0;
            for (int i = 0; i < draw_data.CmdListsCount; i++)
            {
                ImDrawListPtr cmd_list = draw_data.CmdListsRange[i];

                //crash here... possibly just when restoring from computer sleep?
                cl.UpdateBuffer(
                    _vertexBuffer,
                    vertexOffsetInVertices * (uint)Unsafe.SizeOf<ImDrawVert>(),
                    cmd_list.VtxBuffer.Data,
                    (uint)(cmd_list.VtxBuffer.Size * Unsafe.SizeOf<ImDrawVert>()));

                cl.UpdateBuffer(
                    _indexBuffer,
                    indexOffsetInElements * sizeof(ushort),
                    cmd_list.IdxBuffer.Data,
                    (uint)(cmd_list.IdxBuffer.Size * sizeof(ushort)));

                vertexOffsetInVertices += (uint)cmd_list.VtxBuffer.Size;
                indexOffsetInElements += (uint)cmd_list.IdxBuffer.Size;
            }
        }


        // Render command lists
        private void DrawCommands(ImDrawDataPtr draw_data, CommandList cl)
        {
            int vtx_offset = 0;
            int idx_offset = 0;
            for (int n = 0; n < draw_data.CmdListsCount; n++)
            {
                ImDrawListPtr cmd_list = draw_data.CmdListsRange[n];
                for (int cmd_i = 0; cmd_i < cmd_list.CmdBuffer.Size; cmd_i++)
                {
                    ImDrawCmdPtr ptrCmnd = cmd_list.CmdBuffer[cmd_i];
                    if (ptrCmnd.UserCallback != IntPtr.Zero)
                    {
                        throw new NotImplementedException();
                    }
                    else
                    {
                        if (ptrCmnd.TextureId != IntPtr.Zero)
                        {
                            if (ptrCmnd.TextureId == _fontAtlasID)
                            {
                                cl.SetGraphicsResourceSet(1, _fontTextureResourceSet);
                            }
                            else
                            {
                                ResourceSet rscset = GetImageResourceSet(ptrCmnd.TextureId);
                                cl.SetGraphicsResourceSet(1, rscset);
                            }
                        }

                        cl.SetScissorRect(
                            0,
                            (uint)ptrCmnd.ClipRect.X,
                            (uint)ptrCmnd.ClipRect.Y,
                            (uint)(ptrCmnd.ClipRect.Z - ptrCmnd.ClipRect.X),
                            (uint)(ptrCmnd.ClipRect.W - ptrCmnd.ClipRect.Y));

                        cl.DrawIndexed(ptrCmnd.ElemCount, 1, (uint)idx_offset, vtx_offset, 0);
                    }

                    idx_offset += (int)ptrCmnd.ElemCount;
                }
                vtx_offset += cmd_list.VtxBuffer.Size;
            }
        }


        private void RenderImDrawData(ImDrawDataPtr draw_data, GraphicsDevice gd, CommandList cl)
        {
            if (draw_data.CmdListsCount == 0)
            {
                return;
            }

            ExpandGraphicsBuffers(draw_data, gd);

            LoadCommandBuffers(draw_data, cl);

            SetupUIProjection(draw_data, cl);

            cl.SetVertexBuffer(0, _vertexBuffer);
            cl.SetIndexBuffer(_indexBuffer, IndexFormat.UInt16);
            cl.SetPipeline(_pipeline);
            cl.SetGraphicsResourceSet(0, _mainResourceSet);

            DrawCommands(draw_data, cl);
        }


        /// <summary>
        /// Frees all graphics resources used by the renderer.
        /// </summary>
        public void Dispose()
        {
            _vertexBuffer?.Dispose();
            _indexBuffer?.Dispose();
            _projMatrixBuffer?.Dispose();
            _fontTexture?.Dispose();
            _fontTextureView?.Dispose();
            _vertexShader?.Dispose();
            _fragmentShader?.Dispose();
            _layout?.Dispose();
            _textureLayout?.Dispose();
            _pipeline?.Dispose();
            _mainResourceSet?.Dispose();
            _imagesTextureArray?.Dispose();

            foreach (IDisposable resource in _ownedResources)
            {
                resource.Dispose();
            }
        }


        private struct ResourceSetInfo
        {
            public readonly IntPtr ImGuiBinding;
            public readonly ResourceSet ResourceSet;

            public ResourceSetInfo(IntPtr imGuiBinding, ResourceSet resourceSet)
            {
                ImGuiBinding = imGuiBinding;
                ResourceSet = resourceSet;
            }
        }



#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        public static readonly char FA_ICON_COG = '\uf013';
        public static readonly char FA_ICON_REFRESH = '\uf021';
        public static readonly char FA_ICON_LOCK = '\uf023';
        public static readonly char FA_ICON_MEDIAPLAY = '\uf04b';
        public static readonly char FA_ICON_MEDIAPAUSE = '\uf04c';
        public static readonly char FA_ICON_MEDIASTOP = '\uf04d';
        public static readonly char FA_ICON_STEP = '\uf051';
        public static readonly char FA_ICON_LEFT = '\uf060';
        public static readonly char FA_ICON_RIGHT = '\uf061';
        public static readonly char FA_ICON_UP = '\uf062';
        public static readonly char FA_ICON_DOWN = '\uf063';
        public static readonly char FA_ICON_NOENTRY = '\uf05e';


        public static readonly char FA_ICON_NETWORK = '\uf6ff';
        public static readonly char FA_ICON_LOCALCODE = '\uf5fc';
        public static readonly char FA_ICON_SAMPLE = '\ue05a';
        public static readonly char FA_ICON_COGS = '\uf085';

        public static readonly char FA_ICON_MOVEMENT = '\uf31e';
        public static readonly char FA_ICON_ROTATION = '\uf2ea';

        public static readonly char FA_ICON_SQUAREGRID = '\uf00a';
        public static readonly char FA_ICON_CLOCK = '\uf017';
        public static readonly char FA_ICON_DOWNLOAD2 = '\uf019';
        public static readonly char FA_PLAY_CIRCLE = '\uf144';
        public static readonly char FA_BLANK_CIRCLE = '\uf111';
        public static readonly char FA_VIDEO_CAMERA = '\uf03d';
        public static readonly char FA_STILL_CAMERA = '\uf030';
        public static readonly char FA_ICON_WARNING = '\uf071';
        public static readonly char FA_ICON_LIST = '\uf0ca';
        public static readonly char FA_ICON_EYE = '\uF06E';
        public static readonly char FA_ICON_BELL = '\uF0F3';
        public static readonly char FA_ICON_LISTEN = '\uF2A0';
        public static readonly char FA_ICON_BROADCAST = '\uF7C0';
        public static readonly char FA_ICON_EXCLAIM = '\uf12a';
        public static readonly char FA_ICON_LIGHTNING = '\uf0e7';
        public static readonly char FA_ICON_DIRECTORY = '\uf07b';
        public static readonly char FA_ICON_FILEPLAIN = '\uf15b';
        public static readonly char FA_ICON_KEYBOARD = '\uf11c';
        public static readonly char FA_ICON_BARCODE = '\uf02a';
        public static readonly char FA_ICON_PUNCTUATION = '\uf1dd';
        public static readonly char FA_ICON_FILECODE = '\uf1c9';
        public static readonly char FA_ICON_COPY = '\uf0c5';
        public static readonly char FA_ICON_TICK = '\uf00c';
        public static readonly char FA_ICON_CROSS = '\uf00d';
        public static readonly char FA_ICON_STAR = '\uf005';
        public static readonly char FA_ICON_PLUS = '\uf067';
        public static readonly char FA_ICON_UPCIRCLE = '\uf0aa';
        public static readonly char FA_ICON_DOWNCIRCLE = '\uf0ab';
        public static readonly char FA_ICON_LEFTCIRCLE = '\uf0a8';
        public static readonly char FA_ICON_RIGHTCIRCLE = '\uf0a9';
        public static readonly char FA_ICON_TRASHCAN = '\uf2ed';
        public static readonly char FA_ICON_WRENCH = '\uf0ad';
        public static readonly char FA_ICON_ADDFILE = '\uf477';
        public static readonly char FA_ICON_DOWNLOAD = '\uf56d';
        public static readonly char FA_ICON_LOADFILE = '\uf56e';

        public static readonly char FA_ICON_PLANT = '\uf4d8';
        public static readonly char FA_ICON_EGG = '\uf7fb';
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
