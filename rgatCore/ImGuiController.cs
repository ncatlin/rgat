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
        private DeviceBuffer _vertexBuffer;
        private DeviceBuffer _indexBuffer;
        private DeviceBuffer _projMatrixBuffer;
        private Texture _fontTexture;
        public TextureView _fontTextureView;
        private Shader _vertexShader;
        private Shader _fragmentShader;
        private ResourceLayout _layout;
        private ResourceLayout _textureLayout;
        private Pipeline _pipeline;
        private ResourceSet _mainResourceSet;
        private ResourceSet _fontTextureResourceSet;

        private IntPtr _fontAtlasID = (IntPtr)1;
        private bool _controlDown;
        private bool _shiftDown;
        private bool _altDown;
        private bool _winKeyDown;
        public int _windowWidth;
        public int _windowHeight;
        private Vector2 _scaleFactor = Vector2.One;

        // Image trackers
        private readonly Dictionary<TextureView, ResourceSetInfo> _setsByView
            = new Dictionary<TextureView, ResourceSetInfo>();
        private readonly Dictionary<Texture, TextureView> _autoViewsByTexture
            = new Dictionary<Texture, TextureView>();
        private readonly Dictionary<IntPtr, ResourceSetInfo> _viewsById = new Dictionary<IntPtr, ResourceSetInfo>();
        private readonly List<IDisposable> _ownedResources = new List<IDisposable>();
        private int _lastAssignedID = 100;

        //private ImFontPtr _customFont = null;
        public ImFontPtr _unicodeFont = null;
        ImFontPtr? _splashButtonFont = null;
        public ImFontPtr _originalFont = null;
        private bool _unicodeFontLoaded = false;


        public bool ShowDemoWindow = false;
        public GraphicsDevice graphicsDevice => _gd;

        public static readonly char FA_ICON_NETWORK = '\uf6ff';
        public static readonly char FA_ICON_LOCALCODE = '\uf5fc';
        public static readonly char FA_ICON_SAMPLE = '\ue05a';
        public static readonly char FA_ICON_LOADFILE = '\uf56e';
        public static readonly char FA_ICON_COG = '\uf013';
        public static readonly char FA_ICON_COGS = '\uf085';
        public static readonly char FA_ICON_SQUAREGRID = '\uf00a';

        public static readonly char FA_PLAY_CIRCLE = '\uf144';
        public static readonly char FA_VIDEO_CAMERA = '\uf03d';
        public static readonly char FA_STILL_CAMERA = '\uf030';
        public static readonly char FA_ICON_WARNING = '\uf071';
        public static readonly char FA_ICON_EXCLAIM = '\uf12a';
        public static readonly char FA_ICON_UP = '\uf062';
        public static readonly char FA_ICON_LEFT = '\uf060';
        public static readonly char FA_ICON_RIGHT = '\uf061';
        public static readonly char FA_ICON_DOWN = '\uf063';
        public static readonly char FA_ICON_DIRECTORY = '\uf07b';
        public static readonly char FA_ICON_FILEPLAIN = '\uf15b';
        public static readonly char FA_ICON_FILECODE = '\uf1c9';
        public static readonly char FA_ICON_CROSS = '\uf00d';
        public static readonly char FA_ICON_PLUS = '\uf067';
        public static readonly char FA_ICON_UPCIRCLE = '\uf0aa';
        public static readonly char FA_ICON_DOWNCIRCLE = '\uf0ab';
        public static readonly char FA_ICON_LEFTCIRCLE = '\uf0a8';
        public static readonly char FA_ICON_RIGHTCIRCLE = '\uf0a9';
        public static readonly char FA_ICON_TRASHCAN = '\uf2ed';
        public static readonly char FA_ICON_WRENCH = '\uf0ad';
        public static readonly char FA_ICON_ADDFILE = '\uf477';
        public static readonly char FA_ICON_CLOCK = '\uf017';
        public static readonly char FA_ICON_DOWNLOAD = '\uf56d';

        public unsafe ImGuiController(GraphicsDevice gd, OutputDescription outputDescription, int width, int height)
        {
            _gd = gd;
            _windowWidth = width;
            _windowHeight = height;

            IntPtr context = ImGui.CreateContext();
            ImGui.SetCurrentContext(context);

            Logging.RecordLogEvent("Loading fonts", Logging.LogFilterType.TextDebug);
            var fonts = ImGui.GetIO().Fonts;
            LoadUnicodeFont();
            LoadIconFont();
            _originalFont = fonts.AddFontDefault();


            Logging.RecordLogEvent("Done Loading fonts", Logging.LogFilterType.TextDebug);

            CreateDeviceResources(gd, outputDescription);
            SetKeyMappings();
            LoadImages();
            SetPerFrameImGuiData(1f / 60f);

            //should be fixed now

            Debug.Assert(_unicodeFont.GetCharAdvance('a') == _unicodeFont.FindGlyph('a').AdvanceX,
                    "The ImGui.NET used is not handling bitfields properly, preventing fonts " +
                    "from rendering correctly in the graph. https://github.com/mellinoe/ImGui.NET/issues/206");


            ImGui.NewFrame();
            _frameBegun = true;
        }

        public unsafe void LoadUnicodeFont()
        {
            if (_unicodeFontLoaded) return;

            Logging.RecordLogEvent($"Loading Unicode fonts", Logging.LogFilterType.TextDebug);
            ImFontGlyphRangesBuilderPtr builder = new ImFontGlyphRangesBuilderPtr(ImGuiNative.ImFontGlyphRangesBuilder_ImFontGlyphRangesBuilder());

            //TODO - make these options
            //TODO - see if they can be loaded on the side after start
            var fonts = ImGui.GetIO().Fonts;
            //for (ushort i = 0; i < 0xff; i++) builder.AddChar(i);
            builder.AddRanges(fonts.GetGlyphRangesDefault());
            //builder.AddRanges(fonts.GetGlyphRangesChineseSimplifiedCommon());
            //builder.AddRanges(fonts.GetGlyphRangesChineseFull());  //crash - needs higher version of veldrid (update: updated!)
            //builder.AddRanges(fonts.GetGlyphRangesCyrillic());


            //builder.AddRanges(fonts.GetGlyphRangesJapanese());
            //builder.AddRanges(fonts.GetGlyphRangesKorean());
            //builder.AddRanges(fonts.GetGlyphRangesThai());
            //builder.AddRanges(fonts.GetGlyphRangesVietnamese());
            //builder.AddChar(0xe0dd);
            //builder.AddChar(0xe0d3);
            //for (ushort i = 0xe000; i < 0xe0fe; i++)
            //    builder.AddChar((ushort)i);
            ImVector ranges;
            builder.BuildRanges(out ranges);

            //embed in resource for distribution, once a font is settled on

            
            byte[] notoFontBytes = ReadResourceByteArray("NotoSansSC_Regular");

            if (notoFontBytes == null)
            {
                Logging.RecordError($"No font resouce: \"NotoSansSC_Regular\"");
                return;
            }

            ImFontConfigPtr fontConfig = ImGuiNative.ImFontConfig_ImFontConfig();
            fontConfig.MergeMode = true;
            fontConfig.FontDataOwnedByAtlas = true;
            fontConfig.OversampleH = 2;
            fontConfig.PixelSnapH = true;
            fontConfig.OversampleV = 1;
            fontConfig.GlyphOffset = new Vector2(0, 2);
            fontConfig.GlyphMaxAdvanceX = float.MaxValue;
            fontConfig.RasterizerMultiply = 1f;

            //not a good use of memory, think there are other ways to resize?

            fixed (byte* notoPtr = notoFontBytes)
            {
                _splashButtonFont = ImGui.GetIO().Fonts.AddFontFromMemoryTTF((IntPtr)notoPtr, notoFontBytes.Length, 40, null, ranges.Data);

                _unicodeFont = ImGui.GetIO().Fonts.AddFontFromMemoryTTF((IntPtr)notoPtr, notoFontBytes.Length, 17, null, ranges.Data);

                builder.Clear();
                builder.AddChar('r');
                builder.AddChar('g');
                builder.AddChar('a');
                builder.AddChar('t');
                ImVector rangesTitle;
                builder.BuildRanges(out rangesTitle);

                _titleFont = ImGui.GetIO().Fonts.AddFontFromMemoryTTF((IntPtr)notoPtr, notoFontBytes.Length, 70, null, rangesTitle.Data);
            }
            unsafe
            {
                ImGui.GetIO().NativePtr->FontDefault = _unicodeFont;
            }

 


            _unicodeFontLoaded = true;
        }



        public unsafe void LoadIconFont()
        {
            Logging.RecordLogEvent($"Loading Icon fonts", Logging.LogFilterType.TextDebug);
            System.Runtime.InteropServices.GCHandle rangeHandle = System.Runtime.InteropServices.GCHandle.Alloc(new ushort[]
  { 0xe000,0xffff,0}, System.Runtime.InteropServices.GCHandleType.Pinned);

            ImFontConfigPtr fontConfig = ImGuiNative.ImFontConfig_ImFontConfig();
            fontConfig.MergeMode = true;
            fontConfig.FontDataOwnedByAtlas = true;
            fontConfig.OversampleH = 2;
            fontConfig.PixelSnapH = true;
            fontConfig.OversampleV = 1;
            fontConfig.GlyphOffset = new Vector2(0, 2);
            fontConfig.GlyphMaxAdvanceX = float.MaxValue;
            fontConfig.RasterizerMultiply = 1f;

            byte[] regularFontBytes = ReadResourceByteArray("Font_Awesome_5_Free_Regular_400");
            byte[] solidFontBytes = ReadResourceByteArray("Font_Awesome_5_Free_Solid_900");
            if (regularFontBytes != null && solidFontBytes != null)
            {
                Logging.RecordLogEvent($"Loading font resources", Logging.LogFilterType.TextDebug);

                try
                {
                    fixed (byte* solidPtr = solidFontBytes, regularPtr = regularFontBytes)
                    {
                        fontConfig.FontDataOwnedByAtlas = true;
                        IntPtr glyphRange = rangeHandle.AddrOfPinnedObject();
                        _fafontSolid = ImGui.GetIO().Fonts.AddFontFromMemoryTTF((IntPtr)solidPtr, solidFontBytes.Length, 17, fontConfig, glyphRange);
                        _fafontRegular = ImGui.GetIO().Fonts.AddFontFromMemoryTTF((IntPtr)regularPtr, regularFontBytes.Length, 17, fontConfig, glyphRange);
                        fontConfig.MergeMode = false;
                        _iconsLargeFont = ImGui.GetIO().Fonts.AddFontFromMemoryTTF((IntPtr)solidPtr, solidFontBytes.Length, LargeIconSize.X, fontConfig, glyphRange);
                    }
                }
                finally
                {
                    /*
                    fontConfig.Destroy();
                    if (rangeHandle.IsAllocated)
                    {
                        rangeHandle.Free();
                    }
                    */
                }
            }
            else
            {
                Logging.RecordError("Error loading font resources");
            }
        }


        public readonly Vector2 LargeIconSize = new Vector2(65, 65);
        ImFontPtr _fafontSolid;
        ImFontPtr _fafontRegular;
        ImFontPtr _iconsLargeFont;

        public byte[] ReadResourceByteArray(string name)
        {
            System.Reflection.Assembly assembly = typeof(ImGuiController).Assembly;
            System.IO.Stream fs = assembly.GetManifestResourceStream(assembly.GetManifestResourceNames()[0]);
            System.Resources.ResourceReader r = new System.Resources.ResourceReader(fs);
            r.GetResourceData(name, out string rtype, out byte[] resBytes);
            if (resBytes == null || rtype != "ResourceTypeCode.ByteArray") return null;

            //https://stackoverflow.com/questions/32891004/why-resourcereader-getresourcedata-return-data-of-type-resourcetypecode-stream
            Stream stream = new MemoryStream(resBytes);
            byte[] result = new byte[stream.Length - 4];
            stream.Seek(4, SeekOrigin.Begin);
            stream.Read(result, 0, result.Length - 4);
            return result;
        }

        public unsafe bool GlyphExists(ushort code)
        {
            ImFontGlyphPtr result = _unicodeFont.FindGlyphNoFallback(code);
            return (ulong)result.NativePtr != 0;
        }

        public ImFontPtr SplashLargeFont
        {
            get { return _splashButtonFont.Value; }
            private set { _splashButtonFont = value; }
        }

        ImFontPtr? _titleFont;
        public ImFontPtr rgatLargeFont
        {
            get { return _titleFont.Value; }
            private set { _titleFont = value; }
        }

        Dictionary<string, Texture> _imageTextures = new Dictionary<string, Texture>();
        Dictionary<string, TextureView> _textureViews = new Dictionary<string, TextureView>();

        Texture _imagesTextureArray;
        void LoadImages()
        {
            ResourceFactory factory = _gd.ResourceFactory;
            string imgpath = @"C:\Users\nia\Desktop\rgatstuff\icons\forceDirected.png";
            _imageTextures["Force3D"] = new ImageSharpTexture(imgpath, true, true).CreateDeviceTexture(_gd, factory);

            imgpath = @"C:\Users\nia\Desktop\rgatstuff\icons\spring.png";
            _imageTextures["Cylinder"] = new ImageSharpTexture(imgpath, true, true).CreateDeviceTexture(_gd, factory);

            imgpath = @"C:\Users\nia\Desktop\rgatstuff\icons\circle.png";
            _imageTextures["Circle"] = new ImageSharpTexture(imgpath, true, true).CreateDeviceTexture(_gd, factory);

            imgpath = @"C:\Users\nia\Desktop\rgatstuff\icons\eye-white.png";
            _imageTextures["Eye"] = new ImageSharpTexture(imgpath, true, true).CreateDeviceTexture(_gd, factory);

            imgpath = @"C:\Users\nia\Desktop\rgatstuff\icons\menu2.png";
            _imageTextures["Menu"] = new ImageSharpTexture(imgpath, true, true).CreateDeviceTexture(_gd, factory);
            imgpath = @"C:\Users\nia\Desktop\rgatstuff\icons\menu3.png";
            _imageTextures["Menu2"] = new ImageSharpTexture(imgpath, true, true).CreateDeviceTexture(_gd, factory);
            imgpath = @"C:\Users\nia\Desktop\rgatstuff\icons\search.png";
            _imageTextures["Search"] = new ImageSharpTexture(imgpath, true, true).CreateDeviceTexture(_gd, factory);


            imgpath = @"C:\Users\nia\Desktop\rgatstuff\icons\crosshair.png";
            _imageTextures["Crosshair"] = new ImageSharpTexture(imgpath, true, true).CreateDeviceTexture(_gd, factory);
            _textureViews["Crosshair"] = factory.CreateTextureView(_imageTextures["Crosshair"]);

            imgpath = @"C:\Users\nia\Desktop\rgatstuff\icons\new_circle.png";
            _imageTextures["VertCircle"] = new ImageSharpTexture(imgpath, true, true).CreateDeviceTexture(_gd, factory);
            _textureViews["VertCircle"] = factory.CreateTextureView(_imageTextures["VertCircle"]);


            imgpath = @"C:\Users\nia\Desktop\rgatstuff\icons\loading-arrow.png";
            _imageTextures["ArrowSpin"] = new ImageSharpTexture(imgpath, true, true).CreateDeviceTexture(_gd, factory);

            imgpath = @"C:\Users\nia\Desktop\rgatstuff\icons\check.png";
            _imageTextures["Check"] = new ImageSharpTexture(imgpath, true, true).CreateDeviceTexture(_gd, factory);

            imgpath = @"C:\Users\nia\Desktop\rgatstuff\icons\cancel.png";
            _imageTextures["Cross"] = new ImageSharpTexture(imgpath, true, true).CreateDeviceTexture(_gd, factory);

            imgpath = @"C:\Users\nia\Desktop\rgatstuff\icons\star_full.png";
            _imageTextures["StarFull"] = new ImageSharpTexture(imgpath, true, true).CreateDeviceTexture(_gd, factory);

            imgpath = @"C:\Users\nia\Desktop\rgatstuff\icons\star_empty.png";
            _imageTextures["StarEmpty"] = new ImageSharpTexture(imgpath, true, true).CreateDeviceTexture(_gd, factory);

            imgpath = @"C:\Users\nia\Desktop\rgatstuff\icons\GreenPlus.png";
            _imageTextures["GreenPlus"] = new ImageSharpTexture(imgpath, true, true).CreateDeviceTexture(_gd, factory);


            //can't figure out how to make texture arrays work with veldrid+vulkan, inconclusive+error results from searching
            //instead make a simple 2D texture atlas
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

        public Texture GetImage(string name) => _imageTextures[name];
        public TextureView IconTexturesView => _gd.ResourceFactory.CreateTextureView(_imagesTextureArray);


        public void WindowResized(int width, int height)
        {
            _windowWidth = width;
            _windowHeight = height;
        }

        public void DestroyDeviceObjects()
        {
            Dispose();
        }

        public void PushOriginalFont()
        {
            ImGui.PushFont(_originalFont);
        }
        public void PushUnicodeFont()
        {
            ImGui.PushFont(_unicodeFont);
        }
        public void PushBigIconFont()
        {
            ImGui.PushFont(_iconsLargeFont);
        }

        public void CreateDeviceResources(GraphicsDevice gd, OutputDescription outputDescription)
        {
            _gd = gd;
            ResourceFactory factory = gd.ResourceFactory;
            //can fail if we run out of graphics memory
            _vertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(gd, 200000, BufferUsage.VertexBuffer | BufferUsage.Dynamic, name: "ImGui.NET Vertex Buffer");
            _indexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(gd, 2000, BufferUsage.IndexBuffer | BufferUsage.Dynamic, name: "ImGui.NET Index Buffer");
            RecreateFontDeviceTexture(gd);
            _projMatrixBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(gd, 64, BufferUsage.UniformBuffer | BufferUsage.Dynamic, name: "ImGui.NET Projection Buffer");

            byte[] vertexShaderBytes = LoadEmbeddedShaderCode(gd.ResourceFactory, "imgui-vertex", ShaderStages.Vertex);
            byte[] fragmentShaderBytes = LoadEmbeddedShaderCode(gd.ResourceFactory, "imgui-frag", ShaderStages.Fragment);
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

            ResourceLayout _fontLayout = factory.CreateResourceLayout(new ResourceLayoutDescription(
     new ResourceLayoutElementDescription("FontTexture", ResourceKind.TextureReadOnly, ShaderStages.Fragment)));
            _fontTextureResourceSet = factory.CreateResourceSet(new ResourceSetDescription(_fontLayout, _fontTextureView));
            _fontTextureResourceSet.Name = "ImGuiControllerMainFont";
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
            if (!_autoViewsByTexture.TryGetValue(texture, out TextureView textureView))
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

        List<Tuple<IDisposable, DateTime>> expiredResources = new List<Tuple<IDisposable, DateTime>>();

        // my attempts to stem this minor potential memory leak have failed in crashes so far
        // try to avoid calling GetOrCreateImGuiBinding with too many different things (ie: reuse texture rather than recreate each frame)
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
                Logging.RecordLogEvent($"Housekeeping removed {removed.Count} cached items, {_autoViewsByTexture.Count} active remaining", Logging.LogFilterType.TextDebug);
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

        public byte[] LoadEmbeddedShaderCode(ResourceFactory factory, string name, ShaderStages stage)
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

        private byte[] GetEmbeddedResourceBytes(string resourceName)
        {
            Assembly assembly = typeof(ImGuiController).Assembly;

            using Stream resourceStream = assembly.GetManifestResourceStream(resourceName);
            if (resourceStream == null)
            {
                Logging.RecordLogEvent("ERROR: Failed to find resource " + resourceName, filter: Logging.LogFilterType.TextError);
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
            ImGuiIOPtr io = ImGui.GetIO();
            // Build
            io.Fonts.GetTexDataAsRGBA32(out IntPtr pixels, out int width, out int height, out int bytesPerPixel);
            // Store our identifier
            io.Fonts.SetTexID(_fontAtlasID);

            TextureDescription td = TextureDescription.Texture2D((uint)width, (uint)height, 1, 1, PixelFormat.R8_G8_B8_A8_UNorm, TextureUsage.Sampled);
            _fontTexture = gd.ResourceFactory.CreateTexture(td);
            _fontTexture.Name = "ImGui.NET Font Texture";
            //Crashes on veldrid versions before 2019 with 4096**2 textures
            gd.UpdateTexture(
                texture: _fontTexture, source: pixels, sizeInBytes: (uint)(bytesPerPixel * width * height),
                x: 0, y: 0, z: 0, width: (uint)width,
                height: (uint)height, depth: 1, mipLevel: 0, arrayLayer: 0);
            _fontTextureView = gd.ResourceFactory.CreateTextureView(_fontTexture);

            io.Fonts.ClearTexData();


        }

        /// <summary>
        /// Renders the ImGui draw list data.
        /// This method requires a <see cref="GraphicsDevice"/> because it may create new DeviceBuffers if the size of vertex
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
        /// Updates ImGui input and IO configuration state.
        /// </summary>
        public void Update(float deltaSeconds, InputSnapshot snapshot)
        {
            if (_frameBegun)
            {
                ImGui.Render();
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
                _windowWidth / _scaleFactor.X,
                _windowHeight / _scaleFactor.Y);
            io.DisplayFramebufferScale = _scaleFactor;
            io.DeltaTime = deltaSeconds; // DeltaTime is in seconds.
            io.ConfigFlags |= ImGuiConfigFlags.DockingEnable; //doesnt work yet?
        }

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
            if (totalVBSize > _vertexBuffer.SizeInBytes)
            {
                Logging.RecordLogEvent($"ExpandGraphicsBuffers() Resizing Vertex buffer from {_vertexBuffer.SizeInBytes} to {totalVBSize * 1.5f}", Logging.LogFilterType.TextDebug);
                gd.DisposeWhenIdle(_vertexBuffer);
                _vertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(gd, (uint)(totalVBSize * 1.5f), BufferUsage.VertexBuffer | BufferUsage.Dynamic, name: _vertexBuffer.Name);
            }

            uint totalIBSize = (uint)(draw_data.TotalIdxCount * sizeof(ushort));
            if (totalIBSize > _indexBuffer.SizeInBytes)
            {
                Logging.RecordLogEvent($"ExpandGraphicsBuffers() Resizing Index buffer from {_indexBuffer.SizeInBytes} to {totalIBSize * 1.5f}", Logging.LogFilterType.TextDebug);
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
            _vertexBuffer.Dispose();
            _indexBuffer.Dispose();
            _projMatrixBuffer.Dispose();
            _fontTexture.Dispose();
            _fontTextureView.Dispose();
            _vertexShader.Dispose();
            _fragmentShader.Dispose();
            _layout.Dispose();
            _textureLayout.Dispose();
            _pipeline.Dispose();
            _mainResourceSet.Dispose();
            _imagesTextureArray.Dispose();

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
    }
}
