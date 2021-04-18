using System;
using System.Collections.Generic;
using System.Text;
using Veldrid;
using Veldrid.SPIRV;

namespace rgatCore.Shaders.SPIR_V
{
    class SPIRVShaders
    {

        /*
        * 
        * Display node points for instructions
        * 
        */

        public static ShaderSetDescription CreateNodeShaders(ResourceFactory factory, out DeviceBuffer vertBuffer, out DeviceBuffer indexBuffer)
        {
            VertexElementDescription VEDpos = new VertexElementDescription("Position", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float2);
            VertexElementDescription VEDcol = new VertexElementDescription("Color", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float4);
            VertexLayoutDescription vertexLayout = new VertexLayoutDescription(VEDpos, VEDcol);

            byte[] nodeVertShaderBytes = Encoding.UTF8.GetBytes(Shaders.SPIR_V.SPIRVShaders.vsnodeglsl);
            byte[] nodeFragShaderBytes = Encoding.UTF8.GetBytes(Shaders.SPIR_V.SPIRVShaders.fsnodeglsl);
            ShaderDescription vertexShaderDesc = new ShaderDescription(ShaderStages.Vertex, nodeVertShaderBytes, "main");
            ShaderDescription fragmentShaderDesc = new ShaderDescription(ShaderStages.Fragment, nodeFragShaderBytes, "main");

            ShaderSetDescription shaderSetDesc = new ShaderSetDescription(
                vertexLayouts: new VertexLayoutDescription[] { vertexLayout },
                shaders: factory.CreateFromSpirv(vertexShaderDesc, fragmentShaderDesc));

            vertBuffer = factory.CreateBuffer(new BufferDescription(1, BufferUsage.VertexBuffer));
            indexBuffer = factory.CreateBuffer(new BufferDescription(1, BufferUsage.IndexBuffer));

            return shaderSetDesc;
        }


        public const string vsnodeglsl = @"
#version 450
#extension GL_ARB_separate_shader_objects : enable
#extension GL_ARB_shading_language_420pack : enable


layout(location = 0) in vec2 Position;
layout(location = 1) in vec4 Color;
layout(location = 0) out vec4 vColor;

layout(set = 0, binding=0) uniform ParamsBuf
{
    mat4 Projection;
    mat4 View;
    mat4 World;
    mat4 nonRotated;
    uint TexWidth;
    int pickingNodeID;
    bool isAnimated;
};
layout(set = 0, binding=2) buffer bufpositionTexture{
    vec4 positionTexture[];
};
layout(set = 1, binding=0) buffer bufnodeAttribTexture{
    vec4 nodeAttribTexture[];
};


void main() {
    uint index = uint(Position.y * TexWidth + Position.x);

    if (index == pickingNodeID){
        vColor = vec4(1.0,0.0,1.0,1.0);
    } else {
        vColor = vec4(Color.xyz, nodeAttribTexture[index].y) ;
    }



    vec4 worldPosition = World *  positionTexture[index];
    vec4 viewPosition = View * worldPosition;
    vec4 clipPosition = Projection * viewPosition;
    gl_Position = clipPosition;



    float nodeSize = 90.0;
    float relativeNodeSize = nodeSize / length(gl_Position.xyz);
    gl_PointSize = nodeAttribTexture[index].x * relativeNodeSize;
}

";

        public const string fsnodeglsl = @"
#version 430

#extension GL_EXT_nonuniform_qualifier : enable

layout(location = 0) in vec4 fsin_Color;
layout(location = 1) in vec2 fsin_Position;
layout(location = 0) out vec4 fsout_Color;

layout(set = 0, binding=0) uniform ParamsBuf
{
    mat4 Projection;
    mat4 View;
    mat4 World;
    mat4 nonRotated;
    uint TexWidth;
    int pickingNodeID;
    bool isAnimated;
};
layout(set = 0, binding=1) uniform sampler nodeTexView; //point sampler

layout(set = 1, binding=0) buffer bufnodeAttribTexture{
    vec4 nodeAttribTexture[];
};
layout(set = 1, binding=1) uniform texture2D nodeTextures; 


void main() 
{
    uint index = uint(fsin_Position.y * TexWidth + fsin_Position.x);
    float textureIdx = nodeAttribTexture[index].w;    

    //draw the sphere texture over the node point

    vec4 node = texture(sampler2D(nodeTextures, nodeTexView), vec2((gl_PointCoord.x/2)+(0.5*textureIdx), gl_PointCoord.y)); //
    fsout_Color = vec4( fsin_Color.xyzw ) * node;
}";






        /*
        * 
        * Picking node points for mousing over instruction verts
        * 
        */


        public static ShaderSetDescription CreateNodePickingShaders(ResourceFactory factory, out DeviceBuffer vertBuffer)
        {
            VertexElementDescription VEDpos = new VertexElementDescription("Position", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float2);
            VertexElementDescription VEDcol = new VertexElementDescription("Color", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float4);
            VertexLayoutDescription vertexLayout = new VertexLayoutDescription(VEDpos, VEDcol);

            byte[] vertShaderBytes = Encoding.UTF8.GetBytes(Shaders.SPIR_V.SPIRVShaders.vspickingglsl);
            byte[] fragShaderBytes = Encoding.UTF8.GetBytes(Shaders.SPIR_V.SPIRVShaders.fspickingglsl);
            ShaderDescription vertexShaderDesc = new ShaderDescription(ShaderStages.Vertex, vertShaderBytes, "main");
            ShaderDescription fragmentShaderDesc = new ShaderDescription(ShaderStages.Fragment, fragShaderBytes, "main");

            ShaderSetDescription shaderSetDesc = new ShaderSetDescription(
                vertexLayouts: new VertexLayoutDescription[] { vertexLayout },
                shaders: factory.CreateFromSpirv(vertexShaderDesc, fragmentShaderDesc));

             vertBuffer = factory.CreateBuffer(new BufferDescription(1, BufferUsage.VertexBuffer));

            return shaderSetDesc;
        }

        public const string vspickingglsl = @"
#version 450
#extension GL_ARB_separate_shader_objects : enable
#extension GL_ARB_shading_language_420pack : enable


layout(location = 0) in vec2 Position;
layout(location = 1) in vec4 Color;
layout(location = 0) out vec4 vColor;
layout(location = 1) out vec2 vPosition;

layout(set = 0, binding=0) uniform ParamsBuf
{
    mat4 Projection;
    mat4 View;
    mat4 World;
    mat4 nonRotated;
    uint TexWidth;
    int pickingNodeID;
    bool isAnimated;
};
layout(set = 0, binding=2) buffer bufpositionTexture{
    vec4 positionTexture[];
};
layout(set = 1, binding=0) buffer bufnodeAttribTexture{
    vec4 nodeAttribTexture[];
};


void main() {
    vColor = Color;
    vPosition = Position;

    uint index = uint(Position.y * TexWidth + Position.x);

    vec4 worldPosition = World *  vec4(positionTexture[index].xyz,1);
    vec4 viewPosition = View * worldPosition;
    vec4 clipPosition = Projection * viewPosition;
    gl_Position = clipPosition;

    gl_PointSize = 10;
}";


        public const string fspickingglsl = @"
    #version 430

    layout(location = 0) in vec4 fsin_Color;
    layout(location = 1) in vec2 fsin_Position;
    layout(location = 0) out vec4 fsout_Color;

    void main() 
    {
        fsout_Color = fsin_Color;
    }";


        /*
        * 
        * Edge line lists between nodes
        * 
        */
        public static ShaderSetDescription CreateEdgeRelativeShaders(ResourceFactory factory, out DeviceBuffer vertBuffer, out DeviceBuffer indexBuffer)
        {
            VertexElementDescription VEDpos = new VertexElementDescription("Position", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float2);
            VertexElementDescription VEDcol = new VertexElementDescription("Color", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float4);
            VertexLayoutDescription vertexLayout = new VertexLayoutDescription(VEDpos, VEDcol);

            byte[] vertShaderBytes = Encoding.UTF8.GetBytes(Shaders.SPIR_V.SPIRVShaders.vsedge_relative_glsl);
            byte[] fragShaderBytes = Encoding.UTF8.GetBytes(Shaders.SPIR_V.SPIRVShaders.fsedgeglsl);
            ShaderDescription vertexShaderDesc = new ShaderDescription(ShaderStages.Vertex, vertShaderBytes, "main");
            ShaderDescription fragmentShaderDesc = new ShaderDescription(ShaderStages.Fragment, fragShaderBytes, "main");

            ShaderSetDescription shaderSetDesc = new ShaderSetDescription(
                vertexLayouts: new VertexLayoutDescription[] { vertexLayout },
                shaders: factory.CreateFromSpirv(vertexShaderDesc, fragmentShaderDesc));

            vertBuffer = factory.CreateBuffer(new BufferDescription(1, BufferUsage.VertexBuffer));
            indexBuffer = factory.CreateBuffer(new BufferDescription(1, BufferUsage.IndexBuffer));

            return shaderSetDesc;
        }


        public const string vsedge_relative_glsl = @"
#version 450
#extension GL_ARB_separate_shader_objects : enable
#extension GL_ARB_shading_language_420pack : enable


layout(location = 0) in vec2 Position;
layout(location = 1) in vec4 Color;
layout(location = 0) out vec4 vColor;

layout(set = 0, binding=0) uniform ViewBuffer
{
    mat4 Projection;
    mat4 View;
    mat4 World;
    mat4 nonRotated;
    uint TexWidth;
    int pickingNodeID;
    bool isAnimated;
};

layout(set = 0, binding=2) buffer bufpositionTexture{  vec4 positionTexture[];};

layout(set = 1, binding=0) buffer bufnodeAttribTexture{ vec4 nodeAttribTexture[];};



void main() {

    uint index = uint(Position.y * TexWidth + Position.x);
    /*
        each edge has two verts, one for each node
    */    
    vColor = vec4(Color.xyz, nodeAttribTexture[index].y);

    //vec3 nodePosition = ;
    vec4 nodePos2 =  vec4(positionTexture[index].xyz,1);

    vec4 worldPosition = World *  nodePos2;
    vec4 viewPosition = View * worldPosition;
    vec4 clipPosition = Projection * viewPosition;
    gl_Position = clipPosition;
    
}

";

        public static ShaderSetDescription CreateEdgeRawShaders(ResourceFactory factory, out DeviceBuffer vertBuffer, out DeviceBuffer indexBuffer)
        {
            VertexElementDescription VEDpos = new VertexElementDescription("Position", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float4);
            VertexElementDescription VEDcol = new VertexElementDescription("Color", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float4);
            VertexLayoutDescription vertexLayout = new VertexLayoutDescription(VEDpos, VEDcol);

            byte[] vertShaderBytes = Encoding.UTF8.GetBytes(Shaders.SPIR_V.SPIRVShaders.vsedge_raw_glsl);
            byte[] fragShaderBytes = Encoding.UTF8.GetBytes(Shaders.SPIR_V.SPIRVShaders.fsedgeglsl);
            ShaderDescription vertexShaderDesc = new ShaderDescription(ShaderStages.Vertex, vertShaderBytes, "main");
            ShaderDescription fragmentShaderDesc = new ShaderDescription(ShaderStages.Fragment, fragShaderBytes, "main");

            ShaderSetDescription shaderSetDesc = new ShaderSetDescription(
                vertexLayouts: new VertexLayoutDescription[] { vertexLayout },
                shaders: factory.CreateFromSpirv(vertexShaderDesc, fragmentShaderDesc));

            vertBuffer = factory.CreateBuffer(new BufferDescription(1, BufferUsage.VertexBuffer));
            indexBuffer = factory.CreateBuffer(new BufferDescription(1, BufferUsage.IndexBuffer));

            return shaderSetDesc;
        }

        public const string vsedge_raw_glsl = @"
#version 450
#extension GL_ARB_separate_shader_objects : enable
#extension GL_ARB_shading_language_420pack : enable


layout(location = 0) in vec4 Position;
layout(location = 1) in vec4 Color;
layout(location = 0) out vec4 vColor;

layout(set = 0, binding=0) uniform ViewBuffer
{
    mat4 Projection;
    mat4 View;
    mat4 World;
    mat4 nonRotated;
    uint TexWidth;
    int pickingNodeID;
    bool isAnimated;
};
layout(set = 0, binding=2) buffer bufpositionTexture{  vec4 positionTexture[];};

void main() {

    vColor = Color;
    vec3 nodePosition;

    if (Position.w == 0){
        nodePosition = vec3(Position.xyz);
    } else {
       uint index = uint(Position.y * TexWidth + Position.x);
       nodePosition = positionTexture[index].xyz;
    }

    vec4 worldPosition = World *  vec4(nodePosition,1);
    vec4 viewPosition = View * worldPosition;
    vec4 clipPosition = Projection * viewPosition;
    gl_Position = clipPosition;

}
";

        public const string fsedgeglsl = @"
#version 430

layout(location = 0) in vec4 fsin_Color;
layout(location = 0) out vec4 fsout_Color;

void main() {
    fsout_Color = fsin_Color;
}
";




        /*
        * 
        * Font triangles
        * 
        */
        public static ShaderSetDescription CreateFontShaders(ResourceFactory factory, out DeviceBuffer vertBuffer, out DeviceBuffer indexBuffer)
        {
            VertexElementDescription nodeIdx = new VertexElementDescription("nodeIdx", VertexElementSemantic.TextureCoordinate, VertexElementFormat.UInt1);
            VertexElementDescription VEDpos = new VertexElementDescription("Position", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float3);
            VertexElementDescription Charpos = new VertexElementDescription("CharCoord", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float2);
            VertexElementDescription yoff = new VertexElementDescription("YOffset", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float1);
            VertexElementDescription fcol = new VertexElementDescription("FontColour", VertexElementSemantic.Color, VertexElementFormat.Float4);

            VertexLayoutDescription vertexLayout = new VertexLayoutDescription(nodeIdx, VEDpos, Charpos, yoff, fcol);

            byte[] vertShaderBytes = Encoding.UTF8.GetBytes(Shaders.SPIR_V.SPIRVShaders.vsfontglsl);
            byte[] fragShaderBytes = Encoding.UTF8.GetBytes(Shaders.SPIR_V.SPIRVShaders.fsfontglsl);
            ShaderDescription vertexShaderDesc = new ShaderDescription(ShaderStages.Vertex, vertShaderBytes, "main");
            ShaderDescription fragmentShaderDesc = new ShaderDescription(ShaderStages.Fragment, fragShaderBytes, "main");

            ShaderSetDescription shaderSetDesc = new ShaderSetDescription(
                vertexLayouts: new VertexLayoutDescription[] { vertexLayout },
                shaders: factory.CreateFromSpirv(vertexShaderDesc, fragmentShaderDesc));

            vertBuffer = factory.CreateBuffer(new BufferDescription(1, BufferUsage.VertexBuffer));
            indexBuffer = factory.CreateBuffer(new BufferDescription(1, BufferUsage.IndexBuffer));

            return shaderSetDesc;
        }





        public const string vsfontglsl = @"
#version 450
#extension GL_ARB_separate_shader_objects : enable
#extension GL_ARB_shading_language_420pack : enable


layout(location = 0) in uint nodeIdx;
layout(location = 1) in vec3 vertex;
layout(location = 2) in vec2 fontCrd;
layout(location = 3) in float yOffset;
layout(location = 4) in vec4 fontColour;

layout(location = 0) out vec2 texCoords;
layout(location = 1) out vec4 _outColour;


layout(set = 0, binding=0) uniform ParamsBuf
{
    mat4 Projection;
    mat4 View;
    mat4 World;
    mat4 nonRotated;
    uint TexWidth;
    int pickingNodeID;
    bool isAnimated;
};
layout(set = 0, binding=1) uniform sampler nodeTexView; //point sampler
layout(set = 0, binding=2) buffer bufpositionTexture{
    vec4 positionTexture[];
};

void main()
{

        vec3 nodePosition = positionTexture[nodeIdx].xyz;


        vec4 worldPosition = World *   (vec4(nodePosition.x,nodePosition.y + yOffset,nodePosition.z, 1.0));
        vec4 viewPosition = View * worldPosition;
        vec4 clipPosition = Projection * viewPosition;

        vec4 pos2 = nonRotated * vec4(vertex.x,vertex.y,0,0);

        gl_Position = clipPosition + pos2;

        texCoords = fontCrd;
        _outColour = fontColour;
    
}  
";

        public const string fsfontglsl = @"
#version 450
layout(location = 0) in vec2 TexCoords;
layout(location = 1) in vec4 TexColor;

layout(location = 0) out vec4 color;

layout(set = 0, binding=1) uniform sampler pointSampler; //point sampler
layout(set = 1, binding=0) uniform texture2D fontTexture;   //font graphic

void main()
{   
    vec4 sampled =  texture(sampler2D(fontTexture, pointSampler), TexCoords);
    color = TexColor * sampled;
}  
";





     

    }
}
