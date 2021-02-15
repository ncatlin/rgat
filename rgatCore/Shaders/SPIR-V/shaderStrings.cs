using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore.Shaders.SPIR_V
{
    class ShaderStrings
    {

/*
* 
* Display node points for instructions
* 
*/
        public const string vsnodeglsl = @"
#version 450
#extension GL_ARB_separate_shader_objects : enable
#extension GL_ARB_shading_language_420pack : enable


layout(location = 0) in vec2 Position;
layout(location = 1) in vec4 Color;
layout(location = 0) out vec4 vColor;
layout(location = 1) out vec2 vPosition;

layout(set = 0, binding=0) uniform ParamsBuf
{
    mat4 modelViewMatrix;
    mat4 projectionMatrix;
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

    vec3 nodePosition = positionTexture[index].xyz;
    vPosition = Position;

    float nodeSize = 150.0;
    gl_Position =  modelViewMatrix * vec4(nodePosition,1);
    float mush = nodeSize / length(gl_Position.xyz);
    gl_PointSize = nodeAttribTexture[index].x * mush;
}

";

        public const string fsnodeglsl = @"
#version 430

layout(location = 0) in vec4 fsin_Color;
layout(location = 1) in vec2 fsin_Position;
layout(location = 0) out vec4 fsout_Color;

layout(set = 0, binding=0) uniform ParamsBuf
{
    mat4 modelViewMatrix;
    mat4 projectionMatrix;
    uint TexWidth;
    int pickingNodeID;
    bool isAnimated;
};
layout(set = 0, binding=1) uniform sampler nodeTexView; //point sampler
layout(set = 1, binding=1) uniform texture2D nodeTex;   //sphere graphic


void main() 
{

        //draw the sphere texture over the node point
        vec4 node = texture(sampler2D(nodeTex, nodeTexView), gl_PointCoord);
        fsout_Color = vec4( fsin_Color.xyzw ) * node;
}
";

        /*
        * 
        * Picking node points for mousing over instruction verts
        * 
        */


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
    mat4 modelViewMatrix;
    mat4 projectionMatrix;
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
    vec3 nodePosition = positionTexture[index].xyz;
    gl_Position =  modelViewMatrix * vec4(nodePosition,1);
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
        public const string vsedgeglsl = @"
#version 450
#extension GL_ARB_separate_shader_objects : enable
#extension GL_ARB_shading_language_420pack : enable


layout(location = 0) in vec2 Position;
layout(location = 1) in vec4 Color;
layout(location = 0) out vec4 vColor;

layout(set = 0, binding=0) uniform ViewBuffer
{
    mat4 modelViewMatrix;
    mat4 projectionMatrix;
    uint TexWidth;
    int pickingNodeID;
    bool isAnimated;
};
layout(set = 0, binding=2) buffer bufpositionTexture{  vec4 positionTexture[];};

layout(set = 1, binding=0) buffer bufnodeAttribTexture{ vec4 nodeAttribTexture[];};



void main() {

    uint index = uint(Position.y * TexWidth + Position.x);
    //if (nodeAttribTexture[index].z > 0 )

    /*
        each edge has two verts, one for each node
    */    
    vColor = vec4(Color.xyz, nodeAttribTexture[index].y);

    vec3 nodePosition = positionTexture[index].xyz;
    gl_Position =  modelViewMatrix * vec4(nodePosition,1);
    
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
    mat4 modelViewMatrix;
    mat4 projectionMatrix;
    uint TexWidth;
    int pickingNodeID;
};
layout(set = 0, binding=1) uniform sampler nodeTexView; //point sampler
layout(set = 0, binding=2) buffer bufpositionTexture{
    vec4 positionTexture[];
};

void main()
{
    vec3 nodePosition = positionTexture[nodeIdx].xyz;
    gl_Position = modelViewMatrix * (vec4(nodePosition.x,nodePosition.y + yOffset,nodePosition.z, 1.0)) +  projectionMatrix * vec4(vertex.x,vertex.y,0,0);

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
