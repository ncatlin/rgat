#version 430

layout(location = 0) in vec3 fsin_Color;
//layout(location = 1) in float fsin_Opacity;
layout(location = 1) out vec4 fsout_Color;

layout(set = 0, binding = 3) uniform ViewBuffer
{
    mat4 modelViewMatrix;
    mat4 projectionMatrix;
    bool isAnimated;
};


void main() {
    if (isAnimated)
        fsout_Color = vec4( fsin_Color, 0.2 );
    else
        fsout_Color = vec4( fsin_Color, 1.0 );

}