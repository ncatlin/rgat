#version 430

layout(location = 0) in vec3 fsin_Color;
//layout(location = 1) in float fsin_Opacity;
layout(location = 1) out vec4 fsout_Color;

void main() {
    fsout_Color = vec4( fsin_Color, 1.0 );
}