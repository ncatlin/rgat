#version 430

layout(location = 0) in vec2 texPos;
layout(location = 1) in vec3 customColor;

layout(set = 0, binding=0) buffer bufpositionTexture{
    vec4 positionTexture[];
};
layout(set = 0, binding=1) buffer bufnodeAttribTexture{
    vec4 nodeAttribTexture[];
};
layout(set = 0, binding = 3) uniform ViewBuffer
{
    mat4 modelViewMatrix;
    mat4 projectionMatrix;
};

//varying vec3 vColor;
//varying float vOpacity;

void main() {

    //vColor = customColor;

    //vec3 nodePosition = texture( sampler2D(positionTexture, positionsView) , texPos ).xyz;
    uint index = uint(texPos.y * 4 + texPos.x);
    vec3 nodePosition = positionTexture[index].xyz;
    //vec4 selfAttrib = texture( sampler2D(nodeAttribTexture, positionsView) , texPos );
    //vOpacity = selfAttrib.y;

    vec4 mvPosition = modelViewMatrix * vec4( nodePosition, 1.0 );
    gl_Position = projectionMatrix * mvPosition;

}
