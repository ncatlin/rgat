/*
Copyright (c) 2014-2015, MetaStack Inc.
All rights reserved.

Code vulkanised from https://github.com/jaredmcqueen/analytics/blob/7fa833bb07e2f145dba169b674f8865566970a68/shaders/sim-position.glsl

See included licence: METASTACK ANALYTICS LICENSE

to compile 

glslangValidator.exe  -V sim-nodePosition.glsl -o sim-nodePosition.spv -S comp
*/

#version 450

struct PositionParams
{
    float delta;
    uint nodeCount;
};
layout(set = 0, binding=0) uniform Params{  PositionParams fieldParams;};
layout(set = 0, binding=1) buffer bufpositions{vec4 positions[];};
layout(set = 0, binding=2) buffer bufvelocities{vec4 velocities[];};
layout(set = 0, binding=3) buffer resultData{  vec4 field_Destination[];};


layout (local_size_x = 256) in;

void main()	{ 
    uint index = gl_GlobalInvocationID.x;

    if (index < fieldParams.nodeCount)
    {
        vec4 selfPosition = positions[index];    
        field_Destination[index] = vec4( selfPosition.xyz + velocities[index].xyz * fieldParams.delta * 50.0, selfPosition.w );
    }
}