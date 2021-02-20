/*
Copyright (c) 2014-2015, MetaStack Inc.
All rights reserved.

Copied from https://github.com/jaredmcqueen/analytics

Diff with the December 2015 commit to see rgat modifications

See included licence: METASTACK ANALYTICS LICENSE
*/

/*
to compile 

C:\Users\nia\Desktop\rgatstuff\gslangvalidator\bin\glslangValidator.exe  -V C:\Users\nia\Source\Repos\rgatCore\rgatCore\Shaders\SPIR-V\sim-position.glsl -o sim-position.spv -S comp
*/

#version 450


struct PositionParams
{
    float delta;
    uint nodesTexWidth;
};

layout(set = 0, binding=0) uniform Params 
{
    PositionParams fieldParams;
};
layout(set = 0, binding=1) buffer bufpositions{vec4 positions[];};
layout(set = 0, binding=2) buffer  bufvelocities{vec4 velocities[];};
layout(set = 0, binding=3) buffer resultData
{
    vec4 field_Destination[];

};

void main()	{

    uvec3 id = gl_GlobalInvocationID;    
    uint index = id.y * fieldParams.nodesTexWidth + id.x;
    vec4 selfPosition = positions[index];    
    vec3 selfVelocity = velocities[index].xyz;

    vec4 res = vec4( selfPosition.xyz + selfVelocity * fieldParams.delta * 50.0, selfPosition.w );
    field_Destination[index] = res;

}