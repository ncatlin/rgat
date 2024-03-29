/*
Copyright (c) 2014-2015, MetaStack Inc.
All rights reserved.

Vulkanised from https://github.com/jaredmcqueen/analytics/blob/7fa833bb07e2f145dba169b674f8865566970a68/shaders/sim-velocity.glslc

See included licence: METASTACK ANALYTICS LICENSE
*/

/*
C:\Users\nia\Desktop\rgatstuff\gslangvalidator\bin\glslangValidator.exe  -V C:\Users\nia\Source\Repos\rgatPrivate\rgatCore\Shaders\SPIR-V\sim-presetVelocity.glsl -o sim-presetVelocity.spv -S comp
*/

#version 450
#extension GL_ARB_separate_shader_objects : enable
#extension GL_ARB_shading_language_420pack : enable

struct VelocityParams
{
    uint nodeCount;
    float speedDivisor;
};

layout(set = 0, binding=0) uniform Params { VelocityParams fieldParams;};
layout(set = 0, binding=1) buffer bufPositions{ vec4 positions[];};
layout(set = 0, binding=2) buffer bufPresetPositions{ vec4 presetPositions[];};
layout(set = 0, binding=3) buffer bufvelocities { vec4 velocities[];};
layout(set = 0, binding=4) buffer resultData{ vec4 field_Destination[];};


vec3 addProportionalAttraction(vec3 self, vec4 neighbor, float speed){
    if (neighbor.w == -1) return vec3(0,0,0); 
    vec3 diff = self - neighbor.xyz;    
    return normalize(diff) * speed;
}


layout (local_size_x = 256) in;

void main()	{

    //uvec3 id = gl_GlobalInvocationID;
    uint index = gl_GlobalInvocationID.x;

    if (index < fieldParams.nodeCount)
    {
        vec4 selfPosition = positions[index];
        vec4 presetLayoutPosition = presetPositions[index];
        vec3 selfVelocity = velocities[index].xyz;
        vec3 velocity = selfVelocity;
        vec4 nodePosition;
        float outputDebug = -100;

        // node needs to move towards destination.
        float distFromDest = distance(presetLayoutPosition.xyz, selfPosition.xyz);
            
        if (distFromDest > 0.001) 
        {
            float speed = distFromDest/fieldParams.speedDivisor;
            //if (speed < 10) speed = distFromDest;
            outputDebug = fieldParams.speedDivisor;
            velocity -= addProportionalAttraction(selfPosition.xyz, presetLayoutPosition, speed);
        }
        velocity *= 0.75;
            
    
        // add friction
        velocity *= 0.25;
    
        field_Destination[index] = vec4(velocity,  outputDebug);
    }
}

