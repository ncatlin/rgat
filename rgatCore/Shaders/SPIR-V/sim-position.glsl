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
    float blockNodeSeperation;
    uint fixedInternalNodes;
    bool activatingPreset;
};

layout(set = 0, binding=0) uniform Params 
{
    PositionParams fieldParams;
};
layout(set = 0, binding=1) buffer bufpositions{vec4 positions[];};
layout(set = 0, binding=2) buffer  bufvelocities{vec4 velocities[];};
layout(set = 0, binding=3) buffer blockDataBuf {   
    ivec4 blockData[];
};
layout(set = 0, binding=4) buffer resultData
{
    vec4 field_Destination[];

};


layout (local_size_x = 256) in;

void main()	{

    uvec3 id = gl_GlobalInvocationID;    
    uint index = id.x;// id.y * 256 + id.x;
    vec4 selfPosition = positions[index];    
    vec4 res;

    if (fieldParams.fixedInternalNodes == 1 && !fieldParams.activatingPreset )
    {
        
        ivec4 selfBlockData = blockData[index];
        int offsetFromCenter = selfBlockData.y;
        if (selfBlockData.y != 0)
        {
            vec4 parent = positions[index-offsetFromCenter];
            res.x = parent.x;
            res.z = parent.z;
            res.y = parent.y - offsetFromCenter*fieldParams.blockNodeSeperation;
            res.w = selfPosition.w;
        }
        else
        {
            vec3 selfVelocity = velocities[index].xyz;
            res = vec4( selfPosition.xyz + selfVelocity * fieldParams.delta * 50.0, selfPosition.w );
        }

    }
    else
    {
    
        vec3 selfVelocity = velocities[index].xyz;
        res = vec4( selfPosition.xyz + selfVelocity * fieldParams.delta * 50.0, selfPosition.w );


    }



    field_Destination[index] = res;

}