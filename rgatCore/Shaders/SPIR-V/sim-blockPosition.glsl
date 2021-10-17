/*
Copyright (c) 2014-2015, MetaStack Inc.
All rights reserved.

Code adapted from https://github.com/jaredmcqueen/analytics/blob/7fa833bb07e2f145dba169b674f8865566970a68/shaders/sim-position.glsl

Diff with the December 2015 commit to see rgat modifications

See included licence: METASTACK ANALYTICS LICENSE
*/

/*
to compile 

C:\Users\nia\Desktop\rgatstuff\gslangvalidator\bin\glslangValidator.exe  -V C:\Users\nia\Source\Repos\rgatPrivate\rgatCore\Shaders\SPIR-V\sim-position.glsl -o sim-position.spv -S comp
*/

#version 450


struct PositionParams
{
    float delta;
    uint nodeCount;
    float blockNodeSeperation;
};

struct BLOCK_METADATA{  int BlockID;  int OffsetFromCenterNode;  int CenterBlockTopEdges; int CenterBlockLastEdges; };

layout(set = 0, binding=0) uniform Params {  PositionParams fieldParams;};
layout(set = 0, binding=1) buffer bufpositions{vec4 positions[];};
layout(set = 0, binding=2) buffer  bufvelocities{vec4 velocities[];};
layout(set = 0, binding=3) buffer blockDataBuf { BLOCK_METADATA blockData[];};
layout(set = 0, binding=4) buffer resultData { vec4 field_Destination[];};


layout (local_size_x = 256) in;

void main()	{

    uint index = gl_GlobalInvocationID.x;
    if (index < fieldParams.nodeCount)
    {
        vec4 selfPosition = positions[index];    
        vec4 res;             

        BLOCK_METADATA selfBlockData = blockData[index];
        int offsetFromCenter = selfBlockData.OffsetFromCenterNode;
        if (offsetFromCenter != 0) 
        {
            //Position non-center node above/below the center node of the block it belongs to
            vec4 parent = positions[index-offsetFromCenter];
            res.x = parent.x;
            res.z = parent.z;
            res.y = parent.y - offsetFromCenter*fieldParams.blockNodeSeperation;
            res.w = selfPosition.w;
        }
        else
        {
            //standard force-directed node positioning
            res = vec4( selfPosition.xyz + velocities[index].xyz * fieldParams.delta * 50.0, selfPosition.w );
        }

        field_Destination[index] = res;
    }
}