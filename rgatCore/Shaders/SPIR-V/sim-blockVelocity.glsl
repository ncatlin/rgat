/*
Copyright (c) 2014-2015, MetaStack Inc.
All rights reserved.

Copied from https://github.com/jaredmcqueen/analytics

Diff with the December 2015 commit to see rgat modifications

See included licence: METASTACK ANALYTICS LICENSE

To compile:
    glslangValidator.exe  -V sim-blockVelocity.glsl -o sim-blockVelocity.spv -S comp
*/
#version 450
#extension GL_ARB_separate_shader_objects : enable
#extension GL_ARB_shading_language_420pack : enable

struct VelocityParams
{
    float temperature;
    float repulsionK;
    uint blockCount;
};
struct EDGE_INDEX_LIST_OFFSETS{ int FirstEdgeIndex;  int LastEdgeIndex; };

/*
one entry for each node, describing the block its in
x = blockid, so nodes in each block can attract each other
y = top/bottom flag, so we know to apply gravity 
z = pseudo node id, used for the center node to perform the attractions of the actual edge (this will usually be the id of the top node)
w = pseudo node id, used for the center node to perform the attractions of the actual edge (this will usually be the id of the base node)
*/


struct BLOCK_METADATA{  int BlockID;  int OffsetFromCenterNode;  int CenterBlockTopEdges; int CenterBlockLastEdges; };

layout(set = 0, binding=0) uniform Params {  VelocityParams fieldParams;};
layout(set = 0, binding=1) buffer bufPositions{  vec4 positions[];};
layout(set = 0, binding=2) buffer bufvelocities {  vec4 velocities[];};
layout(set = 0, binding=3) buffer bufedgeIndices {   EDGE_INDEX_LIST_OFFSETS edgeIndices[];}; //edge data offsets
layout(set = 0, binding=4) buffer bufedgeTargets {   uint edgeTargets[];}; //edge data list (node->(node,node,node)) 
layout(set = 0, binding=5) buffer bufEdgeStrengths { float edgeStrengths[];};
layout(set = 0, binding=6) buffer blockDataBuf { BLOCK_METADATA blockData[];};
layout(set = 0, binding=7) buffer blockMiddlesBuf { int blockMiddles[];};
layout(set = 0, binding=8) buffer resultData { vec4 field_Destination[];};



vec4 getNeighbor(uint bufferIndex){
    return positions[bufferIndex];
}


//fr(x) = (k*k)/x;
vec3 addRepulsion(vec4 self, vec4 neighbor){
    //if (neighbor.w == -1) return vec3(0,0,0); 
    vec3 diff = self.xyz - neighbor.xyz;
    float x = length( diff );
    float f = ( fieldParams.repulsionK * fieldParams.repulsionK ) / max(x, 0.001);
    return normalize(diff) * f * 100;
}


//fa(x) = (x*x)/k;
vec3 addAttraction(vec4 self, vec4 neighbor, int edgeIndex){

    if (neighbor.w == -1) return vec3(0,0,0); 
    vec3 diff = self.xyz - neighbor.xyz;
    float x = length( diff );
    float f = ( x * x ) / fieldParams.repulsionK;
    f *= edgeStrengths[edgeIndex];
  
    return normalize(diff) * f;
}

// Not used, experiementing with biasing the graph to flow downwards
vec3 addWorldGravity(vec4 self, float force)
{

    vec3 bodyAbove = self.xyz;
    bodyAbove.y += force;
    vec3 diff = self.xyz - bodyAbove.xyz;
    float x = length( diff );
    float f = ( x * x ) / fieldParams.repulsionK;
    vec3 normalised = normalize(diff) * f;

   return normalised;
}


layout (local_size_x = 256) in;

void main()	{

    uint midListIndex = gl_GlobalInvocationID.x;
    if (midListIndex < fieldParams.blockCount)
    {

        vec4 nodePosition;

        const float speedLimit = 100000.0;
        float outputDebug = 0;
      
        int index = blockMiddles[midListIndex];
        BLOCK_METADATA selfBlockData = blockData[index];
        vec3 velocity = velocities[index].xyz;
        vec4 selfPosition = positions[index];

        //first repel 
        for(uint nodeIdx = 0; nodeIdx < fieldParams.blockCount; nodeIdx++)
        {
            if (nodeIdx != midListIndex)
            {
                int compareNodeMidIndex = blockMiddles[nodeIdx];
                vec4 compareNodePosition = positions[compareNodeMidIndex];
                velocity += addRepulsion(selfPosition, compareNodePosition);
           }
		}
            
            
        //anchor the first block to the center of the space
        if (midListIndex == 0)
        {
            velocity -= addAttraction(selfPosition, vec4(0,0,0,0), 1);
        }
        
        //attract this center node towards any blocks linked to the top node 
        EDGE_INDEX_LIST_OFFSETS topEdgeIndices = edgeIndices[selfBlockData.CenterBlockTopEdges];
        if(topEdgeIndices.FirstEdgeIndex != -1)
        {
            for(int edgeIndex  = int(topEdgeIndices.FirstEdgeIndex); edgeIndex < topEdgeIndices.LastEdgeIndex; edgeIndex++)
            {
                uint neighbourID = edgeTargets[edgeIndex];
                nodePosition = positions[neighbourID];
                BLOCK_METADATA neighborBlockData = blockData[neighbourID];
                if (neighborBlockData.BlockID != selfBlockData.BlockID)
                { 
                   velocity -= addAttraction(selfPosition, nodePosition, int(edgeIndex));
                }
            }
        }

        //attract this center node towards any blocks linked to the base node 
        EDGE_INDEX_LIST_OFFSETS baseEdgeIndices = edgeIndices[selfBlockData.CenterBlockLastEdges];
        if(baseEdgeIndices.FirstEdgeIndex != -1)
        {
            for(int edgeIndex  = int(baseEdgeIndices.FirstEdgeIndex); edgeIndex < baseEdgeIndices.LastEdgeIndex; edgeIndex++)
            {
                uint neighbourID = edgeTargets[edgeIndex];
                nodePosition = positions[neighbourID];
                BLOCK_METADATA neighborBlockData = blockData[neighbourID];
                //attract center of this block to center of another block (not this block)
                if (neighborBlockData.BlockID != selfBlockData.BlockID)
                {
                    velocity -= addAttraction(selfPosition, nodePosition, int(edgeIndex));                
                }
            }
        }
        

                  
        // temperature gradually cools down to zero

        velocity = normalize(velocity) * fieldParams.temperature;

        // Speed Limits
        if ( length( velocity ) > speedLimit ) 
        {
            velocity = normalize( velocity ) * speedLimit;
        }
    
        // add friction
        velocity *= 0.25;
    
    
        field_Destination[index] = vec4(velocity,  outputDebug);
    }
}

