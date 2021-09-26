/*
Copyright (c) 2014-2015, MetaStack Inc.
All rights reserved.

Copied from https://github.com/jaredmcqueen/analytics

Diff with the December 2015 commit to see rgat modifications

See included licence: METASTACK ANALYTICS LICENSE
*/
/*
C:\Users\nia\Desktop\rgatstuff\gslangvalidator\bin\glslangValidator.exe  -V C:\Users\nia\Source\Repos\rgatPrivate\rgatCore\Shaders\SPIR-V\sim-velocity.glsl -o sim-velocity.spv -S comp
*/
#version 450
#extension GL_ARB_separate_shader_objects : enable
#extension GL_ARB_shading_language_420pack : enable

struct VelocityParams
{
    float delta; //not used
    float temperature;
    float attractionK;
    float repulsionK;

    uint fixedInternalNodes;
    uint snapToPreset;
    uint nodeCount;
};

layout(set = 0, binding=0) uniform Params 
{
    VelocityParams fieldParams;
};
layout(set = 0, binding=1) buffer bufPositions{
    vec4 positions[];
};

layout(set = 0, binding=2) buffer bufvelocities {   
    vec4 velocities[];
};
//edge data offsets
layout(set = 0, binding=3) buffer bufedgeIndices {   
    ivec2 edgeIndices[];
};
//edge data 
layout(set = 0, binding=4) buffer bufedgeTargets {   
    uint edgeTargets[];
};
layout(set = 0, binding=5) buffer bufEdgeStrengths {   
    float edgeStrengths[];
};

/*
one entry for each node, describing the block its in
x = blockid, so nodes in each block can attract each other
y = top/bottom flag, so we know to apply gravity 
z = pseudo node id, used for the center node to perform the attractions of the actual edge (this will usually be the id of the top node)
w = pseudo node id, used for the center node to perform the attractions of the actual edge (this will usually be the id of the base node)
*/

layout(set = 0, binding=6) buffer blockDataBuf {   
    ivec4 blockData[];
};

layout(set = 0, binding=7) buffer blockMiddlesBuf {   
    int blockMiddles[];
};

layout(set = 0, binding=8) buffer resultData
{
    vec4 field_Destination[];
};



vec4 getNeighbor(uint bufferIndex){
    //vec2 uv = vec2(((mod(textureIndex, fieldParams.nodesTexWidth)) / fieldParams.nodesTexWidth), (floor(textureIndex / fieldParams.nodesTexWidth) / fieldParams.nodesTexWidth));
    //vec4  r =  texture(sampler2D(positions, positionsView), uv );
    
    return positions[bufferIndex];
}



vec3 addRepulsionOriginal(vec4 self, vec4 neighbor, float multiplier){
    if (neighbor.w == -1) return vec3(0,0,0); 
    vec3 diff = self.xyz - neighbor.xyz;
    float x = length( diff );
   float f = ( fieldParams.repulsionK * fieldParams.repulsionK ) / max(x, 0.001);
    return normalize(diff) * f * multiplier;
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
    float f = ( x * x ) / fieldParams.attractionK;
    f *= edgeStrengths[edgeIndex];


    return normalize(diff) * f;
}


vec3 addWorldGravity(vec4 self, float force)
{

    vec3 bodyAbove = self.xyz;
    bodyAbove.y += force;
    vec3 diff = self.xyz - bodyAbove.xyz;
    float x = length( diff );
    float f = ( x * x ) / fieldParams.attractionK;
    vec3 normalised = normalize(diff) * f;

  
   return normalised;

}

vec3 addProportionalAttraction(vec3 self, vec4 neighbor, float speed){
    if (neighbor.w == -1) return vec3(0,0,0); 
    vec3 diff = self - neighbor.xyz;    
    return normalize(diff) * speed;
}


layout (local_size_x = 256) in;

void main()	{

    
    uvec3 id = gl_GlobalInvocationID;

    uint midListIndex =id.x;//id.y * 256 + id.x;
    if (midListIndex < fieldParams.nodeCount)
    {

        vec4 nodePosition;

        const float speedLimit = 100000.0;
        float attct = 0;
        float outputDebug = -100;
     
         /*
         .w presetLayoutPosition values
     
            -1 = not a node
             0 = internal block node, fixed position from parent
             1 = preset, simple attraction towards target
             2 = free body subject to standard forces
         */

  
        int index = blockMiddles[midListIndex];
        ivec4 selfBlockData = blockData[index];
        vec3 velocity = velocities[index].xyz;
        vec4 selfPosition = positions[index];


        //first repel 
        for(uint nodeIdx = 0; nodeIdx < fieldParams.nodeCount; nodeIdx++)
        {
            int compareNodeMidIndex = blockMiddles[nodeIdx];
            if (compareNodeMidIndex != midListIndex)
            {
            vec4 compareNodePosition = positions[compareNodeMidIndex];
            
            //if distance below threshold, repel every node from every single node
            //if (distance(compareNodePosition.xyz, selfPosition.xyz) > 0.001) 
            //{
                velocity += addRepulsion(selfPosition, compareNodePosition);
            //}
           }
		}
            


        //now attract
        //vec2 selfEdgeIndices = edgeIndices[index];
        //float start = selfEdgeIndices.x;
        //float end = selfEdgeIndices.y;

        /*
        blockdata.x = index of block
        blockdata.y = count of how many nodes from this node to center of block node
        blockdata.z = first node in block  [set only for mid node]
        blockdata.w = last node in block [set only for mid node]
        */
              
             
        //attract any blocks linked to the base node towards this center node
        vec2 baseEdgeIndices = edgeIndices[selfBlockData.z];
        float start = baseEdgeIndices.x;
        float end = baseEdgeIndices.y;
        if(start != -1)
        {
            for(int edgeIndex  = int(start); edgeIndex < end; edgeIndex++)
            {
                uint neighbourID = edgeTargets[edgeIndex];
                nodePosition = positions[neighbourID];
                vec4 neighborBlockData = blockData[neighbourID];
                //attract center of this block to center of another block (not this block)
                if (neighborBlockData.z != -1 && neighborBlockData.x != selfBlockData.x)
                {
                    vec3 resvel = addAttraction(selfPosition, nodePosition, int(edgeIndex));
                    velocity -= resvel;
                }
            }
        }
                               
                              
        //attract any blocks linked to the top node towards this center node 
        vec2 topEdgeIndices = edgeIndices[selfBlockData.w];
        start = topEdgeIndices.x;
        end = topEdgeIndices.y;
        if(start != -1)
        {
            for(int edgeIndex  = int(start); edgeIndex < end; edgeIndex++)
            {
                uint neighbourID = edgeTargets[edgeIndex];
                nodePosition = positions[neighbourID];
                vec4 neighborBlockData = blockData[neighbourID];
                //attract center to another block
                if (neighborBlockData.x != selfBlockData.x)
                {
                    vec3 resvel = addAttraction(selfPosition, nodePosition, int(edgeIndex));
                    velocity -= resvel;
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
    
    
        //debugging

        field_Destination[index] = vec4(velocity,  181);//velocities[index].w);
    }
}
