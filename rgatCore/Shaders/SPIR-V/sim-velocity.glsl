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
layout(set = 0, binding=2) buffer bufPresetPositions{   
    vec4 presetPositions[];
};
layout(set = 0, binding=3) buffer bufvelocities {   
    vec4 velocities[];
};
//edge data offsets
layout(set = 0, binding=4) buffer bufedgeIndices {   
    ivec2 edgeIndices[];
};
//edge data 
layout(set = 0, binding=5) buffer bufedgeTargets {   
    uint edgeTargets[];
};
layout(set = 0, binding=6) buffer bufEdgeStrengths {   
    float edgeStrengths[];
};

/*
one entry for each node, describing the block its in
x = blockid, so nodes in each block can attract each other
y = top/bottom flag, so we know to apply gravity 
z = pseudo node id, used for the center node to perform the attractions of the actual edge (this will usually be the id of the top node)
w = pseudo node id, used for the center node to perform the attractions of the actual edge (this will usually be the id of the base node)
*/

layout(set = 0, binding=7) buffer blockDataBuf {   
    ivec4 blockData[];
};

layout(set = 0, binding=8) buffer resultData
{
    vec4 field_Destination[];
};



vec4 getNeighbor(uint bufferIndex){
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
    if (neighbor.w == -1) return vec3(0,0,0); 
    vec3 diff = self.xyz - neighbor.xyz;
    float x = length( diff );
    float f = ( fieldParams.repulsionK * fieldParams.repulsionK ) / max(x, 0.001);
    return normalize(diff) * f;
}


//fa(x) = (x*x)/k;
vec3 addAttraction(vec4 self, vec4 neighbor, int edgeIndex){

    if (neighbor.w == -1) return vec3(0,0,0); 
    vec3 diff = self.xyz - neighbor.xyz;
    float x = length( diff );
    float f = ( x * x ) / fieldParams.attractionK;
   // f *= edgeStrengths[edgeIndex];


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
    uint index = id.y * 256 + id.x;

    if (index < fieldParams.nodeCount)
    {

        vec4 selfPosition = positions[index];
        vec4 presetLayoutPosition = presetPositions[index];
        vec3 selfVelocity = velocities[index].xyz;
        vec3 velocity = selfVelocity;

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

         if ( selfPosition.w > 0)// && (selfPosition.w < 2 || fieldParams.fixedInternalNodes == 0)) 
         {
            //move towards preset layout position
            if ( fieldParams.snapToPreset >= 1.0) 
            {
     
                // node needs to move towards destination.
                float distFromDest = distance(presetLayoutPosition.xyz, selfPosition.xyz);
            
                if (distFromDest > 0.001) 
                {
                    float speed = distFromDest/10;
                    if (speed < 10) speed = distFromDest;
                    velocity -= addProportionalAttraction(selfPosition.xyz, presetLayoutPosition, distFromDest/10);
                }
                velocity *= 0.75;
            } 
            else 
            {
            
                // force-directed n-body simulation

                //first repel every node away from each other
                
                for(uint nodeIndex = 0; nodeIndex < fieldParams.nodeCount; nodeIndex++)
                {
                  velocity += addRepulsion(selfPosition,  positions[nodeIndex]);
                }
           


                //now iterate over each edge, attracting every connected node towards each other
                //this loop has low impact on throughput (50-150k nodes/second)    
                vec2 selfEdgeIndices = edgeIndices[index];
                float start = selfEdgeIndices.x;
                float end = selfEdgeIndices.y;

                if(start != -1) //todo: get rid of this by making start == end?
                {
                    for(int edgeIndex  = int(start); edgeIndex < end; edgeIndex++)
                    {
                        uint neighbour = edgeTargets[edgeIndex];
                        nodePosition = positions[neighbour];
                        velocity -= addAttraction(selfPosition, nodePosition, int(edgeIndex));
                    
                    }
                }
                     
            
                // temperature gradually cools down to zero
                velocity = normalize(velocity) * fieldParams.temperature;

                // Speed Limits
                //if ( length( velocity ) > speedLimit ) 
               // {
                //    velocity = normalize( velocity ) * speedLimit;
               /// }
            }
        }
    
        // add friction
        velocity *= 0.25;
    
    
        //debugging

        field_Destination[index] = vec4(velocity,  outputDebug);//velocities[index].w);
    }
}

