/*
Copyright (c) 2014-2015, MetaStack Inc.
All rights reserved.

Adapted from https://github.com/jaredmcqueen/analytics/blob/7fa833bb07e2f145dba169b674f8865566970a68/shaders/sim-velocity.glsl

See included licence: METASTACK ANALYTICS LICENSE

C:\Users\nia\Desktop\rgatstuff\gslangvalidator\bin\glslangValidator.exe -V C:\Users\nia\Source\Repos\rgatPrivate\rgatCore\Shaders\SPIR-V\sim-nodeVelocity.glsl -o sim-nodeVelocity.spv -S comp
*/

#version 450
#extension GL_ARB_separate_shader_objects : enable
#extension GL_ARB_shading_language_420pack : enable

struct VelocityParams
{
    float delta; //not used
    float temperature;
    float repulsionK;
    uint nodeCount;
};
struct EDGE_INDEX_LIST_OFFSETS{ int FirstEdgeIndex;  int LastEdgeIndex; };

layout(set = 0, binding=0) uniform Params { VelocityParams fieldParams;};
layout(set = 0, binding=1) buffer bufPositions{ vec4 positions[];};
layout(set = 0, binding=2) buffer bufPresetPositions{ vec4 presetPositions[];};
layout(set = 0, binding=3) buffer bufvelocities { vec4 velocities[];};
layout(set = 0, binding=4) buffer bufedgeIndices { EDGE_INDEX_LIST_OFFSETS edgeIndices[];};  //edge data list start/end offsets (sacrifice space for time)
layout(set = 0, binding=5) buffer bufedgeTargets { uint edgeTargets[];};   //edge data list (node->(node,node,node)) 
layout(set = 0, binding=6) buffer bufEdgeStrengths { float edgeStrengths[];};
layout(set = 0, binding=7) buffer resultData{ vec4 field_Destination[];};


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

vec3 addProportionalAttraction(vec3 self, vec4 neighbor, float speed){
    if (neighbor.w == -1) return vec3(0,0,0); 
    vec3 diff = self - neighbor.xyz;    
    return normalize(diff) * speed;
}


layout (local_size_x = 256) in;

void main()	{

    uint index = gl_GlobalInvocationID.x;

    if (index < fieldParams.nodeCount)
    {

        vec4 selfPosition = positions[index];
        vec4 presetLayoutPosition = presetPositions[index];
        vec3 selfVelocity = velocities[index].xyz;
        vec3 velocity = selfVelocity;

        vec4 nodePosition;

        //const float speedLimit = 100000.0;
        const float outputDebug = -101;
     
         /*
         .w presetLayoutPosition values
     
            -1 = not a node
             0 = invalid
             1 = preset, simple attraction towards target (invalid in this shader)
             2 = free body subject to standard forces
         */

         if ( selfPosition.w > 0)// && (selfPosition.w < 2 || fieldParams.fixedInternalNodes == 0)) 
         {

            // fruchterman reingold, force-directed n-body simulation

            //first repel every single node away from this node. 
            //this loop is the big bad bottleneck, in performance terms                
            for(uint nodeIndex = 0; nodeIndex < fieldParams.nodeCount; nodeIndex++)
            {
                velocity += addRepulsion(selfPosition,  positions[nodeIndex]);
            }
            
            //now iterate over each edge of this nodes edges, attracting any connected nodes
            //this operation is undirected - the force needs to be computed from both sides of the 
            //edge or the forces will be unbalanced and drift off (the "my people need me" effect)
            //this loop has low impact on throughput (50-150k nodes/second)    
            EDGE_INDEX_LIST_OFFSETS selfEdgeIndices = edgeIndices[index];
            if(selfEdgeIndices.FirstEdgeIndex != -1) //todo: get rid of this by making start == end?
            {
                for(int edgeIndex  = selfEdgeIndices.FirstEdgeIndex; edgeIndex < selfEdgeIndices.LastEdgeIndex; edgeIndex++)
                {
                    uint neighbour = edgeTargets[edgeIndex];
                    nodePosition = positions[neighbour];
                    velocity -= addAttraction(selfPosition, nodePosition, int(edgeIndex));            
                }
            }
            
            // temperature gradually cools down to zero
            velocity = normalize(velocity) * fieldParams.temperature;
            
    
        // add friction
        velocity *= 0.25;
    
        field_Destination[index] = vec4(velocity,  outputDebug);
        }
    }
}

