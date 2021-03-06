/*
Copyright (c) 2014-2015, MetaStack Inc.
All rights reserved.

Copied from https://github.com/jaredmcqueen/analytics

Diff with the December 2015 commit to see rgat modifications

See included licence: METASTACK ANALYTICS LICENSE
*/

/*
C:\Users\nia\Desktop\rgatstuff\gslangvalidator\bin\glslangValidator.exe  -V C:\Users\nia\Source\Repos\rgatCore\rgatCore\Shaders\SPIR-V\sim-velocity.glsl -o sim-velocity.spv -S comp
*/

#version 450
#extension GL_ARB_separate_shader_objects : enable
#extension GL_ARB_shading_language_420pack : enable

struct VelocityParams
{
    float delta; //not used
    float k;
    float temperature;
    uint nodesTexWidth;
    uint edgeCount;
    uint fixedInternalNodes;
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
layout(set = 0, binding=5) buffer bufedgeData {   
    uint edgeData[];
};
layout(set = 0, binding=6) buffer bufEdgeStrengths {   
    float edgeStrengths[];
};
layout(set = 0, binding=7) buffer resultData
{
    vec4 field_Destination[];
};




vec4 getNeighbor(uint bufferIndex){
    //vec2 uv = vec2(((mod(textureIndex, fieldParams.nodesTexWidth)) / fieldParams.nodesTexWidth), (floor(textureIndex / fieldParams.nodesTexWidth) / fieldParams.nodesTexWidth));
    //vec4  r =  texture(sampler2D(positions, positionsView), uv );
    
    return positions[bufferIndex];
}


//fr(x) = (k*k)/x;
vec3 addRepulsion(vec4 self, vec4 neighbor){
    vec3 diff = self.xyz - neighbor.xyz;
    float x = length( diff );
    float f = ( fieldParams.k * fieldParams.k ) / x;
    if(fieldParams.fixedInternalNodes == 1) f *= 5;
    return normalize(diff) * f ;
}


//fa(x) = (x*x)/k;
vec3 addAttraction(vec4 self, vec4 neighbor, int edgeIndex){

    if (neighbor.w == -1) return vec3(0,0,0); 
    vec3 diff = self.xyz - neighbor.xyz;
    float x = length( diff );
    float f = ( x * x ) / fieldParams.k;
    f *= edgeStrengths[edgeIndex];


    return normalize(diff) * f;
}

vec3 addProportionalAttraction(vec3 self, vec4 neighbor, float speed){
    if (neighbor.w == -1) return vec3(0,0,0); 
    vec3 diff = self - neighbor.xyz;    
    return normalize(diff) * speed;
}


void main()	{

    
    uvec3 id = gl_GlobalInvocationID;
    uint index = id.y * fieldParams.nodesTexWidth + id.x;

    vec4 selfPosition = positions[index];
    vec4 presetLayoutPosition = presetPositions[index];
    vec3 selfVelocity = velocities[index].xyz;
    vec3 velocity = selfVelocity;

    vec4 nodePosition;
    vec4 compareNodePosition;

    float speedLimit = 250.0;
    float attct = 0;
     
     /*
     .w position values
     
        -1 = not a node
         0 = internal block node, fixed position from parent
         1 = preset, simple attraction towards target
         2 = free body subject to standard forces
     */

     if ( selfPosition.w > 0 && (selfPosition.w < 2 || fieldParams.fixedInternalNodes == 0)) 
     {

        //move towards preset layout position
        if ( presetLayoutPosition.w >= 1.0) 
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
            for(uint y = 0; y < fieldParams.nodesTexWidth; y++)
            {
                for(uint x = 0; x < fieldParams.nodesTexWidth; x++)
                {
                    compareNodePosition = positions[y*fieldParams.nodesTexWidth + x];
                    // note: double ifs work.  using continues do not work for all GPUs.
                    if (compareNodePosition.w >= 0) 
                    {
                        //if distance below threshold, repel every node from every single node
                        if (distance(compareNodePosition.xyz, selfPosition.xyz) > 0.001) 
                        {
                            velocity += addRepulsion(selfPosition, compareNodePosition);
                        }
                    }
                }
		    }
            
            //now iterate over each edge, attracting every connected node towards each other
            vec2 selfEdgeIndices = edgeIndices[index];
            float start = selfEdgeIndices.x;
            float end = selfEdgeIndices.y;

            if(start != -1)
            {
                for(int edgeIndex  = int(start); edgeIndex < end; edgeIndex++)
                {
                    uint neighbour = edgeData[edgeIndex];
                    nodePosition = positions[neighbour];
                    velocity -= addAttraction(selfPosition, nodePosition, int(edgeIndex));  
                }
            }
        

            // temperature gradually cools down to zero

           velocity = normalize(velocity) * fieldParams.temperature;

           // Speed Limits
           if ( length( velocity ) > speedLimit ) 
           {
                velocity = normalize( velocity ) * speedLimit;
           }
        
        }
    }
    
    // add friction
    velocity *= 0.25;
    //field_Destination[index] = vec4(0,index,0,0);
    //field_Destination[index].x = edgeStrengths[index];
    field_Destination[index] = vec4(velocity, velocities[index].w);
}

