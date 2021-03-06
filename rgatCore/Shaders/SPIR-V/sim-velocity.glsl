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
vec3 addRepulsion(vec3 self, vec3 neighbor){
    vec3 diff = self - neighbor;
    float x = length( diff );
    float f = ( fieldParams.k * fieldParams.k ) / x;
    return normalize(diff) * f ;
}


//fa(x) = (x*x)/k;
vec3 addAttraction(vec3 self, vec4 neighbor, int edgeIndex){
    if (neighbor.w == -1) return vec3(0,0,0); 
    vec3 diff = self - neighbor.xyz;
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
      
    //move towards preset layout position
    if ( presetLayoutPosition.w > 0.0 ) {
     
        // node needs to move towards destination.
        
        if ( selfPosition.w > 0.0 ) {
            
            compareNodePosition = presetLayoutPosition;
            float distFromDest = distance(compareNodePosition.xyz, selfPosition.xyz);
            if (distFromDest > 0.001) {
                float speed = distFromDest/10;
                if (speed < 10) speed = distFromDest;
                velocity -= addProportionalAttraction(selfPosition.xyz, compareNodePosition, distFromDest/10);
            }
        }
        velocity *= 0.75;

    } else {
    
        // force-directed n-body simulation
        if( selfPosition.w > 0.0 )
        {
            //first repel every node away from each other
            for(uint y = 0; y < fieldParams.nodesTexWidth; y++)
            {
                for(uint x = 0; x < fieldParams.nodesTexWidth; x++)
                {
                    compareNodePosition = positions[y*fieldParams.nodesTexWidth + x];
                    // note: double ifs work.  using continues do not work for all GPUs.
                    if (compareNodePosition.w != -1.0) 
                    {
                        //if distance below threshold, repel every node from every single node
                        if (distance(compareNodePosition.xyz, selfPosition.xyz) > 0.001) 
                        {
                            velocity += addRepulsion(selfPosition.xyz, compareNodePosition.xyz);
                        }
                    }
                }
		    }
            
            //now iterate over each edge, attracting every connected node towards each other
            vec2 selfEdgeIndices = edgeIndices[index];
            
            float start = selfEdgeIndices.x;
            float end = selfEdgeIndices.y;

            /*
                                            field_Destination[index].x = index;  
                                field_Destination[index].y = start;  
                                field_Destination[index].z = end;  
                                field_Destination[index].w = -9;
                                return;
                                */

            if(start != -1){
                field_Destination[index] = vec4(-8,-8,-8,-8);
                for(int edgeIndex  = int(start); edgeIndex < end; edgeIndex++)
                {
                        
                    uint neighbour = edgeData[edgeIndex];


                    nodePosition = positions[neighbour];
                    velocity -= addAttraction(selfPosition.xyz, nodePosition, int(edgeIndex));  
                    /*
                    field_Destination[edgeIndex].x = edgeIndex;  
                    field_Destination[edgeIndex].y = index;  
                    field_Destination[edgeIndex].z = neighbour;  
                    field_Destination[edgeIndex].w = edgeStrengths[edgeIndex];            */
                }
            }
        }

        // temperature gradually cools down to zero

       velocity = normalize(velocity) * fieldParams.temperature;

        // Speed Limits
        if ( length( velocity ) > speedLimit ) {
            velocity = normalize( velocity ) * speedLimit;
        }
        
    }

    
    // add friction
    velocity *= 0.25;
    //field_Destination[index] = vec4(0,index,0,0);
    //field_Destination[index].x = edgeStrengths[index];
    field_Destination[index] = vec4(velocity, velocities[index].w);
}

