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
    uint edgesTexWidth;
};

layout(set = 0, binding=0) uniform Params 
{
    VelocityParams fieldParams;
};
layout(set = 0, binding=1) buffer bufPositions{
    vec4 positions[];
};
layout(set = 0, binding=2) buffer buflayoutPositions{   
    vec4 layoutPositions[];
};
layout(set = 0, binding=3) buffer bufvelocities {   
    vec4 velocities[];
};
layout(set = 0, binding=4) buffer bufedgeIndices {   
    ivec4 edgeIndices[];
};
layout(set = 0, binding=5) buffer bufedgeData {   
    ivec4 edgeData[];
};
layout(set = 0, binding=6) buffer resultData
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
vec3 addAttraction(vec3 self, vec4 neighbor){
    if (neighbor.w == -1) return vec3(0,0,0); 
    vec3 diff = self - neighbor.xyz;
    float x = length( diff );
    float f = ( x * x ) / fieldParams.k;
    
    return normalize(diff) * f;
}


void main()	{

    
    uvec3 id = gl_GlobalInvocationID;
    uint index = id.y * fieldParams.nodesTexWidth + id.x;

    vec4 selfPosition = positions[index];
    vec4 selfLayoutPosition = layoutPositions[index];
    vec3 selfVelocity = velocities[index].xyz;
    vec3 velocity = selfVelocity;

    vec4 nodePosition;
    vec4 compareNodePosition;

    float speedLimit = 250.0;
    float attct = 0;
    
                int hitcount = 0;
                vec3 hitcoord = vec3(0,0,0);
  
  
    //move towards preset layout position
    if ( selfLayoutPosition.w > 0.0 ) {
     
        // node needs to move towards destination.
        
        if ( selfPosition.w > 0.0 ) {
            
            compareNodePosition = selfLayoutPosition;

            if (distance(compareNodePosition.xyz, selfPosition.xyz) > 0.001) {

                velocity -= addAttraction(selfPosition.xyz, compareNodePosition);

            }

        }
        velocity *= 0.75;

    } else {
    
        // force-directed n-body simulation
        if( selfPosition.w > 0.0 )
        {
            int rc = 0;
            for(uint y = 0; y < fieldParams.nodesTexWidth; y++)
            {
                for(uint x = 0; x < fieldParams.nodesTexWidth; x++)
                {
                    rc += 1;
                    compareNodePosition = positions[y*fieldParams.nodesTexWidth + x];
                    // note: double ifs work.  using continues do not work for all GPUs.
                    if (compareNodePosition.w != -1.0) 
                    {
                        //if distance below threshold, repel every node from every single node
                        if (distance(compareNodePosition.xyz, selfPosition.xyz) > 0.001) 
                        {
                        
                            vec3 repuls = addRepulsion(selfPosition.xyz, compareNodePosition.xyz);
                            velocity += repuls;
                            //field_Destination[y*fieldParams.nodesTexWidth + x] = vec4(selfPosition.xy, compareNodePosition.xy);
                            //field_Destination[y*fieldParams.nodesTexWidth + x] = vec4(repuls, y*fieldParams.nodesTexWidth + x);
                        }
                    }
                }
		    }
            

            vec4 selfEdgeIndices = edgeIndices[index];
            float idx = selfEdgeIndices.x;
            float idy = selfEdgeIndices.y;
            float idz = selfEdgeIndices.z;
            float idw = selfEdgeIndices.w;
           
            float start = idx * 4.0 + idy;
            float end = idz * 4.0 + idw;


            if(! ( idx == idz && idy == idw ) ){

                int edgeIndex = 0;
                //iterate over every edge
                for(uint y = 0; y < fieldParams.edgesTexWidth; y++)
                {
                    for(uint x = 0; x < fieldParams.edgesTexWidth; x++)
                    {
                        ivec4 pixel = edgeData[y*fieldParams.edgesTexWidth + x];

                        if (edgeIndex >= start && edgeIndex < end){
                                hitcount++;
                                nodePosition = getNeighbor(pixel.x);
                                vec3 attrac = addAttraction(selfPosition.xyz, nodePosition);  
                                velocity -= attrac;          
                        }
                        edgeIndex++;

                        if (edgeIndex >= start && edgeIndex < end){
                        hitcount++;
                        
                                nodePosition = getNeighbor(pixel.y);
                                vec3 attrac = addAttraction(selfPosition.xyz, nodePosition);  
                                velocity -= attrac;      
                        }
                        edgeIndex++;

                        if (edgeIndex >= start && edgeIndex < end){
                        hitcount++;     
                        
                                nodePosition = getNeighbor(pixel.z);
                                vec3 attrac = addAttraction(selfPosition.xyz, nodePosition);  
                                velocity -= attrac;            
                        }
                        edgeIndex++;

                        if (edgeIndex >= start && edgeIndex < end){
                            hitcount++;                     
                            
                                nodePosition = getNeighbor(pixel.w);
                                vec3 attrac = addAttraction(selfPosition.xyz, nodePosition);  
                                velocity -= attrac;      
                        }
                        edgeIndex++;
                        
                    }
                }
            }
        }

        // temperature gradually cools down to zero

       velocity = normalize(velocity) * fieldParams.temperature;
    }

    // Speed Limits
    if ( length( velocity ) > speedLimit ) {
        velocity = normalize( velocity ) * speedLimit;
    }
    
    // add friction
    velocity *= 0.25;

    field_Destination[index] = vec4(velocity, 1.0);
    
    //field_Destination[index] = vec4(hitcount,hitcoord);

}

