
#version 450


struct nodeAttribParams
{
     float delta;            // requestAnimationFrame delta
     float minTime;          // epoch min
     float maxTime;          // epoch max
     int  selectedNode;     // selectedNode
     float hoverMode;     // selectedNode
    int nodesTexWidth;     // will be the same for epoch and neighbors
    int epochsTexWidth;   // epoch data
    int edgesTexWidth;     // neighbor data
};

layout(set = 0, binding=0) buffer bufParams{
    nodeAttribParams params; // current self attrib values
};
layout(set = 0, binding=1) buffer bufnodeAttrib{
    vec4 nodeAttrib[]; // current self attrib values
};
layout(set = 0, binding=2) buffer bufepochsIndices{
    vec4 epochsIndices[]; // for epoch detection
};
layout(set = 0, binding=3) buffer bufepochsData{
    vec4 epochsData[]; // for epoch detection
};
layout(set = 0, binding=4) buffer bufedgeIndices{
    ivec4 edgeIndices[]; // for neighbor highlighting
};
layout(set = 0, binding=5) buffer bufedgeData{
    ivec4 edgeData[]; // for neighbor highlighting
};
layout(set = 0, binding=6) buffer bufnodeIDMappings{
    vec4 nodeIDMappings[];  // for selected node
};
layout(set = 0, binding=7) buffer bufresults{
    vec4 resultData[];
};




float inBetweenTimes(float epochTime){
    float increase = 0.0;
    if (epochTime >= params.minTime && epochTime <= params.maxTime){
        increase = 1.0;
    }
    return increase;
}

int hasSelectedNeighbor(int neighbor){
    int counter = 0;
    if ( neighbor == params.selectedNode){
        counter = 1;
    }
    return counter;
}


void main()	{

    uvec3 id = gl_GlobalInvocationID;
    uint index = id.y * params.nodesTexWidth + id.x;
    vec4 selfAttrib = nodeAttrib[index];  // just using x and y right now
    vec4 selfEpochsIndices = epochsIndices[index];
    
    // epoch time lookups

    float idx = selfEpochsIndices.x;
    float idy = selfEpochsIndices.y;
    float idz = selfEpochsIndices.z;
    float idw = selfEpochsIndices.w;

    float start = idx * 4.0 + idy;
    float end = idz * 4.0 + idw;

    float epochPixel = 0.0;
    float neighborPixel = 0.0;
    
   float selfPixel = 0;
    if (index == params.selectedNode) {
        selfPixel = 1.0;
    } else {
        selfPixel = 0.0;
    }


    //this part will do changes in alpha/size during animation
    /*
    if(! ( idx == idz && idy == idw ) ){

        float edgeIndex = 0.0;

        for(uint y = 0; y < params.epochsTexWidth; y++){
            for(uint x = 0; x < params.epochsTexWidth; x++){

                uint pixIndex = y * params.epochsTexWidth + x;
                vec4 pixel = epochsData[pixIndex];

                if (edgeIndex >= start && edgeIndex < end){
                    epochPixel += inBetweenTimes(pixel.x);
                }
                edgeIndex++;

                if (edgeIndex >= start && edgeIndex < end){
                    epochPixel += inBetweenTimes(pixel.y);
                }
                edgeIndex++;

                if (edgeIndex >= start && edgeIndex < end){
                    epochPixel += inBetweenTimes(pixel.z);
                }
                edgeIndex++;

                if (edgeIndex >= start && edgeIndex < end){
                    epochPixel += inBetweenTimes(pixel.w);
                }
                edgeIndex++;

            }
        }

    }
    */

    //  neighbor highlighting

    if (params.selectedNode >= 0 ){

        ivec4 selfEdgeIndices =  edgeIndices[index];

        idx = selfEdgeIndices.x;
        idy = selfEdgeIndices.y;
        idz = selfEdgeIndices.z;
        idw = selfEdgeIndices.w;

        start = idx * 4.0 + idy;
        end = idz * 4.0 + idw;

        if(! ( idx == idz && idy == idw ) ){

            int edgeIndex = 0;
            for(int y = 0; y < params.edgesTexWidth; y++){
                for(int x = 0; x < params.edgesTexWidth; x++){

                    int eTexIdx = y * params.edgesTexWidth + x;
                    ivec4 pixel = edgeData[eTexIdx];

                    if (edgeIndex >= start && edgeIndex < end){
                        neighborPixel += hasSelectedNeighbor( pixel.x );
                    }
                    edgeIndex++;

                    if (edgeIndex >= start && edgeIndex < end){
                        neighborPixel += hasSelectedNeighbor( pixel.y );
                    }
                    edgeIndex++;

                    if (edgeIndex >= start && edgeIndex < end){
                        neighborPixel += hasSelectedNeighbor( pixel.z );
                    }
                    edgeIndex++;

                    if (edgeIndex >= start && edgeIndex < end){
                        neighborPixel += hasSelectedNeighbor( pixel.w );
                    }
                    edgeIndex++;

                }

            }

        }

    }

    if ( params.hoverMode > 0.0 ) {

        // we are in hover mode

        // start the entire scene slightly
        if ( selfAttrib.y > 0.2){

            selfAttrib.y -= params.delta * 2.5;

        }

        if ( selfAttrib.y < 0.2){

            selfAttrib.y += params.delta * 2.5;

        }

        // start the entire scene small
        if ( selfAttrib.x > 200.0){

            selfAttrib.x -= 4000.0 * params.delta;

        }

        // if you are hovering over a real node
        if ( params.selectedNode >= 0.0 ){

            // if you are a node or a neighbor
            if ( neighborPixel > 0.0 || selfPixel > 0.0){

                selfAttrib.y = 0.8; // light up *only* self or neighbors

                if ( epochPixel > 0.0){

                    selfAttrib.x = 600.0;   // make bigger immediately
                    selfAttrib.y = 1.0;     // light up

                }

            }

        } else {

            if ( epochPixel > 0.0){

                selfAttrib.x = 600.0;   // make bigger immediately
                selfAttrib.y = 0.8;     // light up

            }

        }

    } else {

        // i have selected a node
        // completely black out the rest of the scene
        if ( selfAttrib.y > 0.0){

            selfAttrib.y -= params.delta * 2.5;

        }

        if ( selfAttrib.x > 200.0){

            selfAttrib.x -= 4000.0 * params.delta;

        }

        if ( params.selectedNode >= 0.0 ){

            // if you are a node or a neighbor
            if ( neighborPixel > 0.0 || selfPixel > 0.0){

                selfAttrib.y = 0.3; // light up *only* self or neighbors

                if ( epochPixel > 0.0){

                    selfAttrib.x = 600.0;   // make bigger immediately
                    selfAttrib.y = 1.0;     // light up

                }

            }

        }

    }

    selfAttrib.y = 1.0;
    resultData[index] = vec4( selfAttrib.xy, 0,0 );
}