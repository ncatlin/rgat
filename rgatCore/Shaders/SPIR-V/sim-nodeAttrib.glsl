
#version 450


struct nodeAttribParams
{
     float delta;            // requestAnimationFrame delta
     int  selectedNode;     // selectedNode
     float hoverMode;     // selectedNode
    int edgeTexCount;     
    int fff;     // neighbor data
    bool isAnimated;
};

layout(set = 0, binding=0) buffer bufParams{
    nodeAttribParams params; // current self attrib values
};
layout(set = 0, binding=1) buffer bufnodeAttrib{
    vec4 nodeAttrib[]; // current self attrib values
};
layout(set = 0, binding=2) buffer bufedgeIndices{
    ivec2 edgeIndices[]; // for neighbor highlighting
};
layout(set = 0, binding=3) buffer bufedgeData{
    int edgeData[]; // for neighbor highlighting
};
layout(set = 0, binding=4) buffer bufresults{
    vec4 resultData[];
};

const float AnimNodeInflateSize = 11.0;
const float AnimNodeDeflateThreshold = 0.7;

int NodeIndexIsSelected(int neighbor){
    int counter = 0;
    if ( neighbor == params.selectedNode){
        counter = 1;
    }
    return counter;
}



    //x = diameter
    //y = default alpha
    //z = counter since last animation activity
    //w = highlight info


layout (local_size_x = 256) in;
void main()	{
    uvec3 id = gl_GlobalInvocationID;
    uint index = id.x;
    vec4 selfAttrib = nodeAttrib[index];  // just using x and y right now

    // epoch time lookups

    float idx = 0;
    float idy = 0;
    float idz = 0;
    float idw = 0;
    float start, end;

    float neighborPixel = 0.0;
    

   float selfPixel = 0;
    if (index == params.selectedNode) {
        selfPixel = 1.0;
    } else {
        selfPixel = 0.0;
    }
        
    //if live trace or active replay
    //todo - different shaders for these
    if (params.isAnimated == true)
    {        
        //alpha is based on how long since last activated
        
        if (selfAttrib.z > 0) //an 'active' node
        {
            if (selfAttrib.z >= 2) //2+ are blocked/high cpu usage nodes 
            {
                selfAttrib.y = selfAttrib.z - 2.0; //remaining is expected to be pulse alpha
            }
            else
            {  
                selfAttrib.y = selfAttrib.z;
                selfAttrib.z -= params.delta;// * 7.0;

                selfAttrib.x = max(200, selfAttrib.x - (selfAttrib.z * 7.0)); //make animated nodes larger
                
                if (selfAttrib.z < 0.05) 
                    selfAttrib.z = 0;
            }
        }
    }


    //  neighbor highlighting of selected/hovered node
    if (params.selectedNode >= 0 ){

        ivec2 selfEdgeIndices =  edgeIndices[index];

        int start = selfEdgeIndices.x;
        int end = selfEdgeIndices.y;

        for ( int i = start; i < end; i++){
               neighborPixel += NodeIndexIsSelected( edgeData[i] );               
        }

        //todo: commented out this optimisation for debugging. 
        // restore/test/optimised if needed


        //if(! ( idx == idz && idy == idw ) ){

        /*
        if (start != end)
        {
            int edgeIndex = 0;
            for(int eTexIdx = 0; eTexIdx < params.edgeTexCount; eTexIdx += 1){

                    //ivec4 pixel = edgeData[eTexIdx];

                    if (edgeIndex >= start && edgeIndex < end){
                        neighborPixel += hasSelectedNeighbor( edgeData[eTexIdx] );
                    }
                    edgeIndex++;

                    /*
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
                    edgeIndex++;*/

                //}
        //}
        
            

        //}

    }

    float alphaTarget = (params.isAnimated) ? 0.2 : 1.0;

    /*
    This section deals with mouseover hover/selection
    */
    if ( params.hoverMode > 0.0 && selfAttrib.z == 0) {

        // we are in hover mode
        //first restore modified values to default

        selfAttrib.w = 10;
        if (selfAttrib.y != alphaTarget)
        {
            //slowly darken bright geometry to default alpha
            if ( selfAttrib.y > (alphaTarget+0.01)){
                selfAttrib.y =  max(selfAttrib.y - params.delta * 2.5, alphaTarget);
            }

            //slowly brighten dark geometry to default alpha
            if ( selfAttrib.y < (alphaTarget-0.01)){
                selfAttrib.y = min(selfAttrib.y + params.delta * 2.5, alphaTarget);
            }
        }


        //quickly shrink geometry that has been inflated, unless highlighted or very recently animated
        if ( selfAttrib.x > 200.0 && selfAttrib.w == 0 && selfAttrib.z <= AnimNodeDeflateThreshold)
        {
            selfAttrib.x -= 4000.0 * params.delta;
            if (selfAttrib.x < 200) 
            {
            selfAttrib.x = 200;
            }
        }

        // if you are hovering over a real node
        if ( params.selectedNode >= 0.0 ){

            // if you are a node or a neighbor
            if ( neighborPixel > 0.0 || selfPixel > 0.0){
                selfAttrib.y = 0.8; // light up *only* self or neighbors
            }

        } 
    } 
    /*
    else {

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
            }
        }
    }
    */
    
    

    resultData[index] = selfAttrib;
}