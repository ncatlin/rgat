/*
The attributes buffer has a 4-float attribute descriptor for each graph node
These describe the node texture diameter, base alpha, animation counter (for describing how the alpha differs from the base) and highlight state

The attributes buffer is an ephermeral description of the current state of the graph plots graphics. 
It is updated from the CPU when animation activity happens and the GPU shader gradually returns the updated value back to the default state
The overall shader params buffer controls overall behavious
*/
#version 450

// General parameters that control how the shader behaves
struct attribShaderParams
{
    // Time delta since the last update
    float delta;           
    // Index of the selected node
    int  selectedNode;     
    // nonzero if a node is hovered by the mouse
    float hoverMode;    
    // unused
    int edgeTexCount;     
    // baseline alpha for a node/edge with no activity. any non-lingering geometry will be brought back to this alpha
    float minAlpha;  
    // describe if the graph is in animated mode, which cases alpha values to be brought to the baseline
    bool isAnimated;
};

// Node-specific attributes
struct nodeAttribute
{
    // the pixel diameter of the node texture. used by the display shaders
    float nodeDiameter;
    // the current alpha of the node, used by the display shaders
    float currentAlpha;
    // counter which controls how the current alpha is adjusted towards the baseline on each attribute shader pass
    float animCounter;
    // 
    float highlightFlag;
};

layout(set = 0, binding=0) buffer bufParams{   attribShaderParams params;};

layout(set = 0, binding=1) buffer bufnodeAttrib{   nodeAttribute nodeAttribs[]; };

//for neighbor highlighting
layout(set = 0, binding=2) buffer bufedgeIndices{  ivec2 edgeIndices[]; };
 // for neighbor highlighting
layout(set = 0, binding=3) buffer bufedgeData{    int edgeData[];};

layout(set = 0, binding=4) buffer bufresults{    nodeAttribute resultData[];};

const float AnimNodeInflateSize = 11.0;
const float AnimNodeDeflateThreshold = 0.7;

int NodeIndexIsSelected(int neighbor){
    int counter = 0;
    if ( neighbor == params.selectedNode){
        counter = 1;
    }
    return counter;
}


layout (local_size_x = 256) in;
void main()	{
    ///uint index = gl_LocalInvocationIndex;// gl_GlobalInvocationID.x;
    uvec3 id = gl_GlobalInvocationID;
    uint index = id.x;
    nodeAttribute selfAttrib = nodeAttribs[index];  // just using x and y right now

    

    // epoch time lookups

    float idx = 0;
    float idy = 0;
    float idz = 0;
    float idw = 0;
    float start, end;

    float neighborPixel = 0.0;
    
    /*
   float selfPixel = 0;
    if (index == params.selectedNode) {
        selfPixel = 1.0;
    } else {
        selfPixel = 0.0;
    }*/
        
    //if live trace or active replay
    //todo - different shaders for these
    if (params.isAnimated == true)
    {        
        //alpha is based on how long since last activated
        
        if (selfAttrib.animCounter > 0) //an 'active' node
        {
            if (selfAttrib.animCounter >= 2) //2+ are blocked/high cpu usage nodes 
            {
                selfAttrib.currentAlpha = selfAttrib.animCounter - 2.0; //remaining is expected to be pulse alpha
            }
            else
            {  
                selfAttrib.currentAlpha = selfAttrib.animCounter;
                selfAttrib.animCounter -= params.delta;// * 7.0;

                selfAttrib.nodeDiameter = max(200, selfAttrib.nodeDiameter - (selfAttrib.animCounter * 7.0)); //make animated nodes larger
                
                if (selfAttrib.animCounter < 0.05) 
                    selfAttrib.animCounter = 0;
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

    float alphaTarget = (params.isAnimated) ? params.minAlpha : 1.0;

    //quickly shrink geometry that has been inflated, unless highlighted or very recently animated
    if ( selfAttrib.nodeDiameter > 200.0 && selfAttrib.highlightFlag == 0 && selfAttrib.animCounter <= AnimNodeDeflateThreshold)
    {
        selfAttrib.nodeDiameter -= 500.0 * params.delta;
        if (selfAttrib.nodeDiameter < 200) 
        {
            selfAttrib.nodeDiameter = 200;
        }
    }


    /*
    This section deals with mouseover hover/selection
    */
    if ( params.hoverMode > 0.0 && selfAttrib.animCounter == 0) {

        // we are in hover mode
        //first restore modified values to default

        if (selfAttrib.currentAlpha != alphaTarget)
        {
            //slowly darken bright geometry to default alpha
            if ( selfAttrib.currentAlpha > (alphaTarget+0.01)){
                selfAttrib.currentAlpha =  max(selfAttrib.currentAlpha - params.delta * 2.5, alphaTarget);
            }

            //slowly brighten dark geometry to default alpha
            if ( selfAttrib.currentAlpha < (alphaTarget-0.01)){
                selfAttrib.currentAlpha = min(selfAttrib.currentAlpha + params.delta * 2.5, alphaTarget);
            }
        }



        // if you are hovering over a real node
        if ( params.selectedNode >= 0.0 ){

            // if you are a node or a neighbor
            if ( neighborPixel > 0.0 || index == params.selectedNode){
                selfAttrib.currentAlpha = 0.8; // light up *only* self or neighbors
            }

        } 
    } 
    /*
    else {

        // i have selected a node
        // completely black out the rest of the scene
        if ( selfAttrib.currentAlpha > 0.0){
            selfAttrib.currentAlpha -= params.delta * 2.5;
        }

        if ( selfAttrib.x > 200.0){
            selfAttrib.x -= 4000.0 * params.delta;
        }


        if ( params.selectedNode >= 0.0 ){

            // if you are a node or a neighbor
            if ( neighborPixel > 0.0 || index == params.selectedNode){
                selfAttrib.currentAlpha = 0.3; // light up *only* self or neighbors
            }
        }
    }
    */
    
    

    resultData[index] = selfAttrib;
}