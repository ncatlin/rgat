/*
Copyright (c) 2014-2015, MetaStack Inc.
All rights reserved.

Adapted from https://github.com/jaredmcqueen/analytics/blob/7fa833bb07e2f145dba169b674f8865566970a68/shaders/sim-nodeAttrib.glsl

See included licence: METASTACK ANALYTICS LICENSE

C:\Users\nia\Desktop\rgatstuff\gslangvalidator\bin\glslangValidator.exe -V C:\Users\nia\Source\Repos\rgatPrivate\rgatCore\Shaders\SPIR-V\sim-nodeVelocity.glsl -o sim-nodeVelocity.spv -S comp
*/
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
    // Index of the mouseover/selected node
    int hoveredNodeID;     
    // nonzero if a node is hovered by the mouse
    float hoverMode;    
    uint nodeCount;     

    // baseline alpha for a node/edge with no activity. any non-lingering geometry will be brought back to this alpha
    float minAlpha;  
    // describe if the graph is in animated mode, which cases alpha values to be brought to the baseline
    int isAnimated;
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
    // specifies the highlight texture to use, if any
    float highlightFlag;
};

struct EDGE_INDEX_LIST_OFFSETS{ int FirstEdgeIndex;  int LastEdgeIndex; };

layout(set = 0, binding=0) buffer bufParams{   attribShaderParams params;};
layout(set = 0, binding=1) buffer bufnodeAttrib{   nodeAttribute nodeAttribs[]; };
layout(set = 0, binding=2) buffer bufedgeIndices{  EDGE_INDEX_LIST_OFFSETS edgeIndices[]; }; //for neighbor highlighting
layout(set = 0, binding=3) buffer bufedgeData{    int edgeData[];};  // for neighbor highlighting
layout(set = 0, binding=4) buffer bufresults{    nodeAttribute resultData[];};

const float AnimNodeInflateSize = 11.0;
const float AnimNodeDeflateThreshold = 0.7;

int NodeIndexIsSelected(int neighbor){
    int counter = 0;
    if ( neighbor == params.hoveredNodeID){
        counter = 1;
    }
    return counter;
}


layout (local_size_x = 256) in;
void main()	{

    uint index = gl_GlobalInvocationID.x;
    if (index < params.nodeCount)
    {
        nodeAttribute selfAttrib = nodeAttribs[index];  // just using x and y right now

        
        //if live trace or active replay
        //todo - different shaders for these
        if (params.isAnimated == 1)
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
                    selfAttrib.currentAlpha = max(selfAttrib.animCounter, params.minAlpha);
                    selfAttrib.animCounter -= params.delta;// * 7.0;

                    selfAttrib.nodeDiameter = max(200, selfAttrib.nodeDiameter - (selfAttrib.animCounter * 7.0)); //make animated nodes larger
                
                    if (selfAttrib.animCounter < 0.05) 
                        selfAttrib.animCounter = 0;
                }
            }
            else
            {
             selfAttrib.currentAlpha = params.minAlpha;
            }
        }



        float alphaTarget = (params.isAnimated == 1) ? params.minAlpha : 1.0;

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


            //  neighbor highlighting of selected/hovered node
            if (params.hoveredNodeID >= 0 ){
            
                float neighborPixel = 0.0;
                EDGE_INDEX_LIST_OFFSETS selfEdgeIndices =  edgeIndices[index];
                for ( int i = selfEdgeIndices.FirstEdgeIndex; i < selfEdgeIndices.LastEdgeIndex; i++){
                       neighborPixel += NodeIndexIsSelected( edgeData[i] );               
                }

                // if you are a node or a neighbor
                if ( neighborPixel > 0.0 || index == params.hoveredNodeID){
                    selfAttrib.currentAlpha = 0.8; // light up *only* self or neighbors
                }

            } 
        }     

        resultData[index] = selfAttrib;
    }
}