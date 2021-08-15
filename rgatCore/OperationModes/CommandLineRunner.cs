using System;
using System.Collections.Generic;
using System.Text;

namespace rgat.OperationModes
{    
     /// <summary>
     /// Runs rgat locally, without a GUI. Can be run without the GPU at all to generate a trace file, 
     /// or with the GPU to generate a video or image
     /// </summary>
    public class CommandLineRunner
    {
        public CommandLineRunner()
        {

        }

        
        public void InitNoGPU()
        {

        }       

        
        public void InitGPU()
        {

        }


        public void TraceBinary(string targetPath, string saveDirectory = null, bool recordVideo = false)
        {

            Console.WriteLine($"Command line mode tracing binary {targetPath}");
        }


    }
}
