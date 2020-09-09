using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{
    class YARAScan
    {

        readonly object scansLock = new object();

        public void StartYARAScan(BinaryTarget targ)
        {
            Console.WriteLine("TODO start yara scan");
            ulong handle = 0;
            lock (scansLock)
            {
                /*
                handle = dielib.CreateScanHandle();

                if (DIEScanHandles.ContainsKey(targ))
                    DIEScanHandles[targ] = handle;
                else
                    DIEScanHandles.Add(targ, handle);
                */
            }

            /*
            List<object> args = new List<object>() { dielib, targ, handle };

            Thread DIEThread = new Thread(new ParameterizedThreadStart(DetectItScanThread));
            DIEThread.Name = "DetectItEasy_" + targ.FileName;
            DIEThread.Start(args);
            */
        }

        public void CancelAllScans()
        {

        }
    }
}
