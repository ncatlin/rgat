using rgat.Threads;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace rgat.OperationModes
{
    /// <summary>
    /// Runs rgat locally, without a GUI. Can be run without the GPU at all to generate a trace file, 
    /// or with the GPU to generate a video or image
    /// </summary>
    public class CommandLineRunner
    {


        ProcessCoordinatorThread? coordThread;

        /// <summary>
        /// Create a commandline runner
        /// </summary>
        public CommandLineRunner()
        {

        }

        /// <summary>
        /// Initialise for GPU-less operations, such as on an analysis sandbox were only tracing will be performed
        /// </summary>
        public void InitNoGPU()
        {
            LoadingThreadCommandLine();
        }

        //todo - make Exit wait until this returns
        void LoadingThreadCommandLine()
        {

            Logging.RecordLogEvent("Initing/Loading Config", Logging.LogFilterType.TextDebug);

            System.Diagnostics.Stopwatch timer = new System.Diagnostics.Stopwatch();
            timer.Start();
            //float configProgress = 0, widgetProgress = 0;

            GlobalConfig.LoadConfig(GUI: false); // 900ms~ depending on themes


            //InitEventHandlers();

            Logging.RecordLogEvent($"Startup: config loaded in {timer.ElapsedMilliseconds} ms", Logging.LogFilterType.TextDebug);
            timer.Restart();

            //rgatState.VideoRecorder.Load(); //0 ms

            //todo - conditional thread here instead of new trace
            rgatState.processCoordinatorThreadObj = new ProcessCoordinatorThread();
            rgatState.processCoordinatorThreadObj.Begin();


            // api data is the startup item that can be loaded latest as it's only needed when looking at traces
            // we could load it in parallel with the widgets/config but if it gets big then it will be the limiting factor in start up speed
            // doing it last means the user can do stuff while it loads
            Task? apiTask = null;
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
            {
                string? datafile = APIDetailsWin.FindAPIDatafile();
                if (datafile is not null)
                {
                    apiTask = Task.Run(() => APIDetailsWin.Load(datafile));
                }
            }
            else
            {
                apiTask = Task.Run(() => Console.WriteLine("TODO: linux API loading"));
            }

            /*
            if (GlobalConfig.Settings.Updates.DoUpdateCheck)
            {
                _ = Task.Run(() => Updates.CheckForUpdates()); //functionality does not depend on this so we don't wait for it
            }
            */
            if (apiTask is not null)
            {
                Task.WhenAll(apiTask);
            }

            coordThread = new ProcessCoordinatorThread();
            coordThread.Begin();


            timer.Stop();
            Console.WriteLine("Startup done");

        }

        /// <summary>
        /// Init a GPU usage mode
        /// </summary>
        public void InitGPU()
        {

        }

        /// <summary>
        /// Begin tracing a binary in command line mode
        /// </summary>
        /// <param name="targetPath">Binary to trace</param>
        /// <param name="saveDirectory">Where to save the result</param>
        /// <param name="recordVideo">If a video is being recorded</param>
        public void TraceBinary(string targetPath, string? saveDirectory = null, bool recordVideo = false)
        {

            Console.WriteLine($"Command line mode tracing binary {targetPath}");

            BinaryTarget target = new BinaryTarget(targetPath);
            string pintoolpath = target.BitWidth == 32 ? GlobalConfig.GetSettingPath(CONSTANTS.PathKey.PinToolPath32) :
                GlobalConfig.GetSettingPath(CONSTANTS.PathKey.PinToolPath64);


            ProcessLaunching.StartLocalTrace(pintoolpath, targetPath, target.PEFileObj);

            while (true)
            {
                Thread.Sleep(1000);
                var targets = rgatState.targets.GetBinaryTargets();
                int traces = 0, running = 0;
                foreach (var previousTarget in targets)
                {
                    foreach (var previousTrace in previousTarget.GetTracesList())
                    {
                        traces += 1;
                        if (previousTrace.IsRunning)
                        {
                            running += 1;
                        }
                    }
                }
                Console.WriteLine($"{running}/{traces} traces running accross {targets.Count} targets");
                if (traces > 0 && running == 0) //also wait for keypress
                {
                    Console.WriteLine("All traces done. Saving and exiting.");
                    rgatState.SaveAllTargets();
                    rgatState.Shutdown();
                    break;
                }
            }
        }


    }
}
