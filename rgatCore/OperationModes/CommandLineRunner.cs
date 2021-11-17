using rgat.Threads;
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
        private ProcessCoordinatorThread? coordThread;

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
        private void LoadingThreadCommandLine()
        {

            Logging.RecordLogEvent("Initing/Loading Config", Logging.LogFilterType.Debug);

            System.Diagnostics.Stopwatch timer = new();
            timer.Start();

            GlobalConfig.LoadConfig(GUI: false); // 900ms~ depending on themes

            Logging.RecordLogEvent($"Startup: config loaded in {timer.ElapsedMilliseconds} ms", Logging.LogFilterType.Debug);
            timer.Restart();

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
                apiTask = Task.Run(() => Logging.WriteConsole("TODO: linux API loading"));
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
            Logging.WriteConsole("Startup done");

        }

        /// <summary>
        /// Init a GPU usage mode (todo)
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
        public static void TraceBinary(string targetPath, string? saveDirectory = null, bool recordVideo = false)
        {

            Logging.WriteConsole($"Command line mode tracing binary {targetPath}");

            BinaryTarget target = new BinaryTarget(targetPath);
            if (!GlobalConfig.Settings.GetPreviousLaunchSettings(target.GetSHA1Hash(), out ProcessLaunchSettings? settings) || settings is null)
            {
                settings = new ProcessLaunchSettings(targetPath);
                settings.TraceChoices.InitDefaultExclusions();
            }
            
            ProcessLaunching.StartLocalTrace(target.BitWidth, settings, target.PEFileObj);

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
                Logging.WriteConsole($"{running}/{traces} traces running accross {targets.Count} targets");
                if (traces > 0 && running == 0) //also wait for keypress
                {
                    Logging.WriteConsole("All traces done. Saving and exiting.");
                    rgatState.SaveAllTargets();
                    rgatState.Shutdown();
                    break;
                }
            }
        }


    }
}
