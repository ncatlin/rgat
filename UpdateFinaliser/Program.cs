using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace UpdateFinaliser
{
    class Program
    {
        static readonly string[] validSigners = new string[] { "Nia Catlin", "Open Source Developer, Nia CATLIN" };
        static void Main(string[] args)
        {
            string logf = Path.Combine(Path.GetDirectoryName(args[1]), "rgatupdatelog.txt");
            using FileStream log = File.OpenWrite(logf);
            log.Write(Encoding.ASCII.GetBytes($"Started with args len {args.Length} {string.Join(",", args)}\n"));

            if (args.Length != 4)
            {
                return;
            }

            log.Write(Encoding.ASCII.GetBytes("Parsing Parent PID\n"));
            if (!int.TryParse(args[0], out int PID))
            {
                return;
            }

            log.Write(Encoding.ASCII.GetBytes("Checking original rgat exists\n"));
            string originalrgat = args[1];
            if (!File.Exists(originalrgat))
            {
                return;
            }

            log.Write(Encoding.ASCII.GetBytes("Checkign updated rgat exists\n"));
            string newrgat = args[2];
            if (!File.Exists(newrgat))
            {
                return;
            }

            log.Write(Encoding.ASCII.GetBytes("Parsing relaunch option\n"));
            if (!bool.TryParse(args[3], out bool reLaunch))
            {
                return;
            }

            log.Write(Encoding.ASCII.GetBytes("Waiting for parent to terminate\n"));
            try
            {
                Process P = Process.GetProcessById(PID);
                if (P != null)
                {
                    log.Write(Encoding.ASCII.GetBytes("Parent Found\n"));
                    P.WaitForExit();
                }
                log.Write(Encoding.ASCII.GetBytes("Parent Terminated\n"));
            }
            catch (Exception e)
            {
                log.Write(Encoding.ASCII.GetBytes($"Failed to wait for process {PID} to exit: {e.Message}"));
            }

            log.Write(Encoding.ASCII.GetBytes("Checking original and new still exist\n"));
            if (File.Exists(originalrgat) && File.Exists(newrgat))
            {
                log.Write(Encoding.ASCII.GetBytes("Checking signatures of original and new\n"));
                if (!VerifyCertificate(originalrgat, validSigners, out string origErr))
                {
                    log.Write(Encoding.ASCII.GetBytes($"Tried to replace invalid rgat ({originalrgat}) {origErr}\n"));
                    return;
                }

                if (!VerifyCertificate(newrgat, validSigners, out string newErr))
                {
                    log.Write(Encoding.ASCII.GetBytes($"Update had bad signature: ({newrgat}) {newErr}\n"));
                    return;
                }


                log.Write(Encoding.ASCII.GetBytes("Starting replacement\n"));
                try
                {
                    PerformValidatedFileReplace(originalrgat, newrgat);
                }
                catch (Exception e)
                {
                    log.Write(Encoding.ASCII.GetBytes($"Exception on replacement {newrgat} -> {originalrgat}) => {e.Message}"));
                }

                if (reLaunch)
                {
                    string updated_rgat = originalrgat;
                    log.Write(Encoding.ASCII.GetBytes($"Relaunch requested, launching {updated_rgat}\n"));
                    try
                    {
                        Process.Start(updated_rgat);
                    }
                    catch (Exception e)
                    {
                        log.Write(Encoding.ASCII.GetBytes($"Exception launching rgat - {e.Message}\n"));
                        return;
                    }
                }
                log.Close();
                File.Delete(logf); //got here without an error, no log needed
            }
        }

        public static void PerformValidatedFileReplace(string oldfile, string newfile)
        {
            File.Delete(oldfile);
            File.Copy(newfile, oldfile);
            File.Delete(newfile);
        }

        public static bool VerifyCertificate(string path, string[] expectedSigners, out string error)
        {
            error = null;

            try
            {
                X509Certificate signer = X509Certificate.CreateFromSignedFile(path);
                bool hasValidSigner = expectedSigners.Any(validSigner => signer.Subject.ToLower().Contains($"O={validSigner},".ToLower()));
                if (!hasValidSigner)
                {
                    error = "Unexpected signer " + signer.Subject;
                    return false;
                }

                X509Certificate2 certificate = new X509Certificate2(signer);
                if (certificate.NotBefore > DateTime.Now)
                {
                    DateTime limit = certificate.NotBefore;
                    error = $"Signature Validity Starts {limit.ToLongDateString() + " " + limit.ToLongTimeString()}";
                    return false;
                }
                if (certificate.NotAfter < DateTime.Now)
                {
                    DateTime limit = certificate.NotAfter;
                    error = $"Signature Validity Ended {limit.ToLongDateString() + " " + limit.ToLongTimeString()}";
                    return false;
                }

                var certificateChain = new X509Chain
                {
                    ChainPolicy = {
                        RevocationFlag = X509RevocationFlag.EntireChain,
                        RevocationMode = X509RevocationMode.Online,
                        UrlRetrievalTimeout = new TimeSpan(0, 1, 0),
                        VerificationFlags = X509VerificationFlags.NoFlag}
                };

                if (!certificateChain.Build(certificate))
                {
                    error = "Unverifiable signature";
                    return false;
                }
                error = "Success";
                return true;
            }
            catch (Exception e)
            {
                if (e.Message == "Cannot find the requested object.")
                {
                    error = "File is not signed";
                }
                else
                {
                    error = "Exception verifying certificate: " + e.Message;
                }
                return false;
            }
        }
    }
}
