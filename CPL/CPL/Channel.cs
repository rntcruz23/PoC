using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;

namespace CPL
{
    class Channel
    {
        Dictionary<string, Action<string>> dict;

        WebClient client = null;
        public Func<string, int, int, byte[]> fetch;

        string key = null;
        string chunks = null;
        public string url = null;

        public Channel()
        {
            this.dict = new Dictionary<string, Action<string>>();
            this.dict.Add("proxy", setProxy);
            this.dict.Add("chunks", setChunks);
            this.dict.Add("key", setKey);

            this.fetch = GetBytes;

            this.client = new WebClient();
        }

        public int parse(string[] words)
        {
            int len = words.Length;
            for (int i = 0; i < len; i++)
            {
                if (words[i].StartsWith("http"))
                {
                    this.url = words[i];
                    return i - 1;
                }


                this.dict[words[i]](words[i + 1]);

                // Skip args
                i++;
            }

            return 0;
        }

        private void setProxy(string proxy)
        {
            // remove [http://]<user>:<pass>@<ip>:<port> if present
            if (proxy.StartsWith("http://"))
            {
                // proxy = proxy.Remove(0, 6);
            }

            string uri;
            string[] creds = null;

            if (proxy.Contains("@"))
            {
                // Separate <user>:<pass> @ <ip>:<port>
                string[] splitd = proxy.Split('@');
                creds = splitd[0].Split(':');
                uri = "http://" + splitd[1];
            }
            else
                uri = "http://" + proxy;

            Console.WriteLine("{0}", uri);

            WebProxy wp = new WebProxy(new Uri(uri));

            if (creds != null)
            {
                wp.Credentials = new NetworkCredential(creds[0], creds[1]);
                wp.UseDefaultCredentials = false;
            }

            this.client.Proxy = wp;
        }

        private void setChunks(string chunks)
        {
            this.chunks = chunks;
            this.fetch = GetChunked;
        }

        private void setKey(string key)
        {
            this.key = key;
            // Not implemented
        }

        byte[] GetChunked(string url, int retry = 3, int timeout = 1)
        {
            Console.WriteLine("Getting {0} chunks of {1}", this.chunks, url);
            string[] splitd = url.Split('/');
            string executable = splitd[splitd.Length - 1];
            string filename = executable.Split('.')[0];

            byte[] str = null;

            string endpoint = String.Format("{0}//{1}/{2}/{2}.", splitd[0], splitd[2], filename, filename);
            int num = Int32.Parse(this.chunks);
            for (int i = 0; i <= num; i++)
            {
                byte[] chunk = null;

                while (retry >= 0 && chunk == null)
                {

                    string url_chunk = String.Format("{0}{1}", endpoint, i.ToString("D2"));
                    chunk = this.GetBytes(url_chunk, retry, timeout);

                    // First chunk
                    if (str == null)
                        str = chunk;
                    else
                    {
                        int current_lenght = str.Length;
                        Array.Resize(ref str, str.Length + chunk.Length);
                        Array.Copy(chunk, 0, str, current_lenght, chunk.Length);
                    }
                }
                if (chunk == null)
                {
                    Environment.Exit(-1);
                }
            }
            return str;
        }

        byte[] GetBytes(string url, int retry = 3, int timeout = 1)
        {
            Console.WriteLine($"{url}");

            // If https desired
            // ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            byte[] str = null;
            while (retry >= 0 && str == null)
            {
                try
                {
                    str = this.client.DownloadData(url);
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
    }
}
