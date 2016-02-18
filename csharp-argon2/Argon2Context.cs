﻿using System;
using System.Runtime.InteropServices;

namespace Liphsoft.Crypto.Argon2
{
    [StructLayout(LayoutKind.Sequential)]
    internal class Argon2Context
    {
        public IntPtr Out;
        public uint OutLen;

        public IntPtr Pwd;
        public uint PwdLen;

        public IntPtr Salt;
        public uint SaltLen;

        public IntPtr Secret;
        public uint SecretLen;

        public IntPtr AssocData;
        public uint AssocDataLen;

        public uint TimeCost;
        public uint MemoryCost;
        public uint Lanes;
        public uint Threads;

        public IntPtr AllocateCallback;
        public IntPtr FreeCallback;

        public uint Flags;
    }

    /*
    [StructLayout(LayoutKind.Sequential)]
    internal struct Argon2Context
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] Out;
        public uint OutLen;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] Pwd;
        public uint PwdLen;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 48)]
        public byte[] Salt;
        public uint SaltLen;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] Secret;
        public uint SecretLen;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] AssocData;
        public uint AssocDataLen;

        public uint TimeCost;
        public uint MemoryCost;
        public uint Lanes;
        public uint Threads;
    }
    */

    /*
    [StructLayout(LayoutKind.Sequential)]
    internal class Argon2Context
    {
        [MarshalAs(UnmanagedType.LPArray)]
        public byte[] Out;
        public uint OutLen;

        [MarshalAs(UnmanagedType.LPArray)]
        public byte[] Pwd;
        public uint PwdLen;

        [MarshalAs(UnmanagedType.LPArray)]
        public byte[] Salt;
        public uint SaltLen;

        [MarshalAs(UnmanagedType.LPArray)]
        public byte[] Secret;
        public uint SecretLen;

        [MarshalAs(UnmanagedType.LPArray)]
        public byte[] AssocData;
        public uint AssocDataLen;

        public uint TimeCost;
        public uint MemoryCost;
        public uint Lanes;
        public uint Threads;
    }
    */
}
