using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace AppProxy.UI.Services;

public static class PeInspector
{
    private const uint SHGFI_ICON = 0x000000100;
    private const uint SHGFI_LARGEICON = 0x000000000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEINFO
    {
        public IntPtr hIcon;
        public int iIcon;
        public uint dwAttributes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szDisplayName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]
        public string szTypeName;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SHGetFileInfoW(
        string pszPath,
        uint dwFileAttributes,
        out SHFILEINFO psfi,
        uint cbSizeFileInfo,
        uint uFlags);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    public static string DetectArchitecture(string exePath)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
                return "x64";

            using var fs = new FileStream(exePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var br = new BinaryReader(fs);

            if (fs.Length < 64) return "x64";
            ushort dosMagic = br.ReadUInt16();
            if (dosMagic != 0x5A4D) return "x64"; // MZ

            fs.Seek(0x3C, SeekOrigin.Begin);
            int peOffset = br.ReadInt32();
            if (peOffset <= 0 || peOffset + 24 > fs.Length) return "x64";

            fs.Seek(peOffset, SeekOrigin.Begin);
            uint peSig = br.ReadUInt32();
            if (peSig != 0x00004550) return "x64"; // PE\0\0

            ushort machine = br.ReadUInt16();
            ushort numberOfSections = br.ReadUInt16();
            fs.Seek(12, SeekOrigin.Current); // TimeDateStamp + PointerToSymbolTable + NumberOfSymbols
            ushort sizeOfOptionalHeader = br.ReadUInt16();
            br.ReadUInt16(); // Characteristics

            if (machine == 0x8664) return "x64";
            if (machine == 0xAA64) return "arm64";
            if (machine != 0x014C) return "x64";

            // Machine == 0x014C (x86 / AnyCPU IL). Inspect CLR header to detect AnyCPU x64.
            long optionalStart = fs.Position;
            if (sizeOfOptionalHeader >= 216 && optionalStart + sizeOfOptionalHeader <= fs.Length)
            {
                ushort optMagic = br.ReadUInt16();
                if (optMagic == 0x010B) // PE32
                {
                    fs.Seek(optionalStart + 92, SeekOrigin.Begin);
                    uint numDataDirs = br.ReadUInt32();
                    if (numDataDirs > 14)
                    {
                        fs.Seek(optionalStart + 96 + (14 * 8), SeekOrigin.Begin);
                        uint clrRva = br.ReadUInt32();
                        uint clrSize = br.ReadUInt32();
                        if (clrRva != 0 && clrSize >= 72)
                        {
                            long sectionsStart = optionalStart + sizeOfOptionalHeader;
                            long clrFileOffset = RvaToFileOffset(fs, br, sectionsStart, numberOfSections, clrRva);
                            if (clrFileOffset > 0 && clrFileOffset + 20 <= fs.Length)
                            {
                                fs.Seek(clrFileOffset + 16, SeekOrigin.Begin);
                                uint corFlags = br.ReadUInt32();
                                const uint COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002;
                                if ((corFlags & COMIMAGE_FLAGS_32BITREQUIRED) == 0 && Environment.Is64BitOperatingSystem)
                                {
                                    return "x64";
                                }
                            }
                        }
                    }
                }
            }

            return "x86";
        }
        catch
        {
            return "x64";
        }
    }

    private static long RvaToFileOffset(FileStream fs, BinaryReader br, long sectionsStart, ushort count, uint rva)
    {
        for (int i = 0; i < count; i++)
        {
            long secOffset = sectionsStart + (i * 40L);
            if (secOffset + 40 > fs.Length) break;
            fs.Seek(secOffset + 8, SeekOrigin.Begin);
            uint virtualSize = br.ReadUInt32();
            uint virtualAddr = br.ReadUInt32();
            uint rawSize = br.ReadUInt32();
            uint rawPtr = br.ReadUInt32();
            uint span = Math.Max(virtualSize, rawSize);
            if (rva >= virtualAddr && rva < virtualAddr + span)
            {
                return rawPtr + (rva - virtualAddr);
            }
        }
        return -1;
    }

    public static ImageSource? ExtractIcon(string exePath)
    {
        if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
            return null;

        try
        {
            IntPtr hImg = SHGetFileInfoW(exePath, 0, out SHFILEINFO shfi, (uint)Marshal.SizeOf<SHFILEINFO>(), SHGFI_ICON | SHGFI_LARGEICON);
            if (hImg == IntPtr.Zero || shfi.hIcon == IntPtr.Zero)
                return null;

            try
            {
                var src = Imaging.CreateBitmapSourceFromHIcon(
                    shfi.hIcon,
                    Int32Rect.Empty,
                    BitmapSizeOptions.FromEmptyOptions());
                src.Freeze();
                return src;
            }
            finally
            {
                DestroyIcon(shfi.hIcon);
            }
        }
        catch
        {
            return null;
        }
    }
}
