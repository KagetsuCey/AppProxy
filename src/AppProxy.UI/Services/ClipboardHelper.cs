using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;

namespace AppProxy.UI.Services;

/// <summary>
/// Fast, non-blocking clipboard helper that writes CF_UNICODETEXT directly via Win32 first
/// (avoiding WPF's 1000ms-per-call OleFlushClipboard stall), with a non-flushing WPF fallback.
/// </summary>
internal static class ClipboardHelper
{
    private const uint CF_UNICODETEXT = 13;
    private const uint GMEM_MOVEABLE = 0x0002;

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EmptyClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetClipboardData(uint uFormat, IntPtr hMem);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsClipboardFormatAvailable(uint format);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetClipboardData(uint uFormat);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalAlloc(uint uFlags, UIntPtr dwBytes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalUnlock(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalFree(IntPtr hMem);

    public static bool TrySetText(string text, out string? errorMessage)
    {
        text ??= string.Empty;

        if (TrySetTextWin32(text, out string? win32Error))
        {
            errorMessage = null;
            return true;
        }

        try
        {
            // Fallback with copy: false so WPF never triggers OleFlushClipboard's 10x100ms stall on the UI thread.
            Clipboard.SetDataObject(text, copy: false);
            errorMessage = null;
            return true;
        }
        catch (Exception ex)
        {
            errorMessage = !string.IsNullOrWhiteSpace(win32Error)
                ? win32Error
                : (ex.Message ?? "无法访问系统剪贴板");
            return false;
        }
    }

    public static bool TryGetText(out string text, out string? errorMessage)
    {
        if (TryGetTextWin32(out text, out string? win32Error))
        {
            errorMessage = null;
            return true;
        }

        try
        {
            text = Clipboard.ContainsText() ? Clipboard.GetText() : string.Empty;
            errorMessage = null;
            return true;
        }
        catch (Exception ex)
        {
            text = string.Empty;
            errorMessage = !string.IsNullOrWhiteSpace(win32Error)
                ? win32Error
                : (ex.Message ?? "无法读取系统剪贴板");
            return false;
        }
    }

    private static bool TryGetTextWin32(out string text, out string? errorMessage)
    {
        text = string.Empty;
        bool opened = false;
        int lastOpenError = 0;
        for (int attempt = 0; attempt < 5; attempt++)
        {
            if (OpenClipboard(IntPtr.Zero))
            {
                opened = true;
                break;
            }
            lastOpenError = Marshal.GetLastWin32Error();
            Thread.Sleep(10);
        }

        if (!opened)
        {
            errorMessage = new Win32Exception(lastOpenError).Message;
            return false;
        }

        try
        {
            if (!IsClipboardFormatAvailable(CF_UNICODETEXT))
            {
                errorMessage = null;
                return true;
            }

            IntPtr hData = GetClipboardData(CF_UNICODETEXT);
            if (hData == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                errorMessage = err == 0 ? null : new Win32Exception(err).Message;
                return err == 0;
            }

            IntPtr ptr = GlobalLock(hData);
            if (ptr == IntPtr.Zero)
            {
                errorMessage = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                return false;
            }

            try
            {
                text = Marshal.PtrToStringUni(ptr) ?? string.Empty;
                errorMessage = null;
                return true;
            }
            finally
            {
                GlobalUnlock(hData);
            }
        }
        finally
        {
            CloseClipboard();
        }
    }

    private static bool TrySetTextWin32(string text, out string? errorMessage)
    {
        bool opened = false;
        int lastOpenError = 0;
        for (int attempt = 0; attempt < 5; attempt++)
        {
            if (OpenClipboard(IntPtr.Zero))
            {
                opened = true;
                break;
            }
            lastOpenError = Marshal.GetLastWin32Error();
            Thread.Sleep(10);
        }

        if (!opened)
        {
            errorMessage = new Win32Exception(lastOpenError).Message;
            return false;
        }

        try
        {
            if (!EmptyClipboard())
            {
                errorMessage = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                return false;
            }

            char[] chars = text.ToCharArray();
            nuint bytes = (nuint)((chars.Length + 1) * sizeof(char));
            IntPtr hGlobal = GlobalAlloc(GMEM_MOVEABLE, bytes);
            if (hGlobal == IntPtr.Zero)
            {
                errorMessage = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                return false;
            }

            IntPtr ptr = GlobalLock(hGlobal);
            if (ptr == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                GlobalFree(hGlobal);
                errorMessage = new Win32Exception(err).Message;
                return false;
            }

            try
            {
                if (chars.Length > 0)
                {
                    Marshal.Copy(chars, 0, ptr, chars.Length);
                }
                Marshal.WriteInt16(ptr, chars.Length * sizeof(char), 0);
            }
            finally
            {
                GlobalUnlock(hGlobal);
            }

            if (SetClipboardData(CF_UNICODETEXT, hGlobal) == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                GlobalFree(hGlobal);
                errorMessage = new Win32Exception(err).Message;
                return false;
            }

            // Ownership of hGlobal transferred to Windows on SetClipboardData success.
            errorMessage = null;
            return true;
        }
        finally
        {
            CloseClipboard();
        }
    }
}
