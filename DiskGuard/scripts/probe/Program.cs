// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

internal static class Program
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern IntPtr GetModuleHandleW(string name);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    private static extern IntPtr GetProcAddress(IntPtr module, string name);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private delegate int QueryProcess(IntPtr pid, StringBuilder box, IntPtr image, IntPtr sid, out uint session);

    private static object ReadFile(string path)
    {
        bool opened = false;
        try
        {
            using FileStream stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            opened = true;
            int value = stream.ReadByte();
            return new { open_succeeded = true, read_succeeded = true, bytes_read = value < 0 ? 0 : 1, error = (string?)null };
        }
        catch (Exception error)
        {
            return new { open_succeeded = opened, read_succeeded = false, bytes_read = 0, error = error.GetType().Name };
        }
    }

    private static object Enumerate(string path)
    {
        try
        {
            return new { succeeded = true, entry_count = Directory.GetFileSystemEntries(path).Length, error = (string?)null };
        }
        catch (Exception error)
        {
            return new { succeeded = false, entry_count = 0, error = error.GetType().Name };
        }
    }

    private static string SandboxName()
    {
        IntPtr module = GetModuleHandleW("SbieDll.dll");
        if (module == IntPtr.Zero) return string.Empty;
        IntPtr address = GetProcAddress(module, "SbieApi_QueryProcess");
        if (address == IntPtr.Zero) throw new InvalidOperationException("Injected SbieDll lacks SbieApi_QueryProcess");
        QueryProcess query = Marshal.GetDelegateForFunctionPointer<QueryProcess>(address);
        StringBuilder box = new(34);
        int status = query(new IntPtr(Environment.ProcessId), box, IntPtr.Zero, IntPtr.Zero, out _);
        if (status != 0) throw new InvalidOperationException($"SbieApi_QueryProcess failed: 0x{status:X8}");
        return box.ToString();
    }

    private static int Main(string[] args)
    {
        if (args.Length < 3) return 64;
        string directory = args[0];
        string allowedFile = args[1];
        string output = args[2];
        bool isChild = args.Length > 3 && args[3] == "--child";
        string boxName = SandboxName();
        int? childExitCode = null;
        if (!isChild)
        {
            ProcessStartInfo start = new(Environment.ProcessPath ?? throw new InvalidOperationException("Missing executable path"))
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            foreach (string argument in new[] { directory, allowedFile, output + ".child.json", "--child" })
                start.ArgumentList.Add(argument);
            using Process child = Process.Start(start) ?? throw new InvalidOperationException("Unable to start child");
            if (!child.WaitForExit(30000)) throw new TimeoutException("Child probe exceeded 30 seconds");
            childExitCode = child.ExitCode;
        }
        var result = new
        {
            timestamp_utc = DateTime.UtcNow,
            pid = Environment.ProcessId,
            box_name = boxName,
            is_child = isChild,
            child_exit_code = childExitCode,
            denied_file = ReadFile(Path.Combine(directory, "private.txt")),
            sibling_file = ReadFile(Path.Combine(directory + "Sibling", "public.txt")),
            allowed_file = ReadFile(allowedFile),
            directory_enumeration = Enumerate(directory),
        };
        File.WriteAllText(output, JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
        return 0;
    }
}
