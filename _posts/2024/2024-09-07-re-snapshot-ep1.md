---
layout: post
title: RE Snapshot Ep.1 - Identifying Process Injection in Malware
date: 07-09-2024
categories: [Malware, Obfuscation]
tag: [Malware, Obfuscation]
---

![Banner RE Ep.1](assets/images/blogs/RE-Ep1/Banner-RE-Ep1.png)

Process injection is used by attackers to evade detection by running their malware inside running, legitamate processes. In this first **RE Snapshot** episode, we'll look at how attackers achieve process injection at a basic level, and more importantly, we'll look at how to detect process injection by analysing running processes.

## What is process injection?

Process injection is a specific type of code injection that occurs when an attacker injects malicious code into a running process. Under the guise of legitimate system activity, the malicious code can run and access system resources without triggering alarms from native security solutions like Windows Defender.

Attackers can achieve process injection in a few ways, as described below...

### DLL Injection

DLL injection works by running code within the address space of another process by forcing it to load a dynamic link library (DLL). It works by utilising certain Windows API calls – a DLL is loaded into the target process's memory space, where its functions can then be executed.

Before injecting a DLL into a process, the target process must be selected. The first step to achieve DLL injection is normally to enumerate the running processes on the machine to identify lucrative ones that could be injected into. The process ID (or PID) is required to open a handle to the target and allow the necessary work to be done.

The code block below shows how the initial stages of DLL injection might work. It's written in **C** and uses Windows' Tool Help Library to iterate over the list of currently running processes. The objective of this code is to find a certain process by its name (`szProcessName`), then get its process ID (`dwProcessId`), and a handle to this process with all access rights (`hProcess`).

```c
PROCESSENTRY32	Process = {
 .dwSize = sizeof(PROCESSENTRY32) 
};

HANDLE hSshot = NULL;

hSshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

Process32First(hSshot, &Process)

do {
	if (wcscmp(Process.szExeFile, szProcessName) == 0) {
		*dwProcessId = Proc.th32ProcessID;
		*hProcess    = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Process.th32ProcessID);

		break;
	}
} while (Process32Next(hSshot, &Process));
```

* It starts with initializing a `PROCESSENTRY32` structure.

* It then calls `CreateToolhelp32Snapshot` to take a snapshot of all currently running processes. The snapshot is stored in the `hSshot` handle.

* After creating the snapshot, it calls `Process32First` to get information about the first process from this snapshot, storing the data in the Process structure.

* After getting the first process, it enters a loop. In this loop, the wcscmp function is used to compare the name of the current process (`Process.szExeFile`) to the target process name (`szProcessName`). The malware will populate `szProcessName` with the process it wants to inject into (e.g. `notepad.exe`)

* If the names match, it means that the loop has found the target process. It stores the process ID into `dwProcessId`, solicits a handle to this process using `OpenProcess` with all access rights and stores it into `hProcess`. After doing these tasks, it breaks the loop.

* If the names don't match, the code calls `Process32Next` to move to the next process in the snapshot and repeat the loop. This continues until it has iterated through all the processes in the snapshot or found the target process.

If you spot this code pattern in malware, it indicates potential process injection or fingerprinting of a system.

After the running processes have been identified and a handle to the target process has been opened, memory needs to be allocated in the target process. This is done using [VirtualAllocEx WinAPI](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex), shown below.

```c++
LPVOID VirtualAllocEx(
  [in]           HANDLE hProcess,
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);
```
Next, the [WriteProcessMemory WinAPI](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) is used to write the buffer at `lpBaseAddress`, which then writes the directory path of the malicious DLL inside the target executable. `lpBaseAddress` is the starting point of the newly created memory and the `hProcess` argument contains the handle to the target program that's being injected into.

```c++
BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,               // A handle to the process whose memory to be written to
  [in]  LPVOID  lpBaseAddress,          // Base address in the specified process to which data is written
  [in]  LPCVOID lpBuffer,               // A pointer to the buffer that contains data to be written to 'lpBaseAddress'
  [in]  SIZE_T  nSize,                  // The number of bytes to be written to the specified process	
  [out] SIZE_T  *lpNumberOfBytesWritten // A pointer to a 'SIZE_T' variable that receives the number of bytes written
);
```

To execute the malicious DLL inside the running process, the [LoadLibraryA WinAPI](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) is used and is called through `kernel32.dll`, and the address of `LoadLibraryA` is stored as a variable. All `LoadLibaryA` requires is the name of the target file, which in this case would be the legitimate executable being injected.

```c++
HMODULE LoadLibraryA(
  [in] LPCSTR lpLibFileName
);
```
Finally, `CreateRemoteThread` is called to create a thread that runs in the virtual address space of the target executable. This will also result in the malicious DLL running.

There are a few main API functions you should look out for when investigating a DLL injection:

* `OpenProcess`: This function gives a handle for the target process that can be used in subsequent calls to manipulate the process.

* `CreateToolhelp32Snapshot`: This function is used to take a snapshot of the specified processes, as well as the heaps, modules, and threads used by those processes.

* `VirtualAllocEx`: This function is used to reserve or commit memory space within a specified process which can be used for storing the DLL path.

* `WriteProcessMemory`: This function is used to write data to an area of memory in a specified process. In the case of DLL injection, this could mean writing the path of a DLL to the target process's memory.

* `CreateRemoteThread`: This function is often used to create a thread in another process, which can point to and execute the code stored in a DLL, resulting in injection.

### Shellcode Injection

Shellcode injection works in a very similar way to DLL injection in the sense that it uses some of the same API functions:

* `VirtualAllocEx`: Memory allocation
* `WriteProcessMemory`: Write the payload to the remote process
* `VirtualProtectEx`: Modify memory protection to change them to executable or writable
* `CreateRemoteThread`: Payload execution via a new thread

#### Worked Example

Below is an example of a shellcode injection. This example uses the x64dbg debugger so you can see exactly what's going on and how the shellcode operates under the hood.

The first thing an attacker needs to do to achieve shellcode injection is to identify a running process to inject into. This example uses `notepad.exe`.

Shown below is the malicious executable responsible for facilitating the shellcode injection, `shellcode-injection-test.exe`. It's being used to inject shellcode into `notepad.exe` by identifying its process ID and deobfuscating its own payload. Then using `VirtualAlloc`, it will eventually allocate the memory address `0x000001B54020000` to be the location where the payload is written.

![shellcode injection in terminal](assets/images/blogs/RE-Ep1/shellcode-injection-terminal.png)

To prove the concept, when opening a x64dbg session, you'd attach it to `shellcode-injection-test.exe` (or your malware). Locate the memory address where the deobfuscated payload is to see it in the dump. (A later blog post will show you how to write this malware to test for yourself).

![shellcode injection in x64dbg](assets/images/blogs/RE-Ep1/shellcode-injection-debugger.png)

If you were to open another x64dbg and attach it to the victim process, `notepad.exe`, with `PID 10992`, you wouldn't be able to navigate to the `Deobfuscated Payload At : 0x0000023DDB7E1410` address. This is because the deobfuscation routine is happening inside the local malicious process `shellcode-injection-test.exe` (which isn't attached to Notepad yet), not in `notepad.exe`.

![shellcode injection exxpression](assets/images/blogs/RE-Ep1/shellcode-injection-expression.png)

However, after the use of `VirtualAlloc` allocating the memory region, `Allocated Memory At : 0x000001B5402E0000`, this memory region has been zeroed out ready for writing, as shown in the screenshot below in the dump section of the debugger. The allocated memory location is full of zeros.

![shellcode injection shown in notepad](assets/images/blogs/RE-Ep1/shellcode-injection-notepad-debugger.png)

Looking at the x64dbg session attached to `notepad.exe`, when `shellcode-injection-test.exe` writes the payload (as shown in the screenshot below), the zeroed-out memory address is finally written to, and you can now navigate to it. Review the picture above and below – you'll notice the bytes starting at `FC 48 83 E4` are exactly the same, proving the process injection was a success.

![shellcode injection successful](assets/images/blogs/RE-Ep1/shellcode-injection-success.png)

> **Note:** The exact memory addresses will be different each time the malware or **notepad.exe** is run.
{: .prompt-tip }

### PE Injection

Portable execution (PE) injection is a method of executing arbitrary code in the address space of a separate live process. It works by injecting a compiled piece of code into the memory of another currently active process, which then executes the payload, allowing it to run masquerading as another process.

PE injection is often used to evade process-based detection and to elevate privileges and is commonly performed by copying code into the virtual address space of the target process before invoking it via a new thread. The write can be performed with native WinAPI calls, such as `VirtualAllocEx` and `WriteProcessMemory`, then invoked with `CreateRemoteThread` or through the use of a shellcode.

The list below shows some of the API calls that are common to PE injection (some of which are the same as those used in shellcode injection and DLL injection):

* `OpenProcess` : Used to obtain a handle to the target process
* `VirtualAllocEx` : Used to allocate memory within the target process to store the PE file
* `WriteProcessMemory` : Used to write the PE file into the allocated space
* `CreateRemoteThread` : Used to create a thread in the target process that starts executing the injected PE file

#### Debugging process for PE Injection

First, you'd need to open the x64dbg debugger and attach it to the malicious executable, then find the main function.

There are common API functions to look out for when investigating process injection. Once you **Step Into** the main function and scroll through, you'll normally find some telltale API calls. The screenshot below shows some of those API functions in an example, custom written piece of malware, `VirtualAlloc`, `OpenProcess`, and `VirtualAllocEx`.

![pe injection API calls](assets/images/blogs/RE-Ep1/pe-injection-api-calls.png)

If you were to set a breakpoint at `OpenProcess` and run the program up to here, a handle would be opened to `notepad.exe`, which was created via `CreateProcess` earlier in the execution. Now the breakpoint is set on `OpenProcess`, look at the `mov r8d` instruction and review the register. You'd notice that the hex value of `r8` at this time is `CB0`. You'd need to convert this hex value to decimal using a programmer calculator, and you'll get `3248`. Compare this to the PID for the running `notepad.exe` and you'll notice they're the same. The values in the registers will of cours ebe different with every malware sample, but the general process outlined above is repeatable.

![pe injection mem size in calc](assets/images/blogs/RE-Ep1/pe-injection-calc.png)

By scrolling down further, you'd notice `CreateRemoteThread`. You'd need to set a breakpoint and run up to this point, and you'll be able to see the memory address in `r9 – 0000021826221181`. That's the `EntryPoint` of the thread of the new injected process. Again, the values will be different with each analysis, but the overall process is repeatable.

![pe injection remote thread](assets/images/blogs/RE-Ep1/pe-injection-remotethread.png)

You can search for this memory address by opening a new debugger session (without closing the existing one) and attaching it to the active `notepad.exe` session, or whatever exutable the attacker selects as their victim process.

Head to **File > Attach**, then find **notepad.exe**, ensuring the PID is the same as the one identified in the code from **OpenProcess**. This will enable you to attach your debugger to the running notepad session. Once attached, right-click in the disassembly, select **Go to > Expression**, and search for the memory address (`0000021826221181`) from the fourth argument (`r9`) created by the **CreateRemoteThread** API. It'll be identified in the memory of `notepad.exe`.

![pe injection expression](assets/images/blogs/RE-Ep1/pe-injection-expression.png)

Once you click **OK**, you'll be taken to the memory address, which will be the `EntryPoint` of the thread. Set a breakpoint here. Ensure the `notepad.exe` debugger session is in the `running` state.

From there, go back to the debugger session that contains the malicious executable. Click **Run** in that session and return to the debugger session with `notepad.exe`. You'll notice that the `RIP` pointer has stopped execution on the breakpoint you just set.

After running past the injected executable from the debugger session attached to `notepad.exe`, investigate the malware where you can potentially find indicators of compromise. In the picture below, these IoC's are the malware's configuration, including their C2 domain.

![pe injection with campaign details from config](assets/images/blogs/RE-Ep1/pe-injection-rsp.png)

In later episodes of RE Snapshot, we will cover other evasive techniques used by attackers, as well as teaching you how to write custom malware so you can test these defensive techniques for yourself.





























