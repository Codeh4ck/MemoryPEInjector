# Memory PE Injector
A tool that reads a PE file from a byte array buffer and injects it into memory.

# Summary
Memory PE Injector is a C++ class which reads an executable file (PE) from a byte array
and maps it into the memory space of another process. This is commonly known as **Process Forking**
or **RunPE**. To accomplish this, the code follows these steps:

* The code launches a second instance of the program containing the code, in suspended mode.
* It unmaps the PE from the virtual memory space where it is loaded
* The given PE byte array is then mapped in place.
* The process is resumed and the end result is the PE file of the byte array running instead.

# Usage and Tips
This code can be used in various scenarios. One of these scenarios is a case where you want to pack another program with your own one,
but you'd like to deploy one executable only. You can add your second program in the resources of your first one, in an **RT_RCDATA**
resource, then read the bytes and inject it directly into memory, without dropping it on the disk.

**Usage:**
```c++
  Injector *injector = new Injector();
  unsigned char *lpByteBuffer = injector->ReadFileBytes(L"C:/The/path/to/your/executable.exe");
  injector->Inject(lpByteBuffer);
```


