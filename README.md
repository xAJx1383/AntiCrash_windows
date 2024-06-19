# AntiCrash_windows
a simple Dll file that can be loaded by program to prevent Program to crash because of some exception

List Of Exceptions Can trigger AnitCrash:
- EXCEPTION_ACCESS_VIOLATION
- EXCEPTION_BREAKPOINT
- EXCEPTION_ILLEGAL_INSTRUCTION
- EXCEPTION_PRIV_INSTRUCTION
- EXCEPTION_FLT_DIVIDE_BY_ZERO

# How To Use it?
every thing that load the dll in process:
Inject it(with injector or Modify IAt or Something Like Ultimate-ASI-Loader) or
load it via program it self
