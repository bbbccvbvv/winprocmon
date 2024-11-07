# winprocmon
Windows Process Monitor Cmd Tool

## 20241106

upload version v1.0

## 20241107

upload version v1.1
changelog
(1)fix bug in monitor specified process whose pid is invalid;
(2)fix bug in EnumAllProcess(), now we can get all process except IDLE(pid:0), SYSTEM(pid:4) and memory compression process;
(3)delete unused function;
(4)add new function PrintSystemMemoryInfo, use in future;
