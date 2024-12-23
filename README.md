# winprocmon
Windows Process Monitor Cmd Tool

## 20241106

upload version v1.0

## 20241107

upload version v1.1

changelog

(1)fix:fix bug in monitor specified process whose pid is invalid;

(2)fix:fix bug in EnumAllProcess(), now we can get all process except IDLE(pid:0), SYSTEM(pid:4) and memory compression process;

(3)refactor:delete unused function;

(4)feat:add new function PrintSystemMemoryInfo, use in future;

## 20241111

upload version v1.2

changelog

(1)feat:print system info;

(2)fix:fix file disorder exception; 

(3)refactor:add file fflush after write;

## 20241223

upload version v1.3

changelog

(1)change complier from msvc to mingw;
