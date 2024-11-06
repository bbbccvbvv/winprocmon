(1)winprocmon -v/winprocmon --version
Get winprocmon's version message
(2)winprocmon -h/winprocmon --help
Get winprocmon's help message
(3)winprocmon
Print top 10 process's workingset and pagefile order by workingset per 10 seconds.
(4)winprocmon -p 12345
Print process's monitor msg which pid is 12345 per 10 seconds.
(5)winprocmon -p 12345 -t 5
Print process's monitor msg which pid is 12345 per 5 seconds.
(6)winprocmon -n 5 -t 5
Print top 5 process's monitor msg per 5 seconds.
(7)winprocmon -n 5 -t 5 -file c:\\1.txt
Print top 5 process's monitor msg per 5 seconds and save monitor msg to file c:\\1.txt.