# winprocmon

Windows Process Monitor Cmd Tool

# usage

winprocmon [no argument] || [-h||--help||-v||--version] || [-f||--file file_path][-n||--number top_process_number][-t||--time time_seconds][-p||--pid specified_process_id]

no argument    Print top 10 process's working set and pagefile order by working set per 10 seconds.

-f, --file     Save process memory info to specified file.

-h, --help     Get help for commamds.

-n, --number   Number of top process need saving.

-p, --pid      Pid of specified process need saving.

-t, --time     Time(seconds) between two check.

-v, --version  Show version number and quit.
