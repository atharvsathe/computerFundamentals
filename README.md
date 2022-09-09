# Computer Fundamentals Projects

## Malloc Implementation
This project implemnets malloc, calloc, realloc functions with use of segregated explicit lists. This gives memory utilisation of 59% on the curated memory traces. Better fit algorithm and eliminating footers in allocated blocks boost the memory utilisation to around 70% but hampers the throughput of the system.

## Tiny Shell
This is a simple linux shell program that supports a simple form of job control and I/O redirection. The architecture allows each job to start a new process and start executing in that process while maintaining responsiveness of the shell. The commands supported by this implementation are
- quit: Quits the shell.
- jobs: Lists all the background jobs.
- bg job: Runs the job in the background.
- fg job: Runs the job in the foreground.

The shell implementation also handles SIGINT and SIGTSTP signals.

## Proxy Server
