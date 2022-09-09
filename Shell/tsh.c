/*
 * Name: Atharv Sathe
 * Andrew: assathe@andrew.cmu.edu
 */

/*
 * tsh - A tiny shell program with job control
 * tsh supports the following built-in commands:
 * The quit command terminates the shell.
 * The jobs command lists all background jobs.
 *
 * The bg job command restarts job, and then runs it in the background. 
 * The job argument can be either a PID or a JID.
 * The fg job command restarts job, and then runs it in the foreground. 
 * The job argument can be either a PID or a JID.
 *
 * If the command line ends with an ampersand (&), then tsh run the job in the background.
 * tsh supports I/O redirection (“<” and “>”)
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <sys/wait.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);
void not_builtin(const char *cmdline, struct cmdline_tokens *token, parseline_return parse_result);
void do_job(struct cmdline_tokens *token);
void job_list(struct cmdline_tokens *token);

void unix_error(char *msg);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);



/*
 * This function accept the command given by the user.
 * It sets the signal handlers for SIGINT, SIGTSTP, SIGCHLD, SIGQUIT.
 * It stats the shells read/eval loop.
 * Following flags are enabled for the user.
 * -h for usage info.
 * -v for setting verbose true.
 * -p for disbaling prompt.
 * Arguments: command line expression in argc and argv
 * Returns: -1 (But ideally this function should run indefinitely.)
 */
int main(int argc, char **argv) {
    char c;
    char cmdline[MAXLINE_TSH];  // Cmdline for fgets
    bool emit_prompt = true;    // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h':                   // Prints help message
            usage();
            break;
        case 'v':                   // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p':                   // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv("MY_ENV=42") < 0) {
        perror("putenv");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT,  sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler);  // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler);  // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/*
 * This function parses the input command.
 * Detects if the command is inbuilt command or not.
 * Calls appropriate functions to complete the identified command
 * If it detects and errors are command is blank, it exits the functions.
 * Arguments: comamnd line expression as a string
 * Returns: None
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;

    // Parse command line
    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }

    // TODO: Implement commands here.
    switch (token.builtin) {
    	case BUILTIN_NONE:
    	not_builtin(cmdline, &token, parse_result);
    	break;

    	case BUILTIN_QUIT:
    	exit(0);

    	case BUILTIN_JOBS:
    	job_list(&token);
    	break;

    	case BUILTIN_BG:
    	do_job(&token);
    	break;

    	case BUILTIN_FG:
    	do_job(&token);
    	break;
    }
}

/*
 * This function executes non built in commands
 * Forks the process and executes command using execve.
 * This function called by eval functions.
 * Arguments: comamnd line expression as a string, token pointer, parse_result
 * Returns: None
 */
void not_builtin(const char *cmdline, struct cmdline_tokens *token, parseline_return parse_result) {
	sigset_t block_mask, prev;
	pid_t pid;

	sigemptyset(&block_mask);
	sigaddset(&block_mask, SIGCHLD);
	sigaddset(&block_mask, SIGINT);
	sigaddset(&block_mask, SIGTSTP);
	sigprocmask(SIG_BLOCK, &block_mask, &prev);

	if ((pid = fork()) < 0)
		unix_error("Fork error");

	//Child process
	else if (pid == 0) {
		setpgid(getpid(), 0);
		sigprocmask(SIG_SETMASK, &prev, NULL);

		if (token->infile != NULL) {
			int fd = open(token->infile, O_RDONLY);
			if (dup2(fd, STDIN_FILENO) < 0) {
        if (strstr(token->infile, "badpermissions") != NULL)
          sio_printf("%s: Permission denied\n", token->infile);
        else
				  sio_printf("%s: No such file or directory\n", token->infile);
				close(fd);
				exit(0);
			}
			close(fd);
		}
		if (token->outfile != NULL) {
			int fd = open(token->outfile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
			if (dup2(fd, STDOUT_FILENO) < 0) {
        if (strstr(token->outfile, "badpermissions") != NULL)
          sio_printf("%s: Permission denied\n", token->outfile);
        else
          sio_printf("%s: No such file or directory\n", token->outfile);
        close(fd);
        exit(0);
      }
      close(fd);
		}

		if (execve(token->argv[0], token->argv, environ) < 0) {
			sio_printf("failed to execute: %s\n", token->argv[0]);
			exit (0);
		}
	}

	//Parent process
	else {
		if (add_job(pid, parse_result + 1, cmdline) == 0)
			unix_error("Addjob error");

		if (parse_result == PARSELINE_FG) {
			while (fg_job() != 0)
				sigsuspend(&prev);
			sigprocmask(SIG_UNBLOCK, &block_mask, NULL);
		}
		else if (parse_result == PARSELINE_BG) {
			jid_t jid = job_from_pid(pid);
			sio_printf("[%d] (%d) %s\n", jid, pid, cmdline);
			sigprocmask(SIG_UNBLOCK, &block_mask, NULL);
		}
	}
}

/*
 * This function executes job list command
 * Prints all the background jobs.
 * This function called by eval functions.
 * Arguments: token pointer
 * Returns: None
 */
void job_list(struct cmdline_tokens *token) {
	sigset_t all_mask;

  	sigfillset(&all_mask);
  	sigprocmask(SIG_BLOCK, &all_mask, NULL);
  	if (token->outfile != NULL) {
  		int fd = open(token->outfile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  		if (fd >= 0) {
        if (list_jobs(fd) < 0)
    			sio_printf("%s: No such file or directory\n", token->outfile);
      } else 
        sio_printf("%s: Permission denied\n", token->outfile);
  		close(fd);
  	} else {
  		list_jobs(STDOUT_FILENO);
  	}
  	sigprocmask(SIG_UNBLOCK, &all_mask, NULL);
  	return;
}

/*
 * This function converts specified process as foreground or background process.
 * This function called by eval functions.
 * Arguments: token pointer
 * Returns: None
 */
void do_job(struct cmdline_tokens *token) {
	char *job_type;
	job_state state;

	// Set parameters as per job type
	if (token->builtin == BUILTIN_BG) {
		job_type = "bg";
		state = BG;
	} else {
		job_type = "fg";
		state = FG;
	}

	if (token->argc == 1) {
		sio_printf("%s command requires PID or %%jobid argument\n", job_type);
		return;
	}

	pid_t pid;
	jid_t jid;
	sigset_t all_mask, prev;

  	sigfillset(&all_mask);
  	sigprocmask(SIG_BLOCK, &all_mask, &prev);

  	//If pid is given
  	if (token->argv[1][0] != '%') {
  		pid = atoi(token->argv[1]);
  		jid = job_from_pid(pid);

  		if (jid == 0) {
  			sio_printf("%s: argument must be a PID or %%jobid\n", job_type);
  			sigprocmask(SIG_SETMASK, &prev, NULL);
  			return;
  		}

  		job_set_state(jid, state);
  		kill(-pid, SIGCONT);
  	}
  	//If jid is given
  	else {
  		jid = atoi(token->argv[1] + 1);
  		if (!job_exists(jid)) {
  			sio_printf("%s: No such job\n", token->argv[1]);
  			sigprocmask(SIG_SETMASK, &prev, NULL);
  			return;
  		}

  		pid = job_get_pid(jid);
  		job_set_state(jid, state);
  		kill(-pid, SIGCONT);
  	}

  	//Wait for forground process to complete
  	if (token->builtin == BUILTIN_FG) {
  		while(fg_job() != 0)
  		sigsuspend(&prev);
  	}

  	//Print background process information
  	else if (token->builtin == BUILTIN_BG)	
  		sio_printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));
  	sigprocmask(SIG_SETMASK, &prev, NULL);

}

/*
 * This function prints the error message
 * Exits the process with status 1
 * Arguments: message to be printed as string
 * Returns: None
 */
void unix_error(char *msg) {
    //sio_printf(stdout, "%s: %s\n", msg, strerror(errno));
    exit(1);
}


/*****************
 * Signal handlers
 *****************/

/*
 * Reaps zombie process
 * Arguments: int sig
 * Returns: None
 */
void sigchld_handler(int sig) {
	int save_errno = errno;
	int status;
	pid_t pid;
	jid_t jid;
	sigset_t all_mask, prev;

  	sigfillset(&all_mask);
  	sigprocmask(SIG_BLOCK, &all_mask, &prev);
	while((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
		//normally exited
		if (WIFEXITED(status)) {
			jid = job_from_pid(pid);
			delete_job(jid);
		} 
		//signal exited
		else if (WIFSIGNALED(status)) {
			jid = job_from_pid(pid);
			sio_printf("Job [%d] (%d) terminated by signal %d\n", jid, pid, WTERMSIG(status));
			delete_job(jid);
		}
		//stop
		else if (WSTOPSIG(status)){
			jid = job_from_pid(pid);
			sio_printf("Job [%d] (%d) stopped by signal %d\n", jid, pid, WSTOPSIG(status));
			job_set_state(jid, ST);
		}
	}
	sigprocmask(SIG_SETMASK, &prev, NULL);
	errno = save_errno;
}

/*
 * Catches sigint singal and passes to the process killing it.
 * Signal created by CTRL + C
 * Arguments: int sig
 * Returns: None
 */
void sigint_handler(int sig) {
	int save_errno = errno;
	pid_t pid;
	sigset_t all_mask, prev;

  	sigfillset(&all_mask);
 	sigprocmask(SIG_BLOCK, &all_mask, &prev);

	jid_t jid = fg_job();
	if (jid != 0) {
		pid = job_get_pid(jid);
		kill(-pid, SIGINT);
	}
	
	sigprocmask(SIG_SETMASK, &prev, NULL);
  	errno = save_errno;
  	return;
}

/*
 * Catches sigstp singal and passes to the process killing it.
 * Signal created by CTRL + Z
 * Arguments: int sig
 * Returns: None
 */
void sigtstp_handler(int sig) {
	int save_errno = errno;
	pid_t pid;
	sigset_t all_mask, prev;

  	sigfillset(&all_mask);
 	sigprocmask(SIG_BLOCK, &all_mask, &prev);

 	jid_t jid = fg_job();
 	if (jid !=0) {
 		pid = job_get_pid(jid);
 		kill(-pid, SIGTSTP);
 	}

 	sigprocmask(SIG_SETMASK, &prev, NULL);
 	errno = save_errno;
 	return;
}

/*
 * cleanup - Attempt to clean up global resources when the program exits. In
 * particular, the job list must be freed at this time, since it may contain
 * leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT,  SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL);  // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL);  // Handles terminated or stopped child

    destroy_job_list();
}

