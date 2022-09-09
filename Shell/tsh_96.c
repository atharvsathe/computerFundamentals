/*
 * TODO: Include your name and Andrew ID here.
 */

/*
 * TODO: Delete this comment and replace it with your own.
 * tsh - A tiny shell program with job control
 * <The line above is not a sufficient documentation.
 *  You will need to write your program documentation.
 *  Follow the 15-213/18-213/15-513 style guide at
 *  http://www.cs.cmu.edu/~213/codeStyle.html.>
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
void do_background_job(struct cmdline_tokens *token);
void do_foreground_job(struct cmdline_tokens *token);
void job_list(struct cmdline_tokens *token);

void unix_error(char *msg);
void Sigfillset(sigset_t *set);
void Sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
void Sigaddset(sigset_t *set, int sig);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);



/*
 * TODO: Delete this comment and replace it with your own.
 * <Write main's function header documentation. What does main do?>
 * "Each function should be prefaced with a comment describing the purpose
 *  of the function (in a sentence or two), the function's arguments and
 *  return value, any error cases that are relevant to the caller,
 *  any pertinent side effects, and any assumptions that the function makes."
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
 * TODO: Delete this comment and replace it with your own.
 * <What does eval do?>
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
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
    	do_background_job(&token);
    	break;

    	case BUILTIN_FG:
    	do_foreground_job(&token);
    	break;
    }
}

void not_builtin(const char *cmdline, struct cmdline_tokens *token, parseline_return parse_result) {
	sigset_t block_mask, prev;
	pid_t pid;

	sigemptyset(&block_mask);
	Sigaddset(&block_mask, SIGCHLD);
	Sigaddset(&block_mask, SIGINT);
	Sigaddset(&block_mask, SIGTSTP);
	Sigprocmask(SIG_BLOCK, &block_mask, &prev);

	if ((pid = fork()) < 0)
		unix_error("Fork error");

	//Child process
	else if (pid == 0) {
		setpgid(getpid(), 0);
		Sigprocmask(SIG_SETMASK, &prev, NULL);

		if (token->infile != NULL) {
			int fd = open(token->infile, O_RDONLY);
			if (dup2(fd, STDIN_FILENO) < 0) {
				sio_printf("%s: No such file or directory\n", token->infile);
				close(fd);
				exit(0);
			}
			close(fd);
		}
		if (token->outfile != NULL) {
			int fd = open(token->outfile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
			if (dup2(fd, STDOUT_FILENO) < 0) {
                sio_printf("%s: No such file or directory\n", token->outfile);
                close(fd);
                exit(0);
            }
            close(fd);
		}

		if (execve(token->argv[0], token->argv, environ) < 0) {
			printf("failed to execute: %s\n", token->argv[0]);
			exit (0);
		}
	}

	//Parent process
	else {
		//job_state state = FG ? parse_result == PARSELINE_FG : BG;
		if (add_job(pid, parse_result + 1, cmdline) == 0)
			unix_error("Addjob error");

		if (parse_result == PARSELINE_FG) {
			//wait_for_foreground_job(jid);
			//wait(NULL);
			while (fg_job() != 0)
				sigsuspend(&prev);
			Sigprocmask(SIG_UNBLOCK, &block_mask, NULL);
		}
		else if (parse_result == PARSELINE_BG) {
			jid_t jid = job_from_pid(pid);
			sio_printf("[%d] (%d) %s\n", jid, pid, cmdline);
			Sigprocmask(SIG_UNBLOCK, &block_mask, NULL);
		}
	}
}

void job_list(struct cmdline_tokens *token) {
	sigset_t all_mask;

  	sigfillset(&all_mask);
  	Sigprocmask(SIG_BLOCK, &all_mask, NULL);
  	if (token->outfile != NULL) {
  		int fd = open(token->outfile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  		if (list_jobs(fd) < 0)
  			sio_printf("%s: No such file or directory\n", token->outfile);
  		close(fd);
  	} else {
  		list_jobs(STDOUT_FILENO);
  	}
  	Sigprocmask(SIG_UNBLOCK, &all_mask, NULL);
  	return;
}


void do_background_job(struct cmdline_tokens *token) {
	if (token->argc == 1) {
		sio_printf("bg command requires PID or %%jobid argument\n");
		return;
	}

	pid_t pid;
	jid_t jid;
	sigset_t all_mask, prev;

  	sigfillset(&all_mask);
  	Sigprocmask(SIG_BLOCK, &all_mask, &prev);

  	//If pid is given
  	if (token->argv[1][0] != '%') {
  		pid = atoi(token->argv[1]);
  		jid = job_from_pid(pid);

  		if (jid == 0) {
  			sio_printf("bg: argument must be a PID or %%jobid\n");
  			Sigprocmask(SIG_SETMASK, &prev, NULL);
  			return;
  		}

  		job_set_state(jid, BG);
  		kill(-pid, SIGCONT);
  	}
  	//If jid is given
  	else {
  		jid = atoi(token->argv[1] + 1);
  		if (!job_exists(jid)) {
  			sio_printf("%s: No such job\n", token->argv[1]);
  			Sigprocmask(SIG_SETMASK, &prev, NULL);
  			return;
  		}

  		pid = job_get_pid(jid);
  		job_set_state(jid, BG);
  		kill(-pid, SIGCONT);
  	}
  	sio_printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));
  	Sigprocmask(SIG_SETMASK, &prev, NULL);

}

void do_foreground_job(struct cmdline_tokens *token) {
	if (token->argc == 1) {
		sio_printf("fg command requires PID or %%jobid argument\n");
		return;
	}

	pid_t pid;
	jid_t jid;
	sigset_t all_mask, prev;

  	sigfillset(&all_mask);
  	Sigprocmask(SIG_BLOCK, &all_mask, &prev);

  	//If pid is given
  	if (token->argv[1][0] != '%') {
  		pid = atoi(token->argv[1]);
  		jid = job_from_pid(pid);

  		if (jid == 0) {
  			sio_printf("fg: argument must be a PID or %%jobid");
  			Sigprocmask(SIG_SETMASK, &prev, NULL);
  			return;
  		}

  		job_set_state(jid, FG);
  		kill(-pid, SIGCONT);
  	}
  	//If jid is given
  	else {
  		jid = atoi(token->argv[1] + 1);
  		if (!job_exists(jid)) {
  			sio_printf("%s: No such job\n", token->argv[1]);
  			Sigprocmask(SIG_SETMASK, &prev, NULL);
  			return;
  		}

  		pid = job_get_pid(jid);
  		job_set_state(jid, FG);
  		kill(-pid, SIGCONT);
  	}

  	while(fg_job() != 0)
  		sigsuspend(&prev);
  	Sigprocmask(SIG_SETMASK, &prev, NULL);
}

void unix_error(char *msg) {
    //sio_printf(stdout, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

void Sigfillset(sigset_t *set) {
    if (sigfillset(set) < 0)
        unix_error("Sigfillset error");
    return;
}

void Sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
    if (sigprocmask(how, set, oldset) < 0)
        unix_error("Sigprocmask error");
    return;
}

void Sigaddset(sigset_t *set, int sig) {
    if (sigaddset(set, sig) < 0)
        unix_error("Sigaddset error");
    return;	
}
/*****************
 * Signal handlers
 *****************/

/*
 * TODO: Delete this comment and replace it with your own.
 * <What doehows sigchld_handler do?>
 */
void sigchld_handler(int sig) {
	int save_errno = errno;
	int status;
	pid_t pid;
	jid_t jid;
	sigset_t all_mask, prev;

  	sigfillset(&all_mask);
	while((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
		//normally exited
		if (WIFEXITED(status)) {
			Sigprocmask(SIG_BLOCK, &all_mask, &prev);
			jid = job_from_pid(pid);
			delete_job(jid);
			Sigprocmask(SIG_SETMASK, &prev, NULL);
		} 
		//signal exited
		else if (WIFSIGNALED(status)) {
			Sigprocmask(SIG_BLOCK, &all_mask, &prev);
			jid = job_from_pid(pid);
			sio_printf("Job [%d] (%d) terminated by signal %d\n", jid, pid, WTERMSIG(status));
			delete_job(jid);
			Sigprocmask(SIG_SETMASK, &prev, NULL);
		}
		//stop
		else if (WSTOPSIG(status)){
			Sigprocmask(SIG_BLOCK, &all_mask, &prev);
			jid = job_from_pid(pid);
			sio_printf("Job [%d] (%d) stopped by signal %d\n", jid, pid, WSTOPSIG(status));
			job_set_state(jid, ST);
			Sigprocmask(SIG_SETMASK, &prev, NULL);
		}
	}
	errno = save_errno;
}

/*
 * TODO: Delete this comment and replace it with your own.
 * <What does sigint_handler do?>
 */
void sigint_handler(int sig) {
	int save_errno = errno;
	pid_t pid;
	sigset_t all_mask, prev;

  	sigfillset(&all_mask);
 	Sigprocmask(SIG_BLOCK, &all_mask, &prev);

	jid_t jid = fg_job();
	if (jid != 0) {
		pid = job_get_pid(jid);
		kill(-pid, SIGINT);
	}
	
	Sigprocmask(SIG_SETMASK, &prev, NULL);
  	errno = save_errno;
  	return;
}

/*
 * TODO: Delete this comment and replace it with your own.
 * <What does sigtstp_handler do?>
 */
void sigtstp_handler(int sig) {
	int save_errno = errno;
	pid_t pid;
	sigset_t all_mask, prev;

  	sigfillset(&all_mask);
 	Sigprocmask(SIG_BLOCK, &all_mask, &prev);

 	jid_t jid = fg_job();
 	if (jid !=0) {
 		pid = job_get_pid(jid);
 		kill(-pid, SIGTSTP);
 	}

 	Sigprocmask(SIG_SETMASK, &prev, NULL);
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

