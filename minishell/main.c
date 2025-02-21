
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "main.h"  
//pid_t pid = 0;

 char prompt[25] = "msh";
char *cmd;          
int is_paused = 0;
int RET = 0, status;
int job_id = 1;     
int flag;

struct Node {
    int id;             
    pid_t pid;         
    char command[100];  
    struct Node *next;  
};
struct Node *head = NULL;

void insert_at_last(pid_t pid, char *cmd) 
{
    struct Node *new_node = malloc(sizeof(struct Node));
    if (!new_node)
    {
        perror("malloc failed");
        return;
    }
    new_node->pid = pid;
    new_node->id = job_id++; 
    strncpy(new_node->command, cmd, sizeof(new_node->command) - 1);
    new_node->command[sizeof(new_node->command) - 1] = '\0';
    new_node->next = NULL;

    if (head == NULL) 
    {
        head = new_node;
    }
    else
    {
        struct Node *temp = head;
        while (temp->next != NULL)
            temp = temp->next;
        temp->next = new_node;
    }
}

void remove_job(pid_t pid) 
{
    struct Node *temp = head, *prev = NULL;
    while (temp != NULL)
    {
        if (temp->pid == pid)
       	{
            if (prev == NULL)
                head = temp->next;
            else
                prev->next = temp->next;
            free(temp);
            return;
        }
        prev = temp;
        temp = temp->next;
    }
}

void bg_command() 
{
    if (head == NULL)
    {
        printf("No jobs to background\n");
        return;
    }
    struct Node *temp = head;
    while (temp->next != NULL)
        temp = temp->next;
    printf("[%d]+  %s    &\n", temp->id, temp->command);
    kill(temp->pid, SIGCONT);
    flag = 1;
}

void print_jobs() 
{
    struct Node *temp = head;
    while (temp != NULL)
    {
        int job_status;
        if (waitpid(temp->pid, &job_status, WNOHANG) == 0) 
	{
            printf("[%d]+ Running  %s\n", temp->id, temp->command);
        } else 
	{
            if (WIFEXITED(job_status) || WIFSIGNALED(job_status))
	    {
                printf("[%d]+ Done   %s\n", temp->id, temp->command);
                remove_job(temp->pid);
            }
	    else if (WIFSTOPPED(job_status))
	    {
                printf("[%d]+ Stopped   %s\n", temp->id, temp->command);
            }
        }
        temp = temp->next;
    }
}

void fg_command() 
{
    if (head == NULL)
    {
        printf("No jobs to foreground\n");
        return;
    }
    struct Node *temp = head, *prev = NULL;
    while (temp->next != NULL) 
    {
        prev = temp;
        temp = temp->next;
    }
    printf("Bringing job [%d] to foreground: %s\n", temp->id, temp->command);
    kill(temp->pid, SIGCONT);
    waitpid(temp->pid, &status, WUNTRACED);
    if (WIFSTOPPED(status))
    {
        printf("[%d]+ Stopped   %s\n", temp->id, temp->command);
    }
    else if (WIFEXITED(status) || WIFSIGNALED(status))
    {
        printf("[%d]+ Done   %s\n", temp->id, temp->command);
        if (prev == NULL)
            head = NULL;
        else
            prev->next = NULL;
        free(temp);
    }
}

void signal_handler(int signum)
{
    if (signum == SIGINT)
    {
        if (RET == 0)
       	{
            printf("\n");
        }
       	else
       	{
            printf("\nTerminating child process PID %d with SIGINT...\n", RET);
            kill(RET, SIGINT);
            waitpid(RET, &status, 0);
            if (WIFEXITED(status))
                printf("Child terminated with exit status %d\n", WEXITSTATUS(status));
            RET = 0;
        }
    } 
    else if (signum == SIGTSTP)
    {
        if (RET == 0)
       	{
            printf("No command is executing: enter a command\n");
        }
       	else 
	{
            //printf("Pausing child process PID %d with SIGTSTP...\n", RET);
	    //printf("%s",prompt);
	    printf(ANSI_COLOUR_CYAN"[%s]$"ANSI_COLOUR_MAGENTA,prompt);
            insert_at_last(RET, cmd);
            kill(RET, SIGTSTP);
            is_paused = 1;
        }
    } else if (signum == SIGCONT) {
        if (is_paused && RET != 0) {
            printf("Resuming child process PID %d with SIGCONT...\n", RET);
            kill(RET, SIGCONT);
            is_paused = 0;
        } else {
            printf("No paused process to continue.\n");
        }
    }
}

int check_ps1(char *input_string)
{
    if (strncmp(input_string, "PS1=", 4) == 0)
    {
        if (input_string[4] != ' ') 
	{
            return 1;
        }
        return 0;
    }
    return 2;
}

char *get_command(char *input_string)
{
    static char command[25] = {'\0'};
    int i = 0;
    while (*input_string != ' ' && *input_string != '\0') 
    {
        command[i++] = *input_string++;
    }
    command[i] = '\0';
    return command;
}

int check_command_type(char *command)
{
    char *builtins[] =
    {
        "echo", "printf", "read", "cd", "pwd", "pushd", "popd", "dirs",
        "let", "eval", "set", "unset", "export", "declare", "typecast",
        "readonly", "getopts", "source", "exit", "exec", "shopt", "caller",
        "true", "type", "hash", "bind", "help", "jobs", "fg", "bg", NULL
    };

    for (int i = 0; builtins[i] != NULL; i++) {
        if (strcmp(command, builtins[i]) == 0) {
            return BUILDIN;
        }
    }
    if (strcmp(command, "") == 0) 
    {
        return NO_COMMAND;
    }

    char *external_commands[155] = {NULL};
    extract_external_commands(external_commands);
    for (int i = 0; external_commands[i] != NULL; i++) 
    {
        if (strcmp(command, external_commands[i]) == 0)
       	{
            return EXTERNAL;
        }
    }
    return NO_COMMAND;
}

void execute_internal_command(char *input_string)
{
    if (strncmp("exit", input_string, 4) == 0) 
    {
        exit(0);
    }
    if (strncmp("pwd", input_string, 3) == 0)
    {
        system("pwd");
    }
    if (strncmp("cd", input_string, 2) == 0) 
    {
        int i, count = 0;
        for (i = 2; input_string[i] == ' '; i++)
       	{
            count++;
        }
        if (chdir(&input_string[2 + count]) == -1) 
	{
            perror("cd error");
        }
    }
    if (strncmp("jobs", input_string, 4) == 0)
    {
        print_jobs();
    }
    if (strncmp("fg", input_string, 2) == 0)
    {
        fg_command();
    }
    if (strncmp("bg", input_string, 2) == 0) 
    {
        bg_command();
    }
}

void echo(char *input_string, int status) 
{
    if (strcmp(input_string, "echo $?") == 0) 
    {
        printf("%d\n", status);
    }
    else if (strcmp(input_string, "echo $$") == 0)
    {
        printf("%d\n", getpid());
    }
    else if (strcmp(input_string, "echo $SHELL") == 0) 
    {
        char *shell = getenv("SHELL");
        if (shell)
       	{
            printf("%s\n", shell);
        }
       	else
       	{
            printf("Unknown shell\n");
        }
    }
}

void extract_external_commands(char **external_commands)
{
    char ch, buffer[25] = {'\0'};
    int i = 0, j = 0;
    int fd = open("external_commands.txt", O_RDONLY);
    if (fd == -1) 
    {
        return;
    }
    while (read(fd, &ch, 1) > 0) {
        if (ch != '\n') {
            buffer[i++] = ch;
        } 
	else 
	{
            external_commands[j] = calloc(strlen(buffer) + 1, sizeof(char));
            strcpy(external_commands[j++], buffer);
            memset(buffer, '\0', 25);
            i = 0;
        }
    }
    close(fd);
}

void scan_input(char *prompt, char input_string[])
{
    int ret;
    int f;
    flag = 0;
    while (1)
    {
        if (waitpid(RET, &status, WNOHANG) || flag == 0)
       	{
            printf(ANSI_COLOUR_CYAN"[%s]$"ANSI_COLOUR_MAGENTA,prompt);
            flag = 1;
        }
        scanf("%[^\n]", input_string);
        getchar(); 
        if ((f = check_ps1(input_string)) == 1)
       	{
            strcpy(prompt, input_string + 4);
            continue;
        
	}
       	else if (f == 0) 
	{
            printf("PS1 is invalid\n");
            continue;
        }
        cmd = get_command(input_string);
        ret = check_command_type(cmd);
        if (ret == EXTERNAL)
       	{
            RET = fork();
            if (RET == 0) 
	    { 
                signal(SIGINT, SIG_DFL);
                signal(SIGTSTP, SIG_DFL);
                char *argv[20];
                for (int i = 0; i < 10; i++)
	       	{
                    argv[i] = malloc(sizeof(char) * 20);
                }
                int j = 0, k = 0;
                for (int i = 0; input_string[i] != '\0'; i++) 
		{
                    if (input_string[i] != ' ')
		    {
                        argv[j][k++] = input_string[i];
                    }
		    else
		    {
                        argv[j][k] = '\0';
                        j++;
                        k = 0;
                    }
                }
                argv[j][k] = '\0';
                argv[j + 1] = NULL;
                int check_pipe = 0;
                int com_pos[10];
                int com_iter = 0;
                com_pos[com_iter++] = 0;
                int count = 1;  
                for (j = 1; argv[j] != NULL; j++)
	       	{
                    if (strcmp(argv[j], "|") == 0)
		    {
                        argv[j] = NULL;
                        check_pipe = 1;
                        com_pos[com_iter++] = j + 1;
                        count++;
                    }
                }
                if (!check_pipe)
	       	{
                    if (execvp(argv[0], argv) == -1)
		    {
                        printf("exec: No such file or directory\n");
                    }
                    exit(0);
                } 
		else
	       	{
                    int fd[2];
                    for (int i = 0; i < count; i++)
		    {
                        if (i < count - 1)
		       	{
                            if (pipe(fd) == -1)
			    {
                                printf("pipe error\n");
                            }
                        }
                        int ret = fork();
                        if (ret == 0) 
			{
                            if (i < count - 1) 
			    {
                                close(fd[0]);
                                dup2(fd[1], STDOUT_FILENO);
                            }
                            if (execvp(argv[com_pos[i]], &argv[com_pos[i]]) == -1)
			    {
                                printf("exec: No such file or directory\n");
                            }
                            exit(0);
                        }
		       	else if (ret > 0)
		       	{
                            int stat;
                            wait(&stat);
                            if (i < count - 1)
			    {
                                close(fd[1]);
                                dup2(fd[0], STDIN_FILENO);
                                close(fd[0]);
                            }
                        }
                    }
                    exit(0);
                }
            } else if (RET > 0) 
	    { 
                waitpid(RET, &status, WUNTRACED);
                if (WIFEXITED(status))
	       	{
                    printf("Child terminated with status %d\n", WEXITSTATUS(status));
                }
            }
        }
        else if (ret == BUILDIN)
       	{
            if (strcmp(cmd, "exit") == 0)
	    {
                exit(0);
            }
	    else if (strcmp(cmd, "pwd") == 0)
	    {
                char buffer[100];
                getcwd(buffer, 100);
                buffer[99] = '\0';
                printf("%s\n", buffer);
            } 
	    else if (strcmp(cmd, "cd") == 0)
	    {
                int i = 0;
                char *ptr = input_string;
                while (ptr[i] != ' ' && ptr[i] != '\0')
                    i++;
                if (chdir(ptr + i + 1) == -1)
	       	{
                    printf("directory change error\n");
                }

            }
	    else if (strcmp(cmd, "echo") == 0)
	    {
                char *ptr = input_string;
                int i = 0;
                while (ptr[i] != ' ' && ptr[i] != '\0')
                    i++;
                if (strcmp("$$", ptr + i + 1) == 0)
	       	{
                    printf("parent pid %d\n", getpid());
                }
	       	else if (strcmp("$?", ptr + i + 1) == 0)
	       	{
                    printf("last process: %d\n", WEXITSTATUS(status));
                }
	       	else if (strcmp("$SHELL", ptr + i + 1) == 0) 
		{
                    char *qtr = getenv("SHELL");
                    printf("%s\n", qtr ? qtr : "Unknown shell");
                }
            }
            else if (strcmp(cmd, "bg") == 0)
	    {
                bg_command();
            }
	    else if (strcmp(cmd, "fg") == 0) 
	    {
                fg_command();
            } else if (strcmp(cmd, "jobs") == 0)
	    {
                print_jobs();
            }
        }
        echo(input_string, status);
    }
}

int main() 
{
    signal(SIGINT, signal_handler);
    signal(SIGTSTP, signal_handler);
    printf("\033[H\033[J");
    char input_string[25];
    // prompt[25] = "msh";
    scan_input(prompt, input_string);
    return 0;
}

