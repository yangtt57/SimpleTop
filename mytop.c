#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <utmp.h>
#include <unistd.h>
#include <stdint.h>
#include <pwd.h>
#include <sys/types.h>
#include <curses.h>

int R_stat = 0, S_stat = 0, T_stat = 0, Z_stat = 0;
int total = 0;
double totaltime_2;
unsigned long long total_mem;
int cursorrow = 1;
int maxrow = 36;
WINDOW *scrn;
// time
void showtime()
{
    // top - 19:52:24 up  4:44,  6 users,  load average: 0.21, 0.31, 0.29
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t sec = tv.tv_sec;
    struct tm *lt = localtime(&sec);
    printw("top-: %02d:%02d:%02d up  ", lt->tm_hour, lt->tm_min, lt->tm_sec);
    FILE *file = fopen("/proc/uptime", "r");
    if (file == NULL)
    {
        // perror("Fail open /proc/uptime!");
        exit(1);
    }
    double runtime;
    if (fscanf(file, "%lf", &runtime) == 0)
    {
        // perror("Fail fscanf /proc/uptime!");
        exit(1);
    }
    fclose(file);
    if (runtime < 3600)
    {
        printw("%d min,  ", (int)runtime / 60);
    }
    else
    {
        printw("%d:%d,  ", (int)runtime / 3600, (int)runtime % 60);
    }
    // number of users
    struct utmp *entry;
    int users = 0;
    setutent(); // 打开文件utmp，并且将文件指针指向文件的最开始。
    while ((entry = getutent()) != NULL)
    {
        if (entry->ut_type == USER_PROCESS)
        {
            users++;
        }
    }
    printw("%d users,  ", users);
    // load average
    char buf[16];
    file = fopen("/proc/loadavg", "r");
    if (file == NULL)
    {
        // perror("Fail open /proc.loadavg!");
        exit(1);
    }
    else
    {
        fgets(buf, sizeof(buf), file);
        printw("load average: %s\n", buf);
    }
    fclose(file);
}
// tasks
void showtask()
{
    DIR *dir;
    struct dirent *entry;
    dir = opendir("/proc/");
    if (!dir)
    {
        // perror("Fail open /proc");
        exit(1);
    }
    char path[270];
    char state;
    char buf[32];
    FILE *stat;
    while ((entry = readdir(dir)) != NULL)
    {
        if (atoi(entry->d_name))
        {
            sprintf(path, "/proc/%s/status", entry->d_name);
            stat = fopen(path, "r");
            if (stat == NULL)
            {
                // perror("Fail open /proc/xxxxx/status");
                exit(1);
            }
            while (fgets(buf, 32, stat))
            {
                if (buf[0] == 'S' && buf[1] == 't' && buf[2] == 'a' && buf[3] == 't' && buf[4] == 'e')
                {
                    state = buf[7];
                    break;
                }
            };
            fclose(stat);
            // judgement of state
            if (state == 'R')
            {
                R_stat++;
                total++;
            }
            else if (state == 'S' || state == 'I')
            {
                S_stat++;
                total++;
            }
            else if (state == 'T')
            {
                T_stat++;
                total++;
            }
            else if (state == 'Z')
            {
                Z_stat++;
                total++;
            }
            else
            {
                total++;
            }
        }
    }
    printw("Tasks: %d total,   %d running, %d sleeping,   %d stopped,   %d zombie\n",
           total, R_stat, S_stat, T_stat, Z_stat);
    closedir(dir);
}
// cpu -- 两个时间点采样
void showcpu()
{
    system("rm diff.sh;echo \"cat /proc/stat | head -n 1 > diff.txt;sleep 0.1;cat /proc/stat | head -n 1 >> diff.txt;\">diff.sh;");
    system("bash diff.sh");
    FILE *file = fopen("diff.txt", "r");
    if (file == NULL)
    {
        // perror("Fail open diff.txt");
        exit(1);
    }
    char t[128], t_[128];
    fgets(t, sizeof(t), file);
    char *token = strtok(t, " ");
    double cpu_time_1[10], totaltime_1 = 0, cpu_time_2[10];
    totaltime_2 = 0;
    int i = 0;
    while (token != NULL)
    {
        if (strcmp(token, "cpu") != 0)
        {
            cpu_time_1[i++] = atoi(token);
        }
        token = strtok(NULL, " ");
    }
    cpu_time_1[9] = 0;
    fgets(t, sizeof(t), file);
    token = strtok(t, " ");
    i = 0;
    while (token != NULL)
    {
        if (strcmp(token, "cpu") != 0)
        {
            cpu_time_2[i++] = atoi(token);
        }
        token = strtok(NULL, " ");
    }
    cpu_time_2[9] = 0;

    double us, sy, ni, id, wa, hi, si, st;
    for (int i = 0; i < 10; i++)
    {

        totaltime_1 += cpu_time_1[i];
        totaltime_2 += cpu_time_2[i];
    }
    double difftime = totaltime_2 - totaltime_1;

    us = (cpu_time_2[0] + cpu_time_2[1] - cpu_time_1[0] - cpu_time_1[1]) * 100 / difftime;
    sy = (cpu_time_2[2] - cpu_time_1[2]) * 100 / difftime;
    ni = (cpu_time_2[1] - cpu_time_1[1]) * 100 / difftime;
    id = (cpu_time_2[3] - cpu_time_1[3]) * 100 / difftime;
    wa = (cpu_time_2[4] - cpu_time_1[4]) * 100 / difftime;
    hi = (cpu_time_2[5] - cpu_time_1[5]) * 100 / difftime;
    si = (cpu_time_2[6] - cpu_time_1[6]) * 100 / difftime;
    st = (cpu_time_2[7] - cpu_time_1[7]) * 100 / difftime;

    printw("%%Cpu(s): %.1lf us, %.1lf sy, %.1lf ni, %.1lf id %.1lf wa, %.1lf hi, %.1lf si, %.1lf st\n", us, sy, ni, id, wa, hi, si, st);

    fclose(file);
}

// mem
/*
MiB Mem :   3871.5 total,    354.8 free,   2157.0 used,   1359.8 buff/cache
MiB Swap:   3898.0 total,   3191.6 free,    706.4 used.   1469.8 avail Mem
*/
void showmem()
{
    FILE *file = fopen("/proc/meminfo", "r");
    if (file == NULL)
    {
        // perror("Fail open /proc/meminfo");
        exit(1);
    }
    unsigned long long free_mem, stotal_mem, sfree_mem, avai_mem, buff_mem, cache_mem;
    float total, free, avai, buffer, cache, stotal, sfree;
    char buf[128];
    while (fgets(buf, sizeof(buf), file))
    {
        if (sscanf(buf, "MemTotal: %llu kB", &total_mem))
        {
            total = total_mem / 1024.0;
        }
        else if (sscanf(buf, "MemFree: %llu kB", &free_mem))
        {
            free = free_mem / 1024.0;
        }
        else if (sscanf(buf, "SwapTotal: %llu kB", &stotal_mem))
        {
            stotal = stotal_mem / 1024.0;
        }
        else if (sscanf(buf, "SwapFree: %llu kB", &sfree_mem))
        {
            sfree = sfree_mem / 1024.0;
        }
        else if (sscanf(buf, "MemAvailable: %llu kB", &avai_mem))
        {
            avai = avai_mem / 1024.0;
        }
        else if (sscanf(buf, "Buffers: %llu kB", &buff_mem))
        {
            buffer = buff_mem / 1024.0;
        }
        else if (sscanf(buf, "Cached: %llu kB", &cache_mem))
        {
            cache = cache_mem / 1024.0;
        }
    }
    printw("MiB Mem :   %.1f total,    %.1f free,   %.1f used,   %.1f buff/cache\n",
           total,
           free,
           total - free - buffer - cache,
           buffer + cache);
    printw("MiB Swap:   %.1f total,   %.1f free,    %.1f used.   %.1f avail Mem\n",
           stotal,
           sfree,
           stotal - sfree,
           avai);
    fclose(file);
}
// processes
/*
 PID USER      PR  NI    VIRT    RES    SHR    %CPU  %MEM     TIME+ COMMAND
 %d %s %d %d %d %d %d %.1f %.1f %s %s
 153290 ado       20   0   92680  43372  13696 S   3.9   1.1   0:16.19 cpptools
*/
struct pinfo
{
    int pid;
    uid_t uid;
    char cmd[256];
    char time[16];
    char stat[2];
    int PR;
    int NI;
    int VmSize;
    int VmRSS;
    int RssFile;
    float cpuUsage;
    float memUsage;
};
void showprocess()
{
    int currow = 1;
    char buf[256];
    char path[300];
    struct pinfo process;
    struct passwd *pw;
    DIR *dir;
    struct dirent *entry;
    dir = opendir("/proc/");
    if (!dir)
    {
        // perror("Fail open /proc");
        exit(1);
    }

    while ((entry = readdir(dir)) != NULL)
    {
        if (atoi(entry->d_name))
        {
            sprintf(path, "/proc/%s/stat", entry->d_name);
            FILE *stat = fopen(path, "r");
            if (stat == NULL)
            {
                // // perror("Fail open /proc/xxxxx/stat");
                exit(1);
            }
            fgets(buf, sizeof(buf), stat);
            char *token = strtok(buf, " ");
            int i = 0;
            while (token != NULL)
            {
                if (i == 0)
                {
                    process.pid = atoi(token);
                }
                if (i == 1)
                {
                    strcpy(process.cmd, token);
                    int j;
                    for (j = 0; j < strlen(process.cmd) - 2; j++)
                    {
                        process.cmd[j] = process.cmd[j + 1];
                    }
                    process.cmd[j] = '\0';
                }
                if (i == 2)
                {
                    strcpy(process.stat, token);
                }
                if (i == 13)
                {
                    process.cpuUsage = (float)atoi(token);
                }
                if (i == 14)
                {
                    process.cpuUsage += (float)atoi(token);
                    int hours, minutes, seconds;
                    hours = (int)(process.cpuUsage / 3600);
                    minutes = (int)((process.cpuUsage - hours * 3600) / 60);
                    seconds = (int)(process.cpuUsage - hours * 3600 - minutes * 60);
                    int res = sprintf(process.time, "%01d:%02d.%02d", hours, minutes, seconds);
                    if (res < 0)
                    {
                        // // perror("fail time\n");
                    }
                    process.cpuUsage = process.cpuUsage * 100 / totaltime_2;
                }
                if (i == 17)
                {
                    process.PR = atoi(token);
                }
                if (i == 18)
                {
                    process.NI = atoi(token);
                    break;
                }
                i++;
                token = strtok(NULL, " ");
            }
            // memset(path,0,300);
            sprintf(path, "/proc/%s/status", entry->d_name);
            // printf("%s\n",path);
            FILE *status = fopen(path, "r");
            if (status == NULL)
            {
                // perror("Fail open /proc/xxxxx/status");
                exit(1);
            }
            while (fgets(buf, sizeof(buf), status))
            {
                if (buf == (strstr(buf, "Uid:")))
                {
                    sscanf(buf, "Uid:\t%u\t%*u\t%*u\t%*u", &process.uid);
                }
                else if (buf == (strstr(buf, "RssFile:")))
                {
                    sscanf(buf, "RssFile:\t\t%d kB", &process.RssFile);
                }
                else if (buf == (strstr(buf, "VmSize:")))
                {
                    sscanf(buf, "VmSize:\t%d kB", &process.VmSize);
                }
                else if (buf == (strstr(buf, "VmRSS:")))
                {
                    sscanf(buf, "VmRSS:\t\t%d kB", &process.VmRSS);
                }
            }
            fclose(status);
            struct passwd *pw = getpwuid(process.uid);
            if (process.VmRSS == 0 || process.VmSize == 0)
                process.memUsage = 0;
            else
                process.memUsage = (float)(process.VmRSS * 100.0 / total_mem);
            if (currow >= cursorrow)
            {
                if (strcmp(process.cmd, "top") == 0)
                {
                    attron(A_STANDOUT);
                    printw("%d\t%s\t%d\t%d\t%d\t%d\t%d %s\t%.1f\t%.1f\t%s\t%s\n",
                           process.pid, pw->pw_name, process.PR, process.NI, process.VmSize, process.VmRSS, process.RssFile, process.stat, process.cpuUsage, process.memUsage, process.time, process.cmd);
                    attroff(A_STANDOUT);
                }
                else
                    printw("%d\t%s\t%d\t%d\t%d\t%d\t%d %s\t%.1f\t%.1f\t%s\t%s\n",
                           process.pid, pw->pw_name, process.PR, process.NI, process.VmSize, process.VmRSS, process.RssFile, process.stat, process.cpuUsage, process.memUsage, process.time, process.cmd);
            }
            memset(&process.pid, 0, 4);
            memset(&process.PR, 0, 4);
            memset(&process.NI, 0, 4);
            memset(&process.stat, 0, 2);
            memset(&process.time, 0, 16);
            process.uid = 0;
            process.RssFile = 0;
            process.VmRSS = 0;
            process.VmSize = 0;
            process.cpuUsage = 0;
            process.memUsage = 0;
            currow++;
        }
    }
    closedir(dir);
}

int main()
{
    scrn = initscr();
    cursorrow=atoi(getenv("cursorrow"));
    noecho(); 
    cbreak(); 
    while (1)
    {
        // setscrreg(30,40);
        R_stat = 0, S_stat = 0, T_stat = 0, Z_stat = 0;
        total = 0;
        totaltime_2 = 0;
        total_mem = 0;
        erase();
        attron(A_STANDOUT);
        printw("21312872-yangtengteng\n");
        attroff(A_STANDOUT);
        showtime();
        showtask();
        showcpu();
        showmem();
        printw("\n");
        attron(A_STANDOUT);
        printw("PID\tUSER\tPR\tNI\tVIRT\tRES\tSHR\t%%CPU\t%%MEM\tTIME+\tCOMMAND\n");
        attroff(A_STANDOUT);
        showprocess();
        move(LINES - 1, COLS - 100);
        printw("%d",cursorrow);
        clrtoeol();

        char c = getch();
        if (c == 'u')
            cursorrow--;
        else if (c == 'd')
            cursorrow++;
        refresh();
    }
    char s[25];
    itoa(cursorrow,s,10);
    setenv("cursorrow",s,1);
    endwin();
    return 0;
}
