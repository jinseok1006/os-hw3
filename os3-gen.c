#include <stdio.h>
#include <stdlib.h>
#include <time.h>

typedef struct{
    int pid;
    int ref_len;    //Less than 255    
    unsigned char *references;
} process;

#if 1    //DEBUG
#define debug(fmt, args...) fprintf(stderr, fmt, ##args)
#else
#define debug(fmt, args...)
#endif

#define CHANGE_WORKSET (8)

void generate(int num_processes) {
    int i,j, workset_len=1, workset_pivot=0;
    process *cur;
    
    debug("Generate() start num_processes = %d\n", num_processes);

    for(i=0; i<num_processes; i++) {
        cur = (process*) malloc(sizeof(process));

        cur->pid = i;
        cur->ref_len = rand()%192+64;   //64~255
        cur->references = (unsigned char*) malloc(cur->ref_len);

        debug("# PID=%02d\n", cur->pid);
        debug("# REF_LEN=%03d\n", cur->ref_len);
        fwrite(cur, sizeof(int), 2, stdout);

        for(j=0; j<cur->ref_len;j++) {
            if(j%workset_len == 0) {    //j==0 and workset_len==1 at init
                workset_len = CHANGE_WORKSET + rand()%CHANGE_WORKSET;  //8+0~7 = 8~15
                workset_pivot = rand()%60;   //Change Working Set: 0~59
            }
            if(rand()%10 != 0) {    //90% -> in working set, 10% -> not in
                cur->references[j] = workset_pivot + rand()%5;    //0~59 + 0~4 = 0~63
            } else {
                cur->references[j] = rand()%64;    //0~63
            }
            
            //debug("# REF[%02d]=%02d\n", j, cur->references[j]);
            debug("%02d ", cur->references[j]);
        }
        fwrite(cur->references, sizeof(unsigned char), cur->ref_len, stdout);
        debug("\n");
    }

    debug("Generate() end\n");
}

//parameter 1 : number of processes

int main(int argc,char* argv[]){    
    srand((unsigned int)time(NULL) + atoi(*++argv));

    generate(atoi(*argv));
    
    return 0;
}