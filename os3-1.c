#include <stdio.h>
#include <stdlib.h>

#define PAGESIZE (32)
#define PAS_FRAMES (256)                 // fit for unsigned char frame in PTE
#define PAS_SIZE (PAGESIZE * PAS_FRAMES) // 32*256 = 8192 B
#define VAS_PAGES (64)
#define VAS_SIZE (PAGESIZE * VAS_PAGES) // 32*64 = 2048 B
#define PTE_SIZE (4)                    // sizeof(pte)
#define PAGETABLE_FRAMES                                                       \
  (VAS_PAGES * PTE_SIZE / PAGESIZE) // 64*4/32 = 8 consecutive frames
#define PAGE_INVALID (0)
#define PAGE_VALID (1)

#define MAX_REFERENCES (256)
typedef struct {
  unsigned char frame; // allocated frame
  unsigned char vflag; // valid-invalid bit
  unsigned char ref;   // reference bit
  unsigned char pad;   // padding
} pte;                 // Page Table Entry (total 4 Bytes, always)

typedef struct {
  int pid;
  int ref_len; // Less than 255
  unsigned char *references;
} process_raw;

typedef struct {
  unsigned char b[PAGESIZE];
} frame; // 32 / 4 = 8pte

// =====================================================================================

#define TRUE 1
#define FALSE 0
#define NUM_MAX_PROC 10

// 원형 큐
// 출처: https://devpluto.tistory.com/
typedef struct {
  int data[NUM_MAX_PROC];
  int front, rear;
} queue;
void init(queue *q) { q->rear = q->front = -1; }
int is_empty(queue *q) { return q->front == q->rear; }
int is_full(queue *q) { return q->front == (q->rear + 1) % NUM_MAX_PROC; }
void enqueue(queue *q, int e) {
  if (is_full(q))
    printf("Overflow\n");
  else {
    q->rear = (q->rear + 1) % NUM_MAX_PROC;

    q->data[q->rear] = e;
  }
}
int dequeue(queue *q) {
  if (is_empty(q)) {
    printf("Empty\n");
    return 0;
  } else {
    q->front = (q->front + 1) % NUM_MAX_PROC;
    return q->data[q->front];
  }
}

// =======================================================================================

typedef struct {
  int pid;
  int ref_len;
} process_info; // 읽기 전용 프로세스 정보 구조체

typedef struct {
  int pid;
  int ref_len; // Less than 255
  unsigned char *references;
  int ref_index;  // references 순회를 위한 index
  int table_addr; // 테이블이 있는 물리주소
  int num_alloc;  // 통계용
  int num_ref;
  int num_fault;
} process;

process proc_arr[NUM_MAX_PROC]; // 조건에서 PID<10
frame *pas;
int num_proc;       // 입력으로 부터 읽은 프로세스 갯수
int free_frame = 0; // 할당 가능한 프레임
queue proc_queue;   // 시뮬레이션 구현을 위한 큐
int oom_flag = FALSE;

int get_free_frame(int pid, int num_frame) {
  process *proc = &proc_arr[pid];
  if (free_frame >= PAS_FRAMES) {
    return -1;
  }
  int base_frame = free_frame;
  proc->num_alloc += num_frame;
  free_frame += num_frame;
  return base_frame;
}

pte *get_pte(int table_addr, int page) {
  // int pte_addr = table_addr + page;
  // return (pte *)&pas[pte_addr];
  // printf("get_pte: %d %d\n", table_addr, page);
  int page_table_page = page / PAGETABLE_FRAMES;
  int entry_index = page % PAGETABLE_FRAMES;

  int frame_number = table_addr + page_table_page;

  frame *page_frame = &pas[frame_number];
  pte *pte_arr = (pte *)page_frame; // 크기 8의 pte array;

  return &pte_arr[entry_index];
}

// =======================================================================================

void print_process(int pid) {
  process *proc = &proc_arr[pid];
  printf("** Process %03d: Allocated Frames=%03d "
         "PageFaults/References=%03d/%03d\n",
         pid, proc->num_alloc, proc->num_fault, proc->num_ref);
}

void print_table(int pid) {
  process *proc = &proc_arr[pid];
  int table = proc->table_addr;

  for (int page = 0; page < VAS_PAGES; page++) {
    pte *entry = get_pte(table, page);

    if (entry->vflag == PAGE_INVALID)
      continue;

    printf("%03d -> %03d REF=%03d\n", page, entry->frame, entry->ref);
  }
}

void print_stat() {
  int allocated_frames = 0;
  int page_faults = 0;
  int references = 0;

  for (int pid = 0; pid < num_proc; pid++) {
    process *proc = &proc_arr[pid];

    allocated_frames += proc->num_alloc;
    page_faults += proc->num_fault;
    references += proc->num_ref;
  }

  printf("Total: Allocated Frames=%03d Page Faults/References=%03d/%03d\n",
         allocated_frames, page_faults, references);
}

void print_report() {
  if (oom_flag) {
    printf("Out of memory!!\n");
  }

  for (int pid = 0; pid < num_proc; pid++) {
    print_process(pid);
    print_table(pid);
  }

  print_stat();
}
// =======================================================================================

void init_page_table(int table_addr) {
  for (int page = 0; page < VAS_PAGES; page++) {
    pte *entry = get_pte(table_addr, page);
    entry->vflag = PAGE_INVALID;
    entry->ref = 0;
  }
}

// 이진파일에서 프로세스를 읽고 저장한 후 프로세스 갯수 반환
int load_process() {
  int pid = 0;

  while (fread(&proc_arr[pid], sizeof(process_info), 1, stdin) == 1) {
    process *proc = &proc_arr[pid];
    int ref_len = proc->ref_len;
    proc->references = (unsigned char *)malloc(ref_len * sizeof(unsigned char));

    // 참조할 페이지 주소들 읽기
    int num_read =
        fread(proc->references, sizeof(unsigned char), ref_len, stdin);

    if (ref_len != num_read) {
      fprintf(stderr, "읽기 오류!!");
      exit(-1);
    }

    // 페이지테이블 할당
    int frame = get_free_frame(pid, PAGETABLE_FRAMES);
    if (frame == -1) {
      oom_flag = TRUE;
      break;
    }
    proc->table_addr = frame;

    // 페이지테이블 초기화
    init_page_table(proc->table_addr);

    proc->num_fault = 0;
    proc->num_ref = 0;

    // 대기열에 삽입
    enqueue(&proc_queue, pid);
    pid++;
  }

  return pid;
}

void print_process_test(int num_proc) {
  for (int i = 0; i < num_proc; i++) {
    process *cur_proc = &proc_arr[i];
    printf("%d %d\n", cur_proc->pid, cur_proc->ref_len);

    for (int j = 0; j < cur_proc->ref_len; j++) {
      printf("%d ", cur_proc->references[j]);
    }
    printf("\n");
  }
}

int is_terminated(process *proc) { return proc->ref_index >= proc->ref_len; }

void runner() {
  // 프로세스가 번갈아가면서 페이지 참조
  while (!is_empty(&proc_queue)) {
    int pid = dequeue(&proc_queue);
    process *proc = &proc_arr[pid];

    if (is_terminated(proc)) {
      continue;
    }

    int ref_index = proc->ref_index;
    int page = proc->references[ref_index];
    pte *entry = get_pte(proc->table_addr, page);

    // page fault 처리
    if (entry->vflag == PAGE_INVALID) {

      int frame = get_free_frame(pid, 1);
      if (frame == -1) {
        oom_flag = TRUE;
        break;
      }

      proc->num_fault++;
      entry->frame = frame;
      entry->vflag = PAGE_VALID;
    }

    // printf("%d %d %d\n", pid, page, entry->frame);

    // reference
    proc->ref_index++;

    entry->ref++;
    proc->num_ref++;

    // 다음 큐에 처리
    enqueue(&proc_queue, pid);
  }

  return;
}

void deallocate() {
  // pas 동적해제
  free(pas);

  // references 동적해제
  for (int pid = 0; pid < NUM_MAX_PROC; pid++) {
    process *proc = &proc_arr[pid];
    free(proc->references);
  }
}

int main() {
  init(&proc_queue);
  pas = (frame *)malloc(PAS_SIZE); // PAS_SIZE=32*256

  num_proc = load_process();
  if (oom_flag) {
    print_report();
    return 0;
  }

  runner();
  print_report();

  // 할일: 전부다 동적 해제

  deallocate();

  return 0;
}

// 자율진도표: 매크로 코드 이해

// pas 할당, pas 타입?
// pas는 frame으로 이루어진 공간이네용
// 총 256개의 프레임에서 프로세스마다 각 8개의 프레임을 페이지테이블로 활용
// reference는 logical adress space의 page번호를 말하는거겠죠?

// 페이지테이블은 총 64개 엔트리, 즉 64개의 페이지(프레임) 정보를 포함할 수 있음
// 프로세스가 참조하는 페이지는 64이하, 0~63까지만
// 한 페이지테이블에 프로세스가 참조하는 모든 페이지를 넣을 수 있음

// 각 프로세스 자체는 어디에 할당?
// 없으면 page fault를 띄우고 필요할때 할당->즉시즉시할당

// 프레임 번호 == pas index

// pas(frame배열)에다가 연속적으로 pagetable할당
// pas에서 8*pid 부터 8*pid+7까지 페이지테이블 범위
// 0~7: 프로세스0 페이지 테이블
// 8~15: 프로세스1 페이지 테이블

// pas에서 할당가능한 프레임번호 freeframe number 가지고있는게 좋겟네.

// 대기열도 필요하다...