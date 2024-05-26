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


#define TRUE 1
#define FALSE 0
#define NUM_MAX_PROC 10

// ###################################################
// # 원형 큐                         
// # 출처: https://devpluto.tistory.com/    
// ###################################################
typedef struct {
  int data[NUM_MAX_PROC+2];
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

// ###################################################
// # 시뮬레이터를 위한 구조체 및 프레임 할당/엔트리 추출 함수
// ###################################################
typedef struct {
  int pid;
  int ref_len;
} process_info; // 이진파일 읽기 전용 프로세스 정보 구조체

// 실제 시뮬레이션에서 필요한 정보를 포함한 프로세스 구조체
typedef struct {
  int pid;
  int ref_len; // Less than 255
  unsigned char *references;
  int ref_index;  // references 순회를 위한 index
  int table_addr; // 테이블이 있는 물리주소

  // 단순 출력을 위한 멤버
  int num_alloc;  // 할당된 프레임 갯수
  int num_ref;  // 참조한 횟수
  int num_fault; // 페이지 폴트가 발생한 횟수
} process;

process proc_arr[NUM_MAX_PROC]; // 조건에서 PID<10
frame *pas;
int num_proc;       // 입력으로 부터 읽은 프로세스 갯수
int free_frame = 0; // 할당 대기중인 다음 프레임 번호
queue proc_queue;   // 라운드 로빈 형태의 프로세스 처리를 구현
int oom_flag = FALSE; // 메모리 초과 여부

// num_frame만큼 물리 메모리에서 프레임을 할당하고, 
// 할당된 프레임의 시작 주소(기준 프레임)를 반환하는 함수.
// 만약 할당 가능한 프레임이 부족하면 -1을 반환한다.
int get_free_frame(int pid, int num_frame) {
  process *proc = &proc_arr[pid];

  // 물리 메모리 초과
  if (free_frame >= PAS_FRAMES) {
    return -1;
  }
  
  // 할당할 길이만큼 다음 시작 주소로 업데이트하고, 기존 시작주소를 반환함으로써
  // num_frame크기만큼의 공간을 확보한다.
  int base_frame = free_frame;
  proc->num_alloc += num_frame;
  free_frame += num_frame;
  return base_frame;
}

// 주어진 테이블 주소와 페이지 번호를 기반으로 
// 페이지 테이블 엔트리(pte)를 반환하는 함수.
pte *get_pte(int table_addr, int page) {
  int page_table_page = page / PAGETABLE_FRAMES; // 8개의 consecutive 프레임중 특정 테이블 프레임
  int entry_index = page % PAGETABLE_FRAMES; // 특정 테이블 프레임에서의 entry

  // 특정 테이블의 물리주소
  int frame_number = table_addr + page_table_page;

  // 계산된 프레임 번호에서 프레임 가져오기
  frame *page_frame = &pas[frame_number];
  // 프레임을 pte 배열로 캐스팅 (크기 8의 pte array)
  pte *pte_arr = (pte *)page_frame;

  return &pte_arr[entry_index];
}

// ###################################################
// # 출력을 위한 보고서 함수(helper function)
// ###################################################
// 각 프로세스의 시뮬레이션 결과를 출력
// 프로세스 ID, 할당된 프레임 수, 페이지 폴트 수, 참조 수를 출력한다.
void print_process(int pid) {
  process *proc = &proc_arr[pid];
  printf("** Process %03d: Allocated Frames=%03d "
         "PageFaults/References=%03d/%03d\n",
         pid, proc->num_alloc, proc->num_fault, proc->num_ref);
}

// 주어진 프로세스의 페이지 테이블 정보를 출력하는 함수.
// 프로세스의 페이지 테이블을 순회하면서 유효한 페이지 엔트리(pte)의 프레임과 참조 수를 출력한다.
void print_table(int pid) {
  process *proc = &proc_arr[pid];
  int table = proc->table_addr;

  for (int page = 0; page < VAS_PAGES; page++) {
    pte *entry = get_pte(table, page);

    // pte가 invalid한 경우 무시
    if (entry->vflag == PAGE_INVALID)
      continue;

    printf("%03d -> %03d REF=%03d\n", page, entry->frame, entry->ref);
  }
}

// 전체 시스템의 통계 정보를 출력
// 모든 프로세스의 할당된 프레임 수, 페이지 폴트 수, 참조 수를 누적하여 출력한다.
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

// 시뮬레이션 종료 이후, 각 프로세스의 시뮬레이션 결과 및 테이블 정보와 전체 통계 정보를 출력한다.
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

// ###################################################
// # 시뮬레이션을 위한 함수
// ###################################################
// 페이지 테이블을 초기화하는 함수.
// 주어진 페이지 테이블 주소에 대해 모든 페이지 항목을 INVALID로 설정하고 참조 횟수를 0으로 설정한다.
void init_page_table(int table_addr) {
  for (int page = 0; page < VAS_PAGES; page++) {
    pte *entry = get_pte(table_addr, page);
    entry->vflag = PAGE_INVALID;
    entry->ref = 0;
  }
}


//이진 파일로부터 프로세스 정보를 읽어들여 배열에 저장하고,
//각 프로세스에 대해 페이지 테이블을 할당하고 초기화한 후, 프로세스 대기열에 추가
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

// 프로세스가 종료되었는지 확인하는 함수.
// 참조 인덱스가 참조 길이를 초과했는지 확인한다.
int is_terminated(process *proc) { return proc->ref_index >= proc->ref_len; }

void runner() {
  // 큐를 활용하여 각 프로세스를 라운드 로빈으로 처리함
  while (!is_empty(&proc_queue)) {
    int pid = dequeue(&proc_queue);
    process *proc = &proc_arr[pid];

    if (is_terminated(proc)) {
      continue;
    }

    // 현재 프로세스의 참조할 페이지 확인
    int ref_index = proc->ref_index;
    int page = proc->references[ref_index];
    pte *entry = get_pte(proc->table_addr, page);

    // page fault가 발생한경우 프레임을 하나 할당받는다.
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

    // 참조 변수 갱신
    proc->ref_index++;

    entry->ref++;
    proc->num_ref++;

    // 라운드 로빈에 의해 큐의 맨끝으로 이동    
    enqueue(&proc_queue, pid);
  }

  return;
}

// 동적으로 할당된 메모리를 해제하는 함수.
// 페이지 테이블과 프로세스 참조 배열을 포함하여 모든 동적 메모리를 해제한다.
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
  pas = (frame *)malloc(PAS_SIZE); // PAS_SIZE=32*256
  
  init(&proc_queue);

  num_proc = load_process();
  if (oom_flag) {
    print_report();
    return 0;
  }

  runner();
  print_report();

  deallocate();

  return 0;
}