#define _GNU_SOURCE
#include <sched.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include<sys/sendfile.h>
#include<sys/signal.h>
//* 파일 구조체 해당 파일을 열어둔다
typedef  struct File_set
{
    size_t File_Size;           //*파일 크기
    int File;
    char File_Name[1024];       //*파일 이름
    char File_Header[1024];
    int File_Header_Size;
}File_set;
File_set file_set[499];

char Root[256];

//! 쓰레드용 데이터 셋
typedef struct THREAD_SET
{
    int Clint_Sock;
    struct sockaddr_in cll;

}THREAD_SET;
//? 해쉬 함수
int hash_num(char *buf)
{
  int length = strlen(buf);
  int hash_code=0;
  for(int i = 2; i<length-4 ; i++)
  {
          hash_code = ((hash_code*i%499)^(buf[i]*buf[i]%499))%499;
  }
  return hash_code;
}

//? 해당 폴더에서 파일을 찾아 해쉬 함수화 시킨다. //각 쓰레드당 적용 후 셋팅
void File_Setting(char *file_name, char *name) {
  DIR *dp;             //* 폴더 변수
  int fd;              //* 파일 열기 변수
  struct dirent *dent; //*파일 항목
  struct stat sbuf;
  char buf[BUFSIZ];
  char path[BUFSIZ]; //* 파일 경로
  char sub_path[BUFSIZ];
  int hash;
  if ((dp = opendir(file_name)) == NULL) {
    //? 디렉토리 열기를 실패
    perror("Directory Not Open :");
    exit(1);
  }

  while ((dent = readdir(dp))) {
    //? 파일의 이름의 . 는 상위 폴더 혹은 자기 자신을 가르키며 숨긴파일을
    //말한다.
    if (dent->d_name[0] == '.')
      continue;
    sprintf(path, "%s/%s", file_name, dent->d_name);
    stat(path, &sbuf);

    if (S_ISDIR(sbuf.st_mode)) {

      sprintf(sub_path, "%s%s/", name, dent->d_name);

      File_Setting(path, sub_path);
    } else {
      sprintf(buf, "%s%s", name, dent->d_name);
      hash = hash_num(buf);
      strcpy(file_set[hash].File_Name, buf);
      file_set[hash].File_Header_Size=sprintf(file_set[hash].File_Header,"HTTP/1.1 200 OK\nContent-Length:""%d\nConnection: close\nContent-Type: */*;""charset=UTF8\n\n",sbuf.st_size);
      file_set[hash].File=open(path, O_RDONLY);
      file_set[hash].File_Size = sbuf.st_size;
    }
  }
}

//쓰레드 폴
#define THREAD_POOL_SIZE 12

typedef struct THREAD{
  pthread_mutex_t mmutex;
  pthread_cond_t mcond;
  THREAD_SET * value;
  int id;
  int LockFlag;
}THREAD;

void SetValue(THREAD *b,THREAD_SET *a)
{
	b->value = a;
}

// 뮤텍스와 조건변수 초기화 
THREAD *Thread(void)
{
  THREAD * thread = (THREAD *)malloc(sizeof(THREAD));
	thread->LockFlag = 1;
	
	pthread_mutex_init(&thread->mmutex, NULL);
	pthread_cond_init(&thread->mcond, NULL);
    return thread;
}

// 모텍스 잠금 얻기 시도
int THREAD_TryLock(THREAD *d)
{
	int rtv;
	if(d->LockFlag != 1)
	{
		return -1;
	}
   	d->LockFlag = 0;
	rtv = pthread_mutex_lock(&d->mmutex);
	return 0;
}
// 뮤텍스 잠금 되돌려준다.
int THREAD_UnLock(THREAD *d)
{
	pthread_mutex_unlock(&d->mmutex);
}
// 조건변수에 시그널을 전송한다.
// 시그널을 전송한 후에는 뮤텍스 잠금을 되돌려준다.
int THREAD_Signal(THREAD *d)
{
	pthread_cond_signal(&d->mcond);
	THREAD_UnLock(d);
}

// 자식 쓰레드에서 실행할 작업 메서드
int THREAD_Job(THREAD *d)
{
  int readn;
  char buf[255];
  char buff[255];
  int cpu=(d->id)%11+1;
  cpu_set_t mask;
 
  CPU_ZERO(&mask);
  CPU_SET(cpu, &mask);
  sched_setaffinity(0, sizeof(mask), &mask);
  
	while(1)
	{
    
		pthread_mutex_lock(&d->mmutex);
    
    d->LockFlag = 1;		
		pthread_cond_wait(&d->mcond, &d->mmutex);
		d->LockFlag = 0;
		//작업처리
    
    if ((readn = read(d->value->Clint_Sock, buf, 255)) <= 0) {
      close(d->value->Clint_Sock);
      pthread_mutex_unlock(&d->mmutex);
      } 
    else
    {
      
      *(strstr(buf, "HTTP") - 1) = '\0';
      strcpy(buff, &buf[4]);
      if (!strcmp(buff, "/")) {
          sprintf(buff, "/index.html");
      }
    int hash = hash_num(buff);
    
    if (file_set[hash].File_Size == 0) {
      
      char Header[1002]="HTTP1/1 200 OK\nContent-Length:""9\nConnection: close\nContent-Type: */*;""charset=UTF8\n\nNot Found";
      write(d->value->Clint_Sock, Header,strlen(Header));
      close(d->value->Clint_Sock);
      free(d->value);
    } 
    else {
        int sockopt =file_set[hash].File_Header_Size;
        setsockopt(d->value->Clint_Sock,SOL_SOCKET,SO_SNDBUF,&sockopt,sizeof(sockopt));
        write(d->value->Clint_Sock, file_set[hash].File_Header,file_set[hash].File_Header_Size);
        sockopt = file_set[hash].File_Size;
        setsockopt(d->value->Clint_Sock,SOL_SOCKET,SO_SNDBUF,&sockopt,sizeof(sockopt));
        sendfile(d->value->Clint_Sock, file_set[hash].File, NULL,file_set[hash].File_Size);
        lseek(file_set[hash].File, 0, SEEK_SET);
        close(d->value->Clint_Sock);
        free(d->value);
      }
      pthread_mutex_unlock(&d->mmutex);
    }
   
  }
}

// 쓰레드 함수
void *thread_func(void *arg)
{
	THREAD *lThread = (THREAD *)arg;
	THREAD_Job(lThread);
}

int main(int argc, char **argv)
{
	int i = 0;
	int mstat;
	pthread_t p_thread;
	THREAD * ListThread[12];
  int serv_sock;
  struct sockaddr_in serv_addr,clnt_addr;
  int clnt_addr_size=sizeof(clnt_addr);
	pthread_mutex_t mutex_lock;
	pthread_mutexattr_t attr;
  int PORTNUM;
	int kind;
  int cpu=0;
  cpu_set_t mask;
 
  CPU_ZERO(&mask);
  CPU_SET(cpu, &mask);
  sched_setaffinity(1, sizeof(mask), &mask);
  
  if(argc!=3)
    {
        printf("%s <Directory> <port>",argv[0]);
        exit(1);
    }
    
    PORTNUM = atoi(argv[2]);
    //int Fd  = open("log.txt",O_CREAT|O_TRUNC,0644);
    
    
    if((serv_sock=socket(PF_INET, SOCK_STREAM , 0))==-1)
    {
        perror("socket create : ");
        exit(1);
    }
    strcpy(Root,argv[1]);
    //사용 소켓 재사용.
    int optvalue = 1;
    setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &optvalue,sizeof(optvalue));
    // tcp살리기.
    setsockopt(serv_sock, SOL_SOCKET, SO_KEEPALIVE, &optvalue,         sizeof(optvalue));
    //요청있을때마다 보내기.. ->트래픽양은 증가하지만 속도는 증가.
    //setsockopt(serv_sock, IPPROTO_TCP, TCP_NODELAY, &optvalue,           sizeof(optvalue));
    setsockopt(serv_sock, IPPROTO_TCP, TCP_CORK, &optvalue, sizeof(optvalue));
    int sockopt = 255;
    //setsockopt(serv_sock,SOL_SOCKET,SO_SNDBUF,&sockopt,sizeof(sockopt));
    setsockopt(serv_sock,SOL_SOCKET,SO_RCVBUF,&sockopt,sizeof(sockopt));
    memset(&serv_addr, 0, sizeof(serv_addr)); //초기화.
    //서버 정보 입력.
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(PORTNUM);
    
    File_Setting(Root,"/");
    //bind() 에러
  if(bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))==-1){
    printf("bind() error\n");
    return 1;
  }
  //listen() 에러
  if(listen(serv_sock,9)==-1){
    printf("listen() error\n");
    return 1;
  }
  
	// 쓰레드 풀을 만든다.
	for(i = 0; i < THREAD_POOL_SIZE; i++)
	{
    THREAD * lpthread = Thread();
		lpthread->id=i+1;
		ListThread[i]=lpthread;
		pthread_create(&p_thread, NULL, thread_func, (void *)lpthread);
	}

  
	while(1)
	{
		// 작업 가능한 쓰레드를 찾아서
		// 조건변수 시그널을 전송한다.
    THREAD_SET *DATA=(THREAD_SET *)malloc(sizeof(THREAD_SET));
    DATA->Clint_Sock=accept(serv_sock,(struct sockaddr *)&clnt_addr, &clnt_addr_size);
    
		for (i = 0; i < THREAD_POOL_SIZE; i++)
		{
			if((mstat = THREAD_TryLock(ListThread[i])) == 0)
			{
				DATA->cll=clnt_addr;
				SetValue(ListThread[i],DATA);
				THREAD_Signal(ListThread[i]);
				break;
			}
      if(i==THREAD_POOL_SIZE-1)
      {
                i=0;
      }
		}
    
	}
  return 0;
}