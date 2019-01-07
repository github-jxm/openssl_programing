#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/safestack.h>

//#define sk_Student_new(st) OPENSSL_sk_new(st)
//#define sk_Student_new_null() OPENSSL_sk_new_null()
//#define sk_Student_free(st) OPENSSL_sk_free(st)
//#define sk_Student_num(st) OPENSSL_sk_num(st)
//#define sk_Student_value(st, i) OPENSSL_sk_value((st), i)
//#define sk_Student_set(st, i, val) OPENSSL_sk_set((st), (i), (val))
//#define sk_Student_zero(st) OPENSSL_sk_zero(Student, (st))
//#define sk_Student_push(st, val) OPENSSL_sk_push((st),(val))
//#define sk_Student_unshift(st, val) OPENSSL_sk_unshift((st), (val))
//#define sk_Student_find(st, val) OPENSSL_sk_find((st), (val))
//#define sk_Student_delete(st, i) OPENSSL_sk_delete((st), (i))
//#define sk_Student_delete_ptr(st, ptr) OPENSSL_sk_delete_ptr((st), (ptr))
//#define sk_Student_insert(st, val, i) OPENSSL_sk_insert((st), (val), (i))
//#define sk_Student_set_cmp_func(st, cmp) OPENSSL_sk_set_cmp_func((st), (cmp))
//#define sk_Student_dup(st) OPENSSL_sk_dup(Student, st)
//#define sk_Student_pop_free(st, free_func) OPENSSL_sk_pop_free((st), (free_func))
//#define sk_Student_shift(st) OPENSSL_sk_shift(st)
//#define sk_Student_pop(st) OPENSSL_sk_pop(st)
//#define sk_Student_sort(st) OPENSSL_sk_sort(st)


typedef struct Student_st
{
	char  *name;
	int   age;
	char  *otherInfo;
}Student;

typedef STACK_OF(Student) Students;

DEFINE_STACK_OF(Student)

Student *Student_Malloc()
{
	Student *a=malloc(sizeof(Student));
	a->name=malloc(20);
	strcpy(a->name,"zcp");
	a->otherInfo=malloc(20);
	strcpy(a->otherInfo,"no info");
	return a;
}

void Student_Free(Student *a)
{
	free(a->name);
	free(a->otherInfo);
	free(a);
}

static int Student_cmp(const Student * const *a, const Student  *const *b)
{
	int  ret;
	printf("%s cpmp %s \n",(*a)->name,(*b)->name);
	ret=strcmp((*a)->name,(*b)->name);
	return ret;
}


void popfreeCallBack(void *arg)
{
	printf("pop and free  %d \n",*(int*)arg);
}

//*
 // 通用链表
 
int  test_stack()
{

    //创建一个空的栈
    OPENSSL_STACK *st = OPENSSL_sk_new_null();

    int a = 10;
    OPENSSL_sk_push(st, &a);

    int b = 100;
    OPENSSL_sk_push(st, &b);

    char *c = "hello";
    OPENSSL_sk_push(st, c);

    char d[10] = {0};
    OPENSSL_sk_push(st, d);

    char e = 'A';
    OPENSSL_sk_push(st, &e);


    //返回栈内数据个数
    if (OPENSSL_sk_num(st)==5) {
        printf("sk_num PASS\n");
    }

    //获取指定index数据
    int *getb = OPENSSL_sk_value(st, 1);
    if (*getb==b) {
        printf("sk_value PASS\n");
    }

    //获取指定数据，返回index
    if (OPENSSL_sk_find(st,"hello")==2) {
        printf("sk_find PASS \n");
    }

    //在位置2插入一个 数据 TAOBAO,返回总数
    if (OPENSSL_sk_insert(st, "TAOBAO", 2)==6) {
        printf("sk_insert PASS\n");
    }

    int ff = 88;
    OPENSSL_sk_push(st, &ff);
    //在栈顶移出一个数据, 返回删除的元素
    char *popDT = OPENSSL_sk_pop(st);
    if (*popDT==ff) {
        printf("sk_pop PASS\n");
    }

    //从栈中移出所有的元素，并释放内存，并且释放st;
    //每删除一个元素，回调一次popfreeCallBack回调函数
    OPENSSL_sk_pop_free(st, popfreeCallBack);
    return 0;
}
//*/

int main()
{

	Students *s, *snew;
	Student  *s1, *one, *s2;
	int      i, num;

	printf("\n===================\n");
	test_stack(); // 通用链表
	printf("\n===================\n");


	s = sk_Student_new_null();
	//snew = sk_Student_new((sk_Student_compfunc)Student_cmp);
	snew = sk_Student_new(Student_cmp);
	
	s2=Student_Malloc();
	sk_Student_push(snew,s2);
	i=sk_Student_find(snew,s2);
	printf("at : %d \n" ,i  );
	
	s1=Student_Malloc();
	sk_Student_push(s,s1);

	num=sk_Student_num(s);
	for(i=0;i<num;i++) {
		one=sk_Student_value(s,i);
		printf("student name :    %s\n",one->name);
		printf("sutdent age  :     %d\n",one->age);
		printf("student otherinfo :      %s\n\n\n",one->otherInfo);
	}
	sk_Student_pop_free(s,Student_Free);
	sk_Student_pop_free(snew,Student_Free);
	return 0;
}
