#include <string.h>
#include <openssl/lhash.h>



typedef struct Student_st
{
	char name[20];
	int  age;
	char otherInfo[200];
}Student;


static int Student_cmp(const Student *a, const Student *b)
{
	const char *namea = a->name;
	const char *nameb = b->name;    
	return strcmp(namea,nameb);
}

/* 打印每个值*/
static void PrintValue(Student *a)
{
	printf("\nname :%s\n",a->name);
	printf("age   :%d\n",a->age);
	printf("otherInfo : %s\n",a->otherInfo);
}

static void PrintValue_arg(Student *a,int *b)
{
	int flag = *b;
	printf("\n用户输入参数为:%d\n",flag);
	printf("name :%s\n",a->name);
	printf("age   :%d\n",a->age);
	printf("otherInfo : %s\n",a->otherInfo);
}


DEFINE_LHASH_OF(Student);
IMPLEMENT_LHASH_DOALL_ARG(Student, int);

int  main()
{
	int  flag = 11;
	Student  s1 = {"zcp",28,"hu bei"},
		 s2 = {"forxy",28,"no info"},
		 s3 = {"skp",24,"student"},
		 s4 = {"zhao_zcp",28,"zcp's name"},
		 *s5;
	void *data;

 	LHASH_OF(Student) *h =  lh_Student_new(NULL,Student_cmp);
	if(h == NULL) {
		printf("err.\n");
		return -1;
	}

	data = &s1;
	lh_Student_insert(h,data);
	data = &s2;
	lh_Student_insert(h,data);
	data = &s3;
	lh_Student_insert(h,data);
	data = &s4;
	lh_Student_insert(h,data);

	/* 打印*/
	lh_Student_doall(h,PrintValue);

	printf("\n\n");
	lh_Student_doall_int(h,PrintValue_arg,&flag);

	data = lh_Student_retrieve(h,(const void*)"skp");
	if(data == NULL) {
		printf("can not look up skp!\n");
		lh_Student_free(h);
		return -1;
	}

	s5 = data;
	printf("\n\nstudent name :%s\n",s5->name);
	printf("sutdent    age  :   %d\n",s5->age);
	printf("student otherinfo :%s\n",s5->otherInfo);
	lh_Student_free(h);
	//getchar();
	return 0;
} 
