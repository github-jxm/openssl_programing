#include <stdio.h>
#include <openssl/safestack.h>


void popfreeCallBack(void *arg)
{
	printf("pop and free  %d \n",*(int*)arg);
}

/* ****************
 * 通用链表 
 ***************** */
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
    if (OPENSSL_sk_num(st) == 5) {
        printf("sk_num PASS\n");
    }

    //获取指定index数据
    int *getb = OPENSSL_sk_value(st, 1);
    if (*getb==b) {
        printf("sk_value PASS\n");
    }

    //获取指定数据，返回index
    if (OPENSSL_sk_find(st,"hello") == 2) {
        printf("sk_find PASS \n");
    }

    //在位置2插入一个 数据 TAOBAO,返回总数
    if (OPENSSL_sk_insert(st, "TAOBAO", 2) == 6) {
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

int main()
{
	test_stack(); // 通用链表
	return 0;
}
