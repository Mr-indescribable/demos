#ifndef __DICT_H
#define __DICT_H


const unsigned int DICT_DEFAULT_SIZE = 128;


struct _dict_bkt_chain;
struct _dict_bkt;


struct _dict_bkt_chain {
	unsigned long hash;
	void *data;
	struct _dict_bkt_chain *prev;
	struct _dict_bkt_chain *next;
};


struct _dict_bkt {
	unsigned int size;  // bucket 中的链表长度
	struct _dict_bkt_chain *chain;
	struct _dict_bkt_chain *chain_tail;
};


struct dict {
	unsigned int size;
	struct _dict_bkt **bkts;
};
typedef struct dict dict_t;


dict_t *dict_new();

dict_t *dict_new_default();

void dict_free(dict_t *dict);

void dict_update(
	dict_t *dict,
	char *key,
	void *data,
	unsigned int data_size
);

void *dict_get(dict_t *dict, char *key);

int dict_remove(dict_t *dict, char *key);


#endif
