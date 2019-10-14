#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "dict.h"


static unsigned long hash_djb2(unsigned char *str)
{
	unsigned long hash = 5381;
	int c;

	while (c = *str++)
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

	return hash;
}


static void _dict_free_bkt_chain(struct _dict_bkt *bkt)
{
	struct _dict_bkt_chain *cu;  // chain unit
	struct _dict_bkt_chain *prev_cu;  // previous cu

	/* 当 bucket 的链长度大于 0 的时候，我们从链的尾部开始 free */
	if (bkt->size > 0)
	{
		cu = bkt->chain_tail;

		do
		{
			prev_cu = cu->prev;

			free(cu->data);
			free(cu);
		}
		while (prev_cu != NULL);
	}
}


static unsigned long _dict_hash(char *key)
{
	return hash_djb2(key);
}


static unsigned int _dict_index(dict_t *dict, unsigned long hash)
{
	return hash % dict->size;
}


dict_t *dict_new(unsigned int dict_size)
{
	dict_t *dict;

	dict = malloc( sizeof(dict_t) );
	dict->bkts = malloc( sizeof(struct _dict_bkt) * dict_size );
	dict->size = dict_size;

	for (int i = 0; i < dict_size; i++)
	{
		dict->bkts[i] = NULL;
	}

	return dict;
}


dict_t *dict_new_default()
{
	return dict_new(DICT_DEFAULT_SIZE);
}


void dict_free(dict_t *dict)
{
	struct _dict_bkt *bkt;

	for (int i = 0; i < dict->size; i++)
	{
		bkt = dict->bkts[i];

		if (bkt == NULL)
		{
			continue;
		}

		if (bkt->size > 0)
		{
			_dict_free_bkt_chain(bkt);
		}

		free(bkt);
	}

	free(dict);
}


void dict_update(
	dict_t *dict,
	char *key,
	void *data,
	unsigned int data_size
){
	unsigned long hash;
	unsigned int index;
	struct _dict_bkt *bkt;
	struct _dict_bkt_chain *cu;

	/* 一个数据副本，我们在插入数据时，不使用原有的数据，*/
	/* 而是将其复制一份，从而尽量让内部数据不依赖外部环境 */
	void *data_dup;

	data_dup = malloc(data_size);
	memcpy(data_dup, data, data_size);

	hash = _dict_hash(key);
	index = _dict_index(dict, hash);

	bkt = dict->bkts[index];

	if (bkt == NULL)
	{
		bkt = malloc( sizeof(struct _dict_bkt) );
		bkt->size = 0;
		bkt->chain = NULL;
		bkt->chain_tail = NULL;
		dict->bkts[index] = bkt;
	}
	else if (bkt->size > 0)
	{
		/* 当 bkt 中已经存在数据了，那么我们就需要先在其中查找 */
		/* 如果找到相同的 hash 值，则替换原有的 value，*/
		/* 如果没有的话，再插入一个新的 chain unit */
		cu = bkt->chain;

		do
		{
			if (cu->hash == hash)
			{
				/* 把原有的 free 掉，再换上新的，以达到替换的效果 */
				free(cu->data);
				cu->data = data_dup;
				return;
			}

			cu = cu->next;
		}
		while (cu != NULL);
	}

	/* 就像上面说的，如果没有找到重复记录的话，我们就插入一个新的 cu */
	cu = malloc( sizeof(struct _dict_bkt_chain) );
	cu->prev = NULL;
	cu->next = NULL;
	cu->hash = hash;
	cu->data = data_dup;

	if (bkt->size == 0)
	{
		bkt->chain = cu;
		bkt->chain_tail = cu;
	}
	else
	{
		cu->prev = bkt->chain_tail;
		bkt->chain_tail->next = cu;
		bkt->chain_tail = cu;
	}

	bkt->size += 1;
}


void *dict_get(dict_t *dict, char *key)
{
	unsigned long hash;
	unsigned int index;
	struct _dict_bkt *bkt;
	struct _dict_bkt_chain *cu;

	hash = _dict_hash(key);
	index = _dict_index(dict, hash);

	bkt = dict->bkts[index];

	if (bkt == NULL || bkt->size == 0)
	{
		return NULL;
	}

	cu = bkt->chain;
	do
	{
		if (cu->hash == hash)
		{
			return cu->data;
		}

		cu = cu->next;
	}
	while (cu != NULL);

	return NULL;
}


int dict_remove(dict_t *dict, char *key)
{
	unsigned long hash;
	unsigned int index;
	struct _dict_bkt *bkt;
	struct _dict_bkt_chain *cu;

	hash = _dict_hash(key);
	index = _dict_index(dict, hash);

	bkt = dict->bkts[index];

	if (bkt == NULL || bkt->size == 0)
	{
		return 0;
	}

	cu = bkt->chain;
	do
	{
		/*
		 * 当我们找到了目标节点之后，我们需要将其从链中移除，并且函数在此结束
		 */
		if (cu->hash == hash)
		{
			if (cu->prev != NULL && cu->next != NULL)
			{
				/* 当 cu 的前后都有节点的时候，我们给它焊接一下 */
				cu->prev->next = cu->next;
				cu->next->prev = cu->prev;
			}
			else if (cu->prev == NULL)
			{
				/* 当 cu 前面没有节点的时候，说明它是第一个节点 */
				/* 我们将其移除时，需要将它后面的那个节点变成 bucket 的头节点 */
				bkt->chain = cu->next;

				/* 并且，cu 后面的那个节点的前节点需要变成 NULL，如果有的话 */
				if (cu->next != NULL)
				{
					cu->next->prev = NULL;
				}
			}
			else if (cu->next == NULL)
			{
				/* 当 cu 后面没有节点的时候，说明它是最后一个节点 */
				/* 我们将其移除时，需要将它前面的一个节点变成 bucket 的尾节点 */
				bkt->chain_tail = cu->prev;

				/* 并且，cu 前面那个节点的后节点需要变成 NULL，如果有的话 */
				if (cu->prev != NULL)
				{
					cu->prev->next == NULL;
				}
			}

			/* 然后销毁被拿出来的节点 */
			bkt->size -= 1;
			free(cu->data);
			free(cu);

			return 1;
		}

		cu = cu->next;
	}
	while (cu != NULL);

	return 0;
}


int main(void)
{
	int vi0 = 100;
	int vi1 = 200;
	int vi2 = 300;
	int vi3 = 400;

	int *v;
	dict_t *dict;

	dict = dict_new_default();
	dict_update(dict, "k0",  &vi0, sizeof(int));

	v = dict_get(dict, "k0");
	printf("k0: %d\n", *v);

	dict_update(dict, "k0",  &vi1, sizeof(int));
	dict_update(dict, "k1", &vi2, sizeof(int));
	dict_update(dict, "k2", &vi3, sizeof(int));

	v = dict_get(dict, "k0");
	printf("k0 overrided: %d\n", *v);

	v = dict_get(dict, "k1");
	printf("k1: %d\n", *v);

	v = dict_get(dict, "k2");
	printf("k2: %d\n", *v);

	dict_remove(dict, "k2");
	v = dict_get(dict, "k2");
	if (v == NULL)
	{
		printf("k2 removed\n");
	}

	dict_free(dict);
	return 0;
}
