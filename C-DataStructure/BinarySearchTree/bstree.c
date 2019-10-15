#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bstree.h"


static bs_node_t *_bst_new_node()
{
	bs_node_t *node;

	node = malloc( sizeof(bs_node_t) );

	node->id = 0;
	node->data   = NULL;
	node->left   = NULL;
	node->right  = NULL;
	node->parent = NULL;
	node->is_left_child = 0;
}


static void _bst_free_node(bs_node_t *node)
{
	free(node->data);
	free(node);
}


static void _bst_free_subtree(bs_node_t *node)
{
	bs_node_t *ln;  // left node
	bs_node_t *rn;  // right node

	if (node == NULL)
	{
		return;
	}

	free(node->data);

	ln = node->left;
	rn = node->right;

	/* 这里，我们深度优先，从左往右 free 掉整棵子树 */
	if (ln != NULL)
	{
		_bst_free_subtree(ln);
	}

	if (rn != NULL)
	{
		_bst_free_subtree(rn);
	}

	free(node);
}


bs_tree_t *bst_new()
{
	bs_tree_t *tree;
	bs_node_t *root;

	tree = malloc( sizeof(bs_tree_t) );
	root = _bst_new_node();

	tree->root = root;
	tree->root_used = 0;
}


void bst_free(bs_tree_t *tree)
{
	_bst_free_subtree(tree->root);
}


bs_node_t *bst_search(bs_tree_t *tree, unsigned long node_id)
{
	bs_node_t *cn;  // current node
	bs_node_t *nn;  // next node

	nn = tree->root;

	do
	{
		/* 这一轮的 cn 等于上一轮的 nn */
		cn = nn;

		/* 根据 binary search tree 的规范，小的向左，大的向右 */
		if (node_id < cn->id)
		{
			nn = cn->left;
		}
		else if (node_id > cn->id)
		{
			nn = cn->right;
		}
		else
		{
			return cn;
		}
	}
	while (nn != NULL);

	return NULL;
}


static int _bst_conditional_insert(
	bs_tree_t *tree,
	unsigned long node_id,
	void *data,
	unsigned int data_len,
	unsigned char override
){
	void *data_dup;  // 数据副本，我们内部存储的均为副本，不直接引用外部指针
	unsigned char insert_left;  // 一个 boolean，表示插入方向（左/右）
	bs_node_t *cn;  // current node
	bs_node_t *nn;  // next node
	bs_node_t *new_node;

	data_dup = malloc(data_len);
	memcpy(data_dup, data, data_len);

	if ( !tree->root_used )
	{
		tree->root->id = node_id;
		tree->root->data = data_dup;
		tree->root_used = 1;
		return 0;
	}

	nn = tree->root;

	do
	{
		/* 这一轮的 cn 等于上一轮的 nn */
		cn = nn;

		/* 根据 binary search tree 的规范，小的向左，大的向右 */
		if (node_id < cn->id)
		{
			nn = cn->left;
			insert_left = 1;
		}
		else if (node_id > cn->id)
		{
			nn = cn->right;
			insert_left = 0;
		}
		else
		{
			/* node_id 已存在于树中，根据 override 参数来决定是否覆盖原有数据 */
			if (override)
			{
				cn->data = data_dup;
				return 0;
			}
			else
			{
				free(data_dup);
				return 1;
			}
		}
	}
	while (nn != NULL);

	/* 当 next node 为 NULL 的时候，说明我们找到了插入点 */
	new_node = _bst_new_node();
	new_node->id = node_id;
	new_node->data = data_dup;
	new_node->parent = cn;

	if (insert_left)
	{
		new_node->is_left_child = 1;
		cn->left = new_node;
	}
	else
	{
		new_node->is_left_child = 0;
		cn->right = new_node;
	}

	return 0;
}


int bst_insert(
	bs_tree_t *tree,
	unsigned long node_id,
	void *data,
	unsigned int data_len
){
	return _bst_conditional_insert(tree, node_id, data, data_len, 0);
}


void bst_update(
	bs_tree_t *tree,
	unsigned long node_id,
	void *data,
	unsigned int data_len
){
	_bst_conditional_insert(tree, node_id, data, data_len, 1);
}


/*
 * binary search tree 的节点删除以及续接逻辑位于这里
 */
static void _bst_delete_node(bs_node_t *node)
{
	char is_root;
	bs_node_t *successor;

	is_root = node->parent == NULL;

	if (node->left == NULL && node->right == NULL)
	{
		successor = NULL;
	}
	else if (node->left != NULL && node->right != NULL)
	{
		/* 当要删除的节点同时拥有左右两个子节点时，我们需要将右子树的最左节点 */
		/* 当作要删除的节点的 successor，然后移动 successor 来覆盖之。 */
		/* successor 没有左子节点，如果有右子节点的话，则将右子节点接到 */
		/* successor 原来的位置上。 */

		successor = node->right;

		while (successor->left != NULL)
		{
			successor = successor->left;
		}

		if (successor == node->right)
		{
			/*
			 * 特殊情况：successor 是右子树的根节点
			 *           在这种特殊情况下，我们实际上不需要做什么特殊处理，
			 *           直接用右子树的根节点顶替要删除的节点即可，完美衔接
			 */
			node->left->parent = successor;
			successor->left = node->left;
			successor->parent = node->parent;
			successor->is_left_child = node->is_left_child;
		}
		else if (successor != node->right && successor->right != NULL)
		{
			/*
			 * 通常，successor 一定是 left child，这里就不用再判断了。
			 */
			successor->parent->left = successor->right;
			successor->right->parent = successor->parent;
			successor->right->is_left_child = 1;

			node->left->parent = successor;
			node->right->parent = successor;
			successor->left = node->left;
			successor->right = node->right;
			successor->parent = node->parent;
			successor->is_left_child = node->is_left_child;
		}
	}
	else if (node->left != NULL)
	{
		successor = node->left;
		node->left->parent = node->parent;
		node->left->is_left_child = node->is_left_child;
	}
	else if (node->right != NULL)
	{
		successor = node->right;
		node->right->parent = node->parent;
		node->right->is_left_child = node->is_left_child;
	}

	if (!is_root)
	{
		if (node->is_left_child)
		{
			node->parent->left = successor;
		}
		else
		{
			node->parent->right = successor;
		}
	}
	_bst_free_node(node);
}


int bst_delete(bs_tree_t *tree, unsigned long node_id)
{
	bs_node_t *node;

	node = bst_search(tree, node_id);

	if (node != NULL)
	{
		_bst_delete_node(node);
		return 1;
	}

	return 0;
}


int main(void)
{
	char *failure_msg = "Dayyyyyumn we failed\n";
	int r;
	bs_tree_t *tree;
	bs_node_t *node;

	/*
	 *                        2000
	 *                          |
	 *             +------------+------------+
	 *             |                         |
	 *            10                       10000
	 *             |                         |
	 *         +---+---+                 +---+---+
	 *         |       |                 |       |
	 *         1     1000              5000     NULL
	 *                 |                 |
	 *             +---+---+         +---+---+
	 *             |       |         |       |
	 *            777    1200      2456     6000
	 *             |
	 *          +--+--+
	 *          |     |
	 *         123   900
	 *          |
	 *      +---+---+
	 *      |       |
	 *     NULL    234
	 */
	unsigned long id0  = 2000;
	unsigned long id1  = 10000;
	unsigned long id2  = 10;
	unsigned long id3  = 1000;
	unsigned long id4  = 5000;
	unsigned long id5  = 777;
	unsigned long id6  = 1;
	unsigned long id7  = 2456;
	unsigned long id8  = 123;
	unsigned long id9  = 6000;
	unsigned long id10 = 1200;
	unsigned long id11 = 900;
	unsigned long id12 = 234;

	tree = bst_new();

	bst_insert(tree, id0, "aaaa\n", 6);

	r = bst_insert(tree, id0, "bbbb\n", 6);

	if (r != 0)
	{
		printf("The insert function omitted existing node id: %d\n", id0);
	}
	else
	{
		printf(failure_msg);
		return 1;
	}

	bst_insert(tree, id0,  "bbbb\n", 6);
	bst_insert(tree, id1,  "cccc\n", 6);
	bst_insert(tree, id2,  "dddd\n", 6);
	bst_insert(tree, id3,  "eeee\n", 6);
	bst_insert(tree, id4,  "ffff\n", 6);
	bst_insert(tree, id5,  "gggg\n", 6);
	bst_insert(tree, id6,  "hhhh\n", 6);
	bst_insert(tree, id7,  "iiii\n", 6);
	bst_insert(tree, id8,  "jjjj\n", 6);
	bst_insert(tree, id9,  "kkkk\n", 6);
	bst_insert(tree, id10, "llll\n", 6);
	bst_insert(tree, id11, "mmmm\n", 6);
	bst_insert(tree, id12, "nnnn\n", 6);

	bst_delete(tree, id2);
	bst_delete(tree, id4);

	if (
		bst_search(tree, id2) != NULL ||
		bst_search(tree, id4) != NULL
	){
		printf(failure_msg);
		return 1;
	}

	node = bst_search(tree, id8);
	if (node == NULL || node->left->id != id6 || node->parent->id != id0)
	{
		printf(failure_msg);
		return 1;
	}
	else
	{
		printf("deletion case 1st succeeded\n");
	}

	node = bst_search(tree, id12);
	if (node == NULL || node->parent->id != id5)
	{
		printf(failure_msg);
		return 1;
	}
	else
	{
		printf("deletion case 2nd succeeded\n");
	}

	bst_free(tree);
	printf("bs-tree freed\n");
	return 0;
}
