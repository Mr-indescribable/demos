#ifndef __BSTREE_H
#define __BSTREE_H


struct bs_node;
struct bs_tree;
typedef struct bs_node bs_node_t;
typedef struct bs_tree bs_tree_t;

struct bs_node {
	unsigned long id;
	void *data;
	bs_node_t *left;
	bs_node_t *right;
	bs_node_t *parent;
	char is_left_child;  // boolean，表示当前节点是否是父级节点的左子节点
};


struct bs_tree {
	bs_node_t *root;
	char root_used;  // boolean，表示 root 节点是否已经被存入数据
};


bs_tree_t *bst_new();

void bst_free(bs_tree_t *tree);

bs_node_t *bst_search(bs_tree_t *tree, unsigned long node_id);

int bst_delete(bs_tree_t *tree, unsigned long node_id);

int bst_insert(
	bs_tree_t *tree,
	unsigned long node_id,
	void *data,
	unsigned int data_len
);

void bst_update(
	bs_tree_t *tree,
	unsigned long node_id,
	void *data,
	unsigned int data_len
);


#endif
