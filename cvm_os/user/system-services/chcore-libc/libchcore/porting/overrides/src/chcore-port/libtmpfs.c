#define _GNU_SOURCE
#include "libtmpfs.h"
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <pthread.h>
#include <limits.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <chcore/bug.h>
#include <sys/uio.h>
#include <time.h>
#include <chcore/container/list.h>
#include <chcore/container/rbtree.h>
#include <chcore/container/hashtable.h>
#include <chcore/container/radix.h>

#define AT_FDROOT           (-101)
#define FS_REQ_PATH_BUF_LEN (256)
#define FS_REQ_PATH_LEN     (255)
#define FS_BUF_SIZE         (IPC_SHM_AVAILABLE - sizeof(struct fs_request))

#define MAX_FILE_PAGES       512
#define MAX_SERVER_ENTRY_NUM 1024

enum fs_vnode_type { FS_NODE_RESERVED = 0, FS_NODE_REG, FS_NODE_DIR };

/*
 * per-inode
 */
#define PC_HASH_SIZE 512
struct fs_vnode {
        ino_t vnode_id; /* identifier */
        struct rb_node node; /* rbtree node */

        enum fs_vnode_type type; /* regular or directory */
        int refcnt; /* reference count */
        off_t size; /* file size or directory entry number */
        void *private;

        pthread_rwlock_t rwlock; /* vnode rwlock */
};

/*
 * per-fd
 */
struct server_entry {
        /* `flags` and `offset` is assigned to each fd */
        int flags;
        off_t offset;
        int refcnt;
        /*
         * Different FS may use different struct to store path,
         * normally `char*`
         */
        void *path;

        /* Entry lock */
        pthread_mutex_t lock;

        /* Each vnode is binding with a disk inode */
        struct fs_vnode *vnode;
};

struct string {
        char *str;
        size_t len;
        u32 hash;
};

struct inode {
        bool opened;
        int type;
        int nlinks;
        off_t size;
        mode_t mode; /* not supported now */

        /* type-specific file content */
        union {
                char *symlink;
                struct radix data;
                struct htable dentries;
        };

        /* shared behaviour of all inodes */
        struct base_inode_ops *base_ops;

        /* type-specific operations */
        union {
                struct regfile_ops *f_ops;
                struct dir_ops *d_ops;
                struct symlink_ops *sym_ops;
        };

        /* other fields used by mmap */
        struct {
                bool valid;
                vaddr_t *array;
                size_t nr_used; /* Number of entries filled. */
                size_t size; /* Total capacity. */
                cap_t translated_pmo_cap; /* PMO cap of translated array. */
        } aarray;
};

struct dentry {
        struct string name;
        struct inode *inode;
        struct hlist_node node;
};

/* Internal operations of different types of inodes */

struct base_inode_ops {
        void (*open)(struct inode *inode);
        void (*close)(struct inode *inode);
        void (*dec_nlinks)(struct inode *inode);
        void (*inc_nlinks)(struct inode *inode);
        void (*free)(struct inode *inode);
        void (*stat)(struct inode *inode, struct stat *stat);
};

struct regfile_ops {
        ssize_t (*read)(struct inode *reg, char *buff, size_t len,
                        off_t offset);
        ssize_t (*write)(struct inode *reg, const char *buff, size_t len,
                         off_t offset);
        int (*truncate)(struct inode *reg, off_t len);
        int (*punch_hole)(struct inode *reg, off_t offset, off_t len);
        int (*collapse_range)(struct inode *reg, off_t offset, off_t len);
        int (*zero_range)(struct inode *reg, off_t offset, off_t len,
                          mode_t mode);
        int (*insert_range)(struct inode *reg, off_t offset, off_t len);
        int (*allocate)(struct inode *reg, off_t offset, off_t len,
                        int keep_size);
};

struct dir_ops {
        struct dentry *(*alloc_dentry)();
        void (*free_dentry)(struct dentry *dentry);
        int (*add_dentry)(struct inode *dir, struct dentry *dentry, char *name,
                          size_t len);
        void (*remove_dentry)(struct inode *dir, struct dentry *dentry);
        bool (*is_empty)(struct inode *dir);
        void (*link)(struct inode *dir, struct dentry *dentry,
                     struct inode *inode);
        void (*unlink)(struct inode *dir, struct dentry *dentry);
        int (*mkdir)(struct inode *dir, struct dentry *dentry, mode_t mode);
        int (*rmdir)(struct inode *dir, struct dentry *dentry);
        void (*rename)(struct inode *old_dir, struct dentry *old_dentry,
                       struct inode *new_dir, struct dentry *new_dentry);
        int (*mknod)(struct inode *dir, struct dentry *dentry, mode_t mode,
                     int type);
        struct dentry *(*dirlookup)(struct inode *dir, const char *name,
                                    size_t len);
        int (*scan)(struct inode *dir, unsigned int start, void *buf, void *end,
                    int *read_bytes);
};

struct symlink_ops {
        ssize_t (*read_link)(struct inode *symlink, char *buff, size_t len);
        ssize_t (*write_link)(struct inode *symlink, const char *buff,
                              size_t len);
};

#define MAX_STACK_SIZE 3 /* Maximum number of nested symlinks */
#define MAX_SYM_CNT    10 /* Maximum number of symlinks in a lookup */

#define FS_REG (8)
#define FS_DIR (4)
#define FS_SYM (10)

#define MAX_STACK_SIZE 3 /* Maximum number of nested symlinks */
#define MAX_SYM_CNT    10 /* Maximum number of symlinks in a lookup */

/* nd->flags flags */
#define ND_FOLLOW         0x0001 /* follow links at the end */
#define ND_DIRECTORY      0x0002 /* require a directory */
#define ND_EMPTY          0x0004 /* accept empty path */
#define ND_NO_SYMLINKS    0x0008 /* no symlinks during the walk */
#define ND_TRAILING_SLASH 0x0010 /* the path ends with one or more slashes */

#define DENT_SIZE (1) /* A faked directory entry size */

#define MAX_PATH    (4096)
#define MAX_SYM_LEN MAX_PATH

#define MAX_NR_FID_RECORDS (1024)
#define MAX_DIR_HASH_BUCKETS (1024)

struct nameidata {
        struct dentry *current;
        struct string last;
        unsigned int flags;
        int last_type; /* LAST_NORM, LAST_DOT, LAST_DOTDOT */
        unsigned depth;
        int total_link_count;
        const char *stack[MAX_STACK_SIZE]; /* saved pathname when handling
                                              symlinks */
};

static struct server_entry *server_entrys[MAX_SERVER_ENTRY_NUM];

static struct rb_root *fs_vnode_list;

static pthread_rwlock_t fs_wrapper_meta_rwlock;

static struct inode *tmpfs_root = NULL;
static struct dentry *tmpfs_root_dent = NULL;

static struct base_inode_ops base_inode_ops;
static struct regfile_ops regfile_ops;
static struct dir_ops dir_ops;
static struct symlink_ops symlink_ops;

/* string utils */
static u64 hash_chars(const char *str, size_t len)
{
        u64 seed = 131; /* 31 131 1313 13131 131313 etc.. */
        u64 hash = 0;
        int i;

        if (len < 0) {
                while (*str) {
                        hash = (hash * seed) + *str;
                        str++;
                }
        } else {
                for (i = 0; i < len; ++i)
                        hash = (hash * seed) + str[i];
        }

        return hash;
}

static void hash_string(struct string *s)
{
        s->hash = hash_chars(s->str, s->len);
}

static void free_string(struct string *s)
{
        if (s->str) {
                free(s->str);
        }
        s->str = NULL;
}

static int init_string(struct string *s, const char *name, size_t len)
{
        free_string(s);

        /*
         * s->str is allocated and copied,
         * remember to free it afterwards
         */
        s->str = malloc(len + 1);
        if (!s->str) {
                return -ENOMEM;
        }

        memcpy(s->str, name, len);
        s->str[len] = '\0';

        s->len = len;

        hash_string(s);
        return 0;
}

static int comp_vnode_key(const void *key, const struct rb_node *node)
{
        struct fs_vnode *vnode = rb_entry(node, struct fs_vnode, node);
        ino_t vnode_id = *(ino_t *)key;

        if (vnode_id < vnode->vnode_id)
                return -1;
        else if (vnode_id > vnode->vnode_id)
                return 1;
        else
                return 0;
}

static bool less_vnode(const struct rb_node *lhs, const struct rb_node *rhs)
{
        struct fs_vnode *l = rb_entry(lhs, struct fs_vnode, node);
        struct fs_vnode *r = rb_entry(rhs, struct fs_vnode, node);

        return l->vnode_id < r->vnode_id;
}

static void free_entry(int entry_idx)
{
        free(server_entrys[entry_idx]->path);
        free(server_entrys[entry_idx]);
        server_entrys[entry_idx] = NULL;
}

static int alloc_entry(void)
{
        int i;

        for (i = 0; i < MAX_SERVER_ENTRY_NUM; i++) {
                if (server_entrys[i] == NULL) {
                        server_entrys[i] = (struct server_entry *)malloc(
                                sizeof(struct server_entry));
                        if (server_entrys[i] == NULL)
                                return -1;
                        pthread_mutex_init(&server_entrys[i]->lock, NULL);
                        return i;
                }
        }
        return -1;
}

static void assign_entry(struct server_entry *e, u64 f, off_t o, int t, void *p,
                  struct fs_vnode *n)
{
        e->flags = f;
        e->offset = o;
        e->path = p;
        e->vnode = n;
        e->refcnt = t;
}

static void fs_vnode_init(void)
{
        fs_vnode_list = malloc(sizeof(*fs_vnode_list));
        if (fs_vnode_list == NULL) {
                printf("[fs_base] no enough memory to initialize, exiting...\n");
                exit(-1);
        }
        init_rb_root(fs_vnode_list);
}

static struct fs_vnode *alloc_fs_vnode(ino_t id, enum fs_vnode_type type, off_t size,
                                       void *private)
{
        struct fs_vnode *ret = (struct fs_vnode *)malloc(sizeof(*ret));
        if (ret == NULL) {
                return NULL;
        }

        /* Filling Initial State */
        ret->vnode_id = id;
        ret->type = type;
        ret->size = size;
        ret->private = private;

        /* Ref Count start as 1 */
        ret->refcnt = 1;

        pthread_rwlock_init(&ret->rwlock, NULL);

        return ret;
}

static void push_fs_vnode(struct fs_vnode *n)
{
        rb_insert(fs_vnode_list, &n->node, less_vnode);
}

static void pop_free_fs_vnode(struct fs_vnode *n)
{
        rb_erase(fs_vnode_list, &n->node);
        free(n);
}

static struct fs_vnode *get_fs_vnode_by_id(ino_t vnode_id)
{
        struct rb_node *node =
                rb_search(fs_vnode_list, &vnode_id, comp_vnode_key);
        if (node == NULL)
                return NULL;
        return rb_entry(node, struct fs_vnode, node);
}

/* refcnt for vnode */
static int inc_ref_fs_vnode(void *n)
{
        ((struct fs_vnode *)n)->refcnt++;
        return 0;
}

static int tmpfs_close(void *operator, bool is_dir /* not handled */, bool do_close);

static int dec_ref_fs_vnode(void *node)
{
        int ret;
        struct fs_vnode *n = (struct fs_vnode *)node;

        n->refcnt--;
        assert(n->refcnt >= 0);

        if (n->refcnt == 0) {
                ret = tmpfs_close(
                        n->private, (n->type == FS_NODE_DIR), true);
                if (ret) {
                        printf("Warning: close failed when deref vnode: %d\n",
                               ret);
                        return ret;
                }

                pop_free_fs_vnode(n);
        }

        return 0;
}

/* Return true if fd is NOT valid */
static inline bool fd_type_invalid(int fd, bool isfile)
{
        if (fd < 0 || fd >= MAX_SERVER_ENTRY_NUM)
                return true;
        if (server_entrys[fd] == NULL)
                return true;
        if (isfile && (server_entrys[fd]->vnode->type != FS_NODE_REG))
                return true;
        if (!isfile && (server_entrys[fd]->vnode->type != FS_NODE_DIR))
                return true;
        return false;
}

static int get_path_leaf(const char *path, char *path_leaf)
{
        int i;
        int ret;

        ret = -1; /* return -1 means find no '/' */

        for (i = strlen(path) - 2; i >= 0; i--) {
                if (path[i] == '/') {
                        strcpy(path_leaf, path + i + 1);
                        ret = 0;
                        break;
                }
        }

        if (ret == -1)
                return ret;

        if (path_leaf[strlen(path_leaf) - 1] == '/') {
                path_leaf[strlen(path_leaf) - 1] = '\0';
        }

        return ret;
}

static int get_path_prefix(const char *path, char *path_prefix)
{
        int i;
        int ret;

        ret = -1; /* return -1 means find no '/' */

        BUG_ON(strlen(path) > FS_REQ_PATH_BUF_LEN);

        strcpy(path_prefix, path);
        for (i = strlen(path_prefix) - 2; i >= 0; i--) {
                if (path_prefix[i] == '/') {
                        path_prefix[i] = '\0';
                        ret = 0;
                        break;
                }
        }

        return ret;
}

static int check_path_leaf_is_not_dot(const char *path)
{
        char leaf[FS_REQ_PATH_BUF_LEN];

        if (get_path_leaf(path, leaf) == -1)
                return -EINVAL;
        if (strcmp(leaf, ".") == 0 || strcmp(leaf, "..") == 0)
                return -EINVAL;

        return 0;
}

/**
 * @brief length until next '/' or '\0'
 * @param name pointer to a null terminated string
 * @return u64 The length of the first component pointed to by name
 */
static inline u64 get_component_len(const char *name)
{
        int i = 0;
        while (name[i] != '\0' && name[i] != '/') {
                i++;
        }
        return i;
}

static void init_nd(struct nameidata *nd, unsigned flags)
{
        nd->depth = 0;
        nd->flags = flags;
        /*
         * The current implementation of fs_base ensures tmpfs only get absolute
         * path when dealing with file system requests
         */
        nd->current = tmpfs_root_dent;
        nd->total_link_count = 0;
        nd->last.str = NULL;
}

/**
 * @brief Decide whether we can follow the symlink.
 * @param nd The nameidata structure to check.
 * @return int 0 if no error, or errno.
 */
static int can_follow_symlink(struct nameidata *nd)
{
        /* No stack space for the new symlink */
        if (nd->depth == MAX_STACK_SIZE) {
                return -ENOMEM;
        }

        /* Too many symlink encountered */
        if (nd->total_link_count++ == MAX_SYM_CNT) {
                return -ELOOP;
        }

        return 0;
}

/**
 * @brief update nd->current according to the found dentry
 * @param nd The nd structure of this path lookup.
 * @param trailing Indicate whether this is a trailing component, if it is, it
 * requires some special care.
 * @param dentry The dentry for nd->current to update to.
 * @return const char* Return NULL if not a symlink or should not follow, return
 * the symlink otherwise.
 */
static const char *step_into(struct nameidata *nd, bool trailing,
                             struct dentry *dentry)
{
        int err;

        /*
         * The dentry is not a symlink or should not be followed
         */
        if (dentry->inode->type != FS_SYM
            /* only the trailing symlink needs to check if it can be followed.
               always follow non-trailing symlinks */
            || (trailing && !(nd->flags & ND_FOLLOW))) {
                nd->current = dentry;
                return NULL;
        }

        /* dealing with a symlink now */

        err = can_follow_symlink(nd);
        if (err) {
                return CHCORE_ERR_PTR(err);
        }

        /* symlink is not allowed */
        if (nd->flags & ND_NO_SYMLINKS) {
                return CHCORE_ERR_PTR(-ELOOP);
        }

        /*
         * we directly return the actual symlink,
         * without copying it
         */
        const char *name = dentry->inode->symlink;

        if (!name) {
                return NULL;
        }

        if (*name == '/') {
                /* Absolute path symlink, jump to root */
                nd->current = tmpfs_root_dent;

                do {
                        name++;
                } while (*name == '/');
        }

        /* we do not update nd->current if the symlink is a relative path. */

        return *name ? name : NULL;
}

/**
 * @brief Lookup a single component named "nd->last" under the dentry
 * "nd->current". Find the dentry in walk_component() then call step_into() to
 * process symlinks and some flags.
 * @param nd The nd structure representing this path lookup.
 * @param trailing If this is the trailing component, some special care would be
 * taken when considering symlinks.
 * @return const char* Return NULL if no symlink encountered or should/can not
 * follow, return the symlink to follow it.
 * @note The result of this function during a pathname lookup will be an updated
 * nd->current, serving as the parent directory of next component lookup.
 */
static const char *walk_component(struct nameidata *nd, bool trailing)
{
        struct dentry *dentry;
        struct inode *i_parent;

        i_parent = nd->current->inode;
        if (i_parent->type != FS_DIR) {
                return CHCORE_ERR_PTR(-ENOTDIR);
        }

        /* Find the dentry of the nd->last component under nd->current */
        dentry = i_parent->d_ops->dirlookup(
                i_parent, nd->last.str, (int)nd->last.len);

        if (dentry == NULL) {
                return CHCORE_ERR_PTR(-ENOENT); /* File not exist */
        }

        return step_into(nd, trailing, dentry);
};

/**
 * @brief A simple wrapper of walk_component, used when looking up the last
 * component in the path.
 * @param nd The nd structure representing this path lookup.
 * @return const char* Return NULL if no symlink encountered or should/can not
 * follow, return the symlink to follow it.
 */
static inline const char *lookup_last(struct nameidata *nd)
{
        if (nd->last.str == NULL) {
                return NULL;
        }

        return walk_component(nd, true);
}

/**
 * @brief lookup the dentry that is to be opened, if it exists, return it.
 * If it does not exist and O_CREAT is set, creat a regular file of the name
 * @param nd The nd structure representing this path lookup.
 * @param open_flags The open flags of this open() syscall.
 * @return struct dentry* Return the found/created dentry, or NULL if not found.
 */
static struct dentry *lookup_create(struct nameidata *nd, unsigned open_flags)
{
        struct dentry *dir = nd->current;
        struct inode *i_dir = dir->inode;
        struct dentry *dentry;
        int err;

        dentry =
                i_dir->d_ops->dirlookup(i_dir, nd->last.str, (int)nd->last.len);
        if (dentry) {
                return dentry;
        }

        /* not found, create it */
        if (open_flags & O_CREAT) {
                dentry = i_dir->d_ops->alloc_dentry();
                if (CHCORE_IS_ERR(dentry)) {
                        return dentry;
                }

                err = i_dir->d_ops->add_dentry(
                        i_dir, dentry, nd->last.str, nd->last.len);
                if (err) {
                        i_dir->d_ops->free_dentry(dentry);
                        return CHCORE_ERR_PTR(err);
                }

                /* we are not currently handling mode in open() */
                mode_t faked_mode = 0x888;

                err = i_dir->d_ops->mknod(i_dir, dentry, faked_mode, FS_REG);
                if (err) {
                        i_dir->d_ops->remove_dentry(i_dir, dentry);
                        i_dir->d_ops->free_dentry(dentry);
                        return CHCORE_ERR_PTR(err);
                }
        }

        return dentry;
}

/**
 * @brief Used in open when looking up the last component of a path, may create
 * the file if not found.
 * @param nd The nd structure representing this path lookup.
 * @param open_flags The open flags of this open() syscall.
 * @return const char* Return NULL if no symlink encountered or should/can not
 * follow, return the symlink to follow it.
 */
static const char *lookup_last_open(struct nameidata *nd, unsigned open_flags)
{
        struct dentry *dentry;

        if (!nd->last.str) {
                return NULL;
        }

        if ((open_flags & O_CREAT)) {
                /*
                 * when O_CREAT is set
                 * the path should not have trailing slashes
                 */
                if (nd->flags & ND_TRAILING_SLASH) {
                        return CHCORE_ERR_PTR(-EISDIR);
                }
        }

        dentry = lookup_create(nd, open_flags);

        if (!dentry) {
                return CHCORE_ERR_PTR(-ENOENT);
        }

        if (CHCORE_IS_ERR(dentry)) {
                return (char *)dentry;
        }

        return step_into(nd, true, dentry);
}

/**
 * @brief lookup a path except its final component
 * @param name The full pathname to lookup.
 * @param nd The nd structure to represent this pathname lookup and to store
 * state information of this lookup.
 * @return int 0 on success, errno on failure.
 */
static int walk_prefix(const char *name, struct nameidata *nd)
{
        int err;
        if (CHCORE_IS_ERR(name)) {
                return CHCORE_PTR_ERR(name);
        }

        while (*name == '/') {
                name++;
        }

        if (!*name) {
                return 0;
        }

        /* each loop deals with one next path component or get a new symlink */
        for (;;) {
                const char *link;
                u64 component_len = get_component_len(name);

                if (component_len > NAME_MAX) {
                        return -ENAMETOOLONG;
                }

                err = init_string(&nd->last, name, component_len);
                if (err) {
                        return err;
                }

                name += component_len;
                /* skipping postfixing '/'s till next component name */
                while (*name == '/') {
                        name++;
                }

                if (!*name) {
                        if (!nd->depth)
                                /* this is the trailing component */
                                return 0;

                        /* pop a link, continue processing */
                        name = nd->stack[--nd->depth];
                }

                link = walk_component(nd, false);

                /* we have another symlink to process */
                if (link) {
                        if (CHCORE_IS_ERR(link)) {
                                return CHCORE_PTR_ERR(link);
                        }

                        /* checked in step_into() that we have space on stack */
                        nd->stack[nd->depth++] = name; /* store current name */
                        name = link; /* deal with the symlink first */
                        continue;
                }

                /* next loop requires nd->current to be a directory */
                if (nd->current->inode->type != FS_DIR) {
                        return -ENOTDIR;
                }
        }
        return 0;
}

/**
 * @brief Find the parent directory of a given pathname. A very simple wrapper
 * of walk_prefix(). Used by rename(), unlink(), etc.
 * @param nd The nd structure representing this lookup.
 * @param path The full path to lookup.
 * @param flags Some restriction of this lookup can be passed by the flags
 * param.
 * @return int 0 on success, errno on failure.
 * @return struct dentry* Returned by pointer, the parent directory's
 * dentry
 * @return char* Returned in nd->last, the name of the last component of the
 * pathname.
 * @note We **DO NOT** call free_string() here because it is normal
 * for the caller to use nd->last after calling path_parentat() (to
 * create/rename/remove it under the parent directory). It should be viewed as
 * the return value of this call.
 */
static int path_parentat(struct nameidata *nd, const char *path, unsigned flags,
                  struct dentry **parent)
{
        init_nd(nd, flags);

        /*
         * there's no need to do the checking of trailing slashes here,
         * since path_parentat never cares about the final component.
         */

        int err = walk_prefix(path, nd);
        if (!err) {
                *parent = nd->current;
        }

        /*
         * we **do not** call free_string() here because it is normal for the
         * caller to use nd->last after calling path_parentat()
         *
         * one should also view nd->last as an output of path_parentat()
         * the subtlety here is annoying but at least we made it clear...
         */
        return err;
}

/**
 * @brief Get the dentry of the full path. Used by: stat(), chmod(), etc.
 * @param nd The nd structure representing this lookup.
 * @param path The full path to lookup.
 * @param flags Some restriction of this lookup can be passed by the flags
 * param.
 * @return int 0 on success, errno on failure.
 * @return struct dentry* Returned by pointer, the final component's
 * dentry.
 * @note We call free_string() here because the caller should never use
 * nd->last after calling path_lookupat().
 */
static int path_lookupat(struct nameidata *nd, const char *path, unsigned flags,
                  struct dentry **dentry)
{
        int err;
        init_nd(nd, flags);

        if (path[strlen(path) - 1] == '/') {
                nd->flags |= ND_TRAILING_SLASH | ND_DIRECTORY | ND_FOLLOW;
        }

        while (!(err = walk_prefix(path, nd))
               && (path = lookup_last(nd)) != NULL) {
                ;
        }

        /* requiring a directory(because of trailing slashes) */
        if (!err && (nd->flags & ND_DIRECTORY)
            && nd->current->inode->type != FS_DIR) {
                err = -ENOTDIR;
        }

        if (!err) {
                *dentry = nd->current;
        }

        /*
         * we call free_string() here because the caller should never use
         * nd->last after calling path_lookupat()
         *
         * in other words, the only effective output of path_lookupat
         * is *dentry when no err is encountered.
         */
        free_string(&nd->last);
        return err;
}

/**
 * @brief Called by open(), behaviour is determined by open_flags.
 * We lookup the path, and do special handling of open().
 * @param nd The nd structure representing this lookup.
 * @param path The full path to lookup.
 * @param open_flags The open flags of the open() syscall.
 * @param flags Some restriction of this lookup can be passed by the flags
 * param.
 * @return int 0 on success, errno on failure.
 * @return struct dentry* Returned by pointer, NULL if not found and cannot be
 * created, or the found/created dentry.
 * @note We call free_string() here because the caller should never use
 * nd->last after calling path_openat().
 *
 */
static int path_openat(struct nameidata *nd, const char *path, unsigned open_flags,
                unsigned flags, struct dentry **dentry)
{
        int err;

        init_nd(nd, flags);

        if (path[strlen(path) - 1] == '/') {
                nd->flags |= ND_TRAILING_SLASH | ND_DIRECTORY | ND_FOLLOW;
        }

        /* we don't follow symlinks at end by default */
        if (!(open_flags & O_NOFOLLOW)) {
                nd->flags |= ND_FOLLOW;
        }

        if (open_flags & O_DIRECTORY) {
                nd->flags |= ND_DIRECTORY;
        }

        while (!(err = walk_prefix(path, nd))
               && (path = lookup_last_open(nd, open_flags)) != NULL) {
                ;
        }

        if (!err) {
                struct inode *inode = nd->current->inode;

                /* we can check O_CREAT | O_EXCL here, but fs_base handles it */

                if ((open_flags & O_CREAT) && (inode->type == FS_DIR)) {
                        err = -EISDIR;
                        goto error;
                }

                if ((nd->flags & ND_DIRECTORY) && !(inode->type == FS_DIR)) {
                        err = -ENOTDIR;
                        goto error;
                }

                /* we can check O_TRUNCATE here, but fs_base handles it */

                *dentry = nd->current;
        }

error:
        /*
         * we call free_string() here because the caller should never use
         * nd->last after calling path_openat(). the reason is the same
         * as explained in path_lookupat()
         */
        free_string(&nd->last);
        return err;
}

/* FS operations */

/* Base inode operations */

/**
 * @brief Create an empty inode of a particular type.
 * @param type The type of the inode to be created,
 * can be one of FS_REG, FS_DIR, FS_SYM.
 * @param mode The access mode of the file, ignored for now.
 * @return inode The newly created inode, NULL if type is illegal or out of
 * memory.
 * @note The created inode is not ready for use. For example the directory is
 * empty and has no dot and dotdot dentries.
 */
static struct inode *tmpfs_inode_init(int type, mode_t mode)
{
        struct inode *inode = malloc(sizeof(struct inode));

        if (inode == NULL) {
                return inode;
        }

#if DEBUG_MEM_USAGE
        tmpfs_record_mem_usage(inode, sizeof(struct inode), INODE);
#endif

        /* Type-specific fields initialization */
        switch (type) {
        case FS_REG:
                inode->f_ops = &regfile_ops;

#if DEBUG_MEM_USAGE
                init_radix_w_deleter(&inode->data, debug_radix_free);
#else
                init_radix_w_deleter(&inode->data, free);
#endif
                break;
        case FS_DIR:
                inode->d_ops = &dir_ops;
                init_htable(&inode->dentries, MAX_DIR_HASH_BUCKETS);
                break;
        case FS_SYM:
                inode->sym_ops = &symlink_ops;
                inode->symlink = NULL;
                break;
        default:
#if DEBUG_MEM_USAGE
                tmpfs_revoke_mem_usage(inode, INODE);
#endif

                free(inode);
                return NULL;
        }

        inode->type = type;
        inode->nlinks = 0; /* ZERO links now */
        inode->size = 0;
        inode->mode = mode;
        inode->opened = false;
        inode->base_ops = &base_inode_ops;

        return inode;
}

/**
 * @brief Open a file.
 * @param inode Inode to be opened.
 * @note Tmpfs does not have anything like an openfile table, and does not to do
 * reference counting on the opened files, they are all done in fs_base. The
 * only thing we have to worry is that it is completely legal for a file to be
 * unlinked when someone is still holding the open file handle and using it, and
 * we can not free the inode at that time, so a flag indicates the file is
 * opened is needed.
 */
static inline void tmpfs_inode_open(struct inode *inode)
{
        inode->opened = true;
}

/**
 * @brief Close a file. If the file has no link, free it.
 * @param inode Inode to be closed
 * @note As said above, when closing, the file may be unlinked before, we should
 * clean it up then.
 */
static void tmpfs_inode_close(struct inode *inode)
{
#if DEBUG
        BUG_ON(!inode->opened);
        BUG_ON(inode->nlinks < 0);
#endif

        inode->opened = false;

        if (inode->nlinks == 0) {
                inode->base_ops->free(inode);
        }
}

/**
 * @brief Increase the inode's nlinks by 1.
 * @param inode
 */
static inline void tmpfs_inode_inc_nlinks(struct inode *inode)
{
#if DEBUG
        BUG_ON(inode->nlinks < 0);
#endif
        inode->nlinks++;
}

/**
 * @brief Decrease the inode's nlinks by 1. If nlinks reaches
 * zero and the inode is not being used, free it.
 * @param inode
 */
static void tmpfs_inode_dec_nlinks(struct inode *inode)
{
#if DEBUG
        BUG_ON(inode->nlinks <= 0);
#endif

        inode->nlinks--;
        if (inode->nlinks == 0 && !inode->opened) {
                inode->base_ops->free(inode);
        }
}

/**
 * @brief Free an inode.
 * @param inode Inode to be freed.
 */
static void tmpfs_inode_free(struct inode *inode)
{
        /* freeing type-specific fields */
        switch (inode->type) {
        case FS_REG:
                radix_free(&inode->data);
                break;
        case FS_DIR:
                htable_free(&inode->dentries);
                break;
        case FS_SYM:
                if (inode->symlink) {
#if DEBUG_MEM_USAGE
                        tmpfs_revoke_mem_usage(inode->symlink, SYMLINK);
#endif
                        free(inode->symlink);
                }
                break;
        default:
                BUG_ON(1);
        }

#if DEBUG_MEM_USAGE
        tmpfs_revoke_mem_usage(inode, INODE);
#endif
        free(inode);
}

/**
 * @brief Get an inode's metadata.
 * @param inode The inode to stat.
 * @return stat The pointer of the buffer to fill the stats in.
 */
static void tmpfs_inode_stat(struct inode *inode, struct stat *stat)
{
        memset(stat, 0, sizeof(struct stat));

        /* We currently support only a small part of stat fields */
        switch (inode->type) {
        case FS_DIR:
                stat->st_mode = S_IFDIR;
                break;
        case FS_REG:
                stat->st_mode = S_IFREG;
                break;
        case FS_SYM:
                stat->st_mode = S_IFLNK;
                break;
        default:
                BUG_ON(1);
        }

#if DEBUG
        BUG_ON(inode->size >= LONG_MAX);
#endif

        stat->st_size = (off_t)inode->size;
        stat->st_nlink = inode->nlinks;
        stat->st_ino = (ino_t)(uintptr_t)inode;
}

/* Regular file operations */

/**
 * @brief read a file's content at offset, and read for size bytes.
 * @param reg The file to be read.
 * @param size Read at most size bytes.
 * @param offset The starting offset of the read.
 * @param buff The caller provided buffer to be filled with the file content.
 * @return ssize_t The actual number of bytes that have been read into the
 * buffer.
 */
static ssize_t tmpfs_file_read(struct inode *reg, char *buff, size_t size,
                               off_t offset)
{
#if DEBUG
        BUG_ON(reg->type != FS_REG);
#endif

        u64 page_no, page_off;
        u64 cur_off = offset;
        size_t to_read;
        void *page;

        /* Returns 0 according to man pages. */
        if (offset >= reg->size)
                return 0;

        size = MIN(reg->size - offset, size);

        while (size > 0 && cur_off <= reg->size) {
                page_no = cur_off / PAGE_SIZE;
                page_off = cur_off % PAGE_SIZE;

                page = radix_get(&reg->data, page_no);
                to_read = MIN(size, PAGE_SIZE - page_off);
                if (!page)
                        memset(buff, 0, to_read);
                else
                        memcpy(buff, (char *)page + page_off, to_read);
                cur_off += to_read;
                buff += to_read;
                size -= to_read;
        }

        return (ssize_t)(cur_off - offset);
}

/**
 * @brief Write a file's content at offset, and write for size bytes.
 * @param reg The file to be written.
 * @param buff The caller provided buffer that is to be written into the file.
 * @param size Write at most size bytes.
 * @param offset The starting offset of the write.
 * @return ssize_t The actual number of bytes that have been written.
 */
static ssize_t tmpfs_file_write(struct inode *reg, const char *buff, size_t len,
                                off_t offset)
{
#if DEBUG
        BUG_ON(reg->type != FS_REG);
#endif

        u64 page_no, page_off;
        off_t cur_off = offset;
        int to_write;
        void *page = NULL;

        if (len == 0)
                return 0;

        while (len > 0) {
                page_no = cur_off / PAGE_SIZE;
                page_off = cur_off % PAGE_SIZE;

                page = radix_get(&reg->data, page_no);
                if (!page) {
                        page = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
                        if (!page)
                                return (ssize_t)(cur_off - offset);

#if DEBUG_MEM_USAGE
                        tmpfs_record_mem_usage(page, PAGE_SIZE, DATA_PAGE);
#endif

                        if (page_off)
                                memset(page, 0, page_off);
                        radix_add(&reg->data, page_no, page);
                }

#if DEBUG
                BUG_ON(page == NULL);
#endif

                to_write = MIN(len, PAGE_SIZE - page_off);
                memcpy((char *)page + page_off, buff, to_write);
                cur_off += to_write;
                buff += to_write;
                len -= to_write;
        }

        if (cur_off > reg->size) {
                reg->size = cur_off;
                if (cur_off % PAGE_SIZE && page) {
                        /* if the last write cannot fill the last page, set the
                         * remaining space to zero to ensure the correctness of
                         * the file_read */
                        page_off = cur_off % PAGE_SIZE;
                        memset((char *)page + page_off, 0, PAGE_SIZE - page_off);
                }
        }
        return (ssize_t)(cur_off - offset);
}

/**
 * @brief Change a file's size to a length.
 * @param reg The file to truncate.
 * @param len The length to change to.
 * @return 0 on success.
 * @note When increasing the file's size, we only allocate the memory space in a
 * lazy fashion. If do need the space to be allocated, consider functions
 * related to fallocate().
 */
static int tmpfs_file_truncate(struct inode *reg, off_t len)
{
#if DEBUG
        BUG_ON(reg->type != FS_REG);
#endif

        u64 page_no, page_off;
        void *page;
        if (len == 0) {
                /* free radix tree and init an empty one */
                radix_free(&reg->data);

#if DEBUG_MEM_USAGE
                init_radix_w_deleter(&reg->data, debug_radix_free);
#else
                init_radix_w_deleter(&reg->data, free);
#endif
                reg->size = 0;
        } else if (len > reg->size) {
                /* truncate should not allocate the space for the file */
                reg->size = len;
        } else if (len < reg->size) {
                size_t cur_off = len;
                size_t to_write;
                page_no = cur_off / PAGE_SIZE;
                page_off = cur_off % PAGE_SIZE;
                if (page_off) {
                        /*
                         * if the last write cannot fill the last page, set the
                         * remaining space to zero to ensure the correctness of
                         * the file_read
                         */
                        page = radix_get(&reg->data, page_no);
                        if (page) {
                                to_write = MIN(reg->size - len,
                                               PAGE_SIZE - page_off);
                                memset((char *)page + page_off, 0, to_write);
                                cur_off += to_write;
                        }
                }
                while (cur_off < reg->size) {
                        page_no = cur_off / PAGE_SIZE;
                        radix_del(&reg->data, page_no, 1);
                        cur_off += PAGE_SIZE;
                }
                reg->size = len;
        }

        return 0;
}

/**
 * @brief Deallocate disk space(memory in tmpfs) in the range specified by
 * params offset to offset + len for a file.
 * @param reg The file to modify.
 * @param offset The start of the deallocate range.
 * @param len The length of the deallocate range.
 * @return int 0 on success, -1 if radix_del() fails.
 * @note For full pages in the range, they are deleted from the file. For
 * partial pages in the range, they are set to zero.
 */
static int tmpfs_file_punch_hole(struct inode *reg, off_t offset, off_t len)
{
#if DEBUG
        BUG_ON(reg->type != FS_REG);
#endif

        u64 page_no, page_off;
        u64 cur_off = offset;
        off_t to_remove;
        void *page;
        int err;

        while (len > 0) {
                page_no = cur_off / PAGE_SIZE;
                page_off = cur_off % PAGE_SIZE;

                to_remove = MIN(len, PAGE_SIZE - page_off);
                cur_off += to_remove;
                len -= to_remove;
                page = radix_get(&reg->data, page_no);
                if (page) {
                        /*
                         * Linux Manpage:
                         * Within the specified range, partial filesystem blocks
                         * are zeroed, and whole filesystem blocks are removed
                         * from the file.
                         */
                        if (to_remove == PAGE_SIZE || cur_off == reg->size) {
                                err = radix_del(&reg->data, page_no, 1);
                                /* if no err, just continue! */
                                if (err) {
                                        return err;
                                }
                        } else {
                                memset((char *)page + page_off, 0, to_remove);
                        }
                }
        }
        return 0;
}

/**
 * @brief Collapse file space in the range from offset to offset + len.
 * @param reg The file to be collapsed.
 * @param offset The start of the to be collapsed range.
 * @param len The length of the range.
 * @return int 0 on success, -EINVAL if the granularity not match or the params
 are illegal, or -1 if radix_del() fails, or -ENOMEM if radix_add() fails.
 * @note The range will be *removed*, without leaving a hole in the file. That
 is, the content start at offset + len will be at offset when this is done, and
 the file size will be len bytes smaller. Tmpfs only allows this to be done at a
 page granularity.
 */
static int tmpfs_file_collapse_range(struct inode *reg, off_t offset, off_t len)
{
#if DEBUG
        BUG_ON(reg->type != FS_REG);
#endif

        u64 page_no1, page_no2;
        u64 cur_off = offset;
        void *page1;
        void *page2;
        u64 remain;
        int err;
        off_t dist;

        /* To ensure efficient implementation, offset and len must be a mutiple
         * of the filesystem logical block size */
        if (offset % PAGE_SIZE || len % PAGE_SIZE)
                return -EINVAL;
        if (offset + len >= reg->size)
                return -EINVAL;

        remain = ((reg->size + PAGE_SIZE - 1) - (offset + len)) / PAGE_SIZE;
        dist = len / PAGE_SIZE;
        while (remain-- > 0) {
                page_no1 = cur_off / PAGE_SIZE;
                page_no2 = page_no1 + dist;

                cur_off += PAGE_SIZE;
                page1 = radix_get(&reg->data, page_no1);
                page2 = radix_get(&reg->data, page_no2);
                if (page1) {
                        err = radix_del(&reg->data, page_no1, 1);
                        if (err)
                                goto error;
                }
                if (page2) {
                        err = radix_add(&reg->data, page_no1, page2);
                        if (err)
                                goto error;
                        err = radix_del(&reg->data, page_no2, 0);
                        if (err)
                                goto error;
                }
        }

        reg->size -= len;
        return 0;

error:
        printf("Error in collapse range!\n");
        return err;
}

/**
 * @brief Zero the given range of a file.
 * @param reg The file to modify.
 * @param offset The start of the range.
 * @param len The length of the range.
 * @param mode The allocate mode of this call.
 * @return 0 on success, -ENOSPC when out of disk(memory) space.
 * @note The range will be set to zero, missing pages will be allocated. If
 * FALLOC_FL_KEEP_SIZE is set in mode, the file size will not be changed.
 */
static int tmpfs_file_zero_range(struct inode *reg, off_t offset, off_t len,
                                 mode_t mode)
{
#if DEBUG
        BUG_ON(reg->type != FS_REG);
#endif

        u64 page_no, page_off;
        u64 cur_off = offset;
        off_t length = len;
        off_t to_zero;
        void *page;

        while (len > 0) {
                page_no = cur_off / PAGE_SIZE;
                page_off = cur_off % PAGE_SIZE;

                to_zero = MIN(len, PAGE_SIZE - page_off);
                cur_off += to_zero;
                len -= to_zero;
                if (!len)
                        to_zero = PAGE_SIZE;
                page = radix_get(&reg->data, page_no);
                if (!page) {
                        page = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
                        if (!page)
                                return -ENOSPC;
#if DEBUG_MEM_USAGE
                        tmpfs_record_mem_usage(page, PAGE_SIZE, DATA_PAGE);
#endif
                        radix_add(&reg->data, page_no, page);
                }

#if DEBUG
                BUG_ON(!page);
#endif

                memset((char *)page + page_off, 0, to_zero);
        }

        if ((!(mode & FALLOC_FL_KEEP_SIZE)) && (offset + length > reg->size))
                reg->size = offset + length;

        return 0;
}

/**
 * @brief Increasing a file's space.
 * @param reg The file to modify.
 * @param offset The start of the range.
 * @param len The length of the range.
 * @return int 0 on success, -EINVAL if the granularity not match or the params
 are illegal, or -1 if radix_del() fails, or -ENOMEM if radix_add() fails.
 * @note The operation inserts spaces at offset with length len, that is: the
 content starting at the offset will be moved to offset + len, and the size of
 the file increased by len. Tmpfs only allows this to happen at page
 granularity.
 */
static int tmpfs_file_insert_range(struct inode *reg, off_t offset, off_t len)
{
#if DEBUG
        BUG_ON(reg->type != FS_REG);
#endif

        u64 page_no1, page_no2;
        void *page;
        int err;
        off_t dist;

        /* To ensure efficient implementation, this mode has the same
         * limitations as FALLOC_FL_COLLAPSE_RANGE regarding the granularity of
         * the operation. (offset and len must be a mutiple of the filesystem
         * logical block size) */
        if (offset % PAGE_SIZE || len % PAGE_SIZE)
                return -EINVAL;
        /* If the offset is equal to or greater than the EOF, an error is
         * returned. For such operations, ftruncate should be used. */
        if (offset >= reg->size)
                return -EINVAL;

        page_no1 = (reg->size + PAGE_SIZE - 1) / PAGE_SIZE;
        dist = len / PAGE_SIZE;
        while (page_no1 >= offset / PAGE_SIZE) {
                page_no2 = page_no1 + dist;
#if DEBUG
                BUG_ON(radix_get(&reg->data, page_no2));
#endif
                page = radix_get(&reg->data, page_no1);
                if (page) {
                        err = radix_del(&reg->data, page_no1, 0);
                        if (err)
                                goto error;
                        err = radix_add(&reg->data, page_no2, page);
                        if (err)
                                goto error;
                }
                page_no1--;
        }

        reg->size += len;
        return 0;

error:
        printf("Error in insert range!\n");
        return err;
}

/**
 * @brief Allocate disk space(memory in tmpfs) for the file, from offset to
 * offset + len, and zero any newly allocated memory space. This ensures later
 * operations within the allocated range will not fail because of lack of memory
 * space.
 * @param reg The file to operate with.
 * @param offset The operation starts at offset.
 * @param len The length of the allocated range.
 * @param keep_size If keep_size is set, the file size will not be changed.
 * Otherwise, if offset + len > reg->size, reg->size will be changed to offset +
 * len.
 * @return int 0 on success, -ENOSPC if not enough disk(memory in tmpfs) space.
 */
static int tmpfs_file_allocate(struct inode *reg, off_t offset, off_t len,
                               int keep_size)
{
#if DEBUG
        BUG_ON(reg->type != FS_REG);
#endif

        u64 page_no;
        u64 cur_off = offset;
        void *page;

        while (cur_off < offset + len) {
                page_no = cur_off / PAGE_SIZE;

                page = radix_get(&reg->data, page_no);
                if (!page) {
                        page = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
                        if (!page)
                                return -ENOSPC;
#if DEBUG_MEM_USAGE
                        tmpfs_record_mem_usage(page, PAGE_SIZE, DATA_PAGE);
#endif

                        if (radix_add(&reg->data, page_no, page)) {
#if DEBUG_MEM_USAGE
                                tmpfs_revoke_mem_usage(page, DATA_PAGE);
#endif
                                free(page);
                                return -ENOSPC;
                        }
                        memset(page, 0, PAGE_SIZE);
                }
                cur_off += PAGE_SIZE;
        }

        if (offset + len > reg->size && !keep_size) {
                reg->size = offset + len;
        }
        return 0;
}

/* Directory operations */

/**
 * @brief Allocate a dentry, and initialize it with the parent dentry.
 * @param d_parent The parent dentry of the to-be-allocated dentry.
 * @return The newly created dentry
 */
static struct dentry *tmpfs_alloc_dent(void)
{
        struct dentry *dentry = malloc(sizeof(struct dentry));
        if (!dentry) {
                return CHCORE_ERR_PTR(-ENOMEM);
        }

#if DEBUG_MEM_USAGE
        tmpfs_record_mem_usage(dentry, sizeof(struct dentry), DENTRY);
#endif

        dentry->inode = NULL;
        dentry->name.str = NULL;
        return dentry;
}

/**
 * @brief Free a dentry and its name string.
 * @param inode The inode which does this operation, and should be the
 * to-be-freed dentry's parent directory.
 * @param dentry The dentry that is to be freed.
 */
static void tmpfs_free_dent(struct dentry *dentry)
{
        free_string(&dentry->name);

#if DEBUG_MEM_USAGE
        tmpfs_revoke_mem_usage(dentry, DENTRY);
#endif
        free(dentry);
}

/**
 * @brief Add a just allocated dentry into a directory, and adjust the dir's
 * size.
 * @param dir The directory to add the new dentry.
 * @param new_dent The newly created dentry that will be added to the dir.
 * @param name The name of the dentry.
 * @param len The length of the name.
 * @return int 0 for success, -ENOMEM if init_string() fails.
 * @note This function does not create the new dentry, it presuppose a created
 * dentry.
 */
static int tmpfs_dir_add_dent(struct inode *dir, struct dentry *new_dent,
                              char *name, size_t len)
{
#if DEBUG
        BUG_ON(dir->type != FS_DIR);
#endif

        int err;

        err = init_string(&new_dent->name, name, len); /* copy the str */
        if (err) {
                return err;
        }

        htable_add(&dir->dentries, (u32)(new_dent->name.hash), &new_dent->node);
        dir->size += DENT_SIZE;

        return 0;
}

/**
 * @brief Remove a dentry from the dir's htable, adjust the size.
 * @param dir the directory to remove the dentry from.
 * @param dentry the dentry to be removed.
 * @note This operation only operate on the directory, *dentry is not freed
 */
static void tmpfs_dir_remove_dent(struct inode *dir, struct dentry *dentry)
{
#if DEBUG
        BUG_ON(dir->type != FS_DIR);
#endif

        htable_del(&dentry->node);
        dir->size -= DENT_SIZE;
        /* not freeing the dentry now */
}

/**
 * @brief Check if the directory is an empty and legal one.
 * @param dir The directory to be checked.
 * @return bool true for empty and legal, false otherwise.
 * @note By saying empty and legal, we mean the directory should *have and only
 * have* the dot dentry and the dotdot dentry in its dentries table.
 */
static bool tmpfs_dir_empty(struct inode *dir)
{
#if DEBUG
        BUG_ON(dir->type != FS_DIR);
#endif

        struct dentry *iter;
        int i = 0;
        bool found_dot, found_dotdot;

        found_dot = false;
        found_dotdot = false;

        for_each_in_htable (iter, i, node, &dir->dentries) {
                if (strcmp(iter->name.str, ".") == 0) {
                        found_dot = true;
                } else if (strcmp(iter->name.str, "..") == 0) {
                        found_dotdot = true;
                } else {
                        /* dentry other than "." or "..", dir not empty */
                        return false;
                }
        }

        return found_dot && found_dotdot;
}

/**
 * @brief Link the dentry with the inode, and do nothing else.
 * @param dir the parent directory which the dentry belongs to.
 * @param dentry The dentry, which has already been added to the directory, to
 * hold the inode.
 * @param inode The inode to be linked with the dentry.
 */
static void tmpfs_dir_link(struct inode *dir, struct dentry *dentry,
                           struct inode *inode)
{
#if DEBUG
        BUG_ON(dir->type != FS_DIR);
#endif

        dentry->inode = inode;
        inode->base_ops->inc_nlinks(inode);
}

/**
 * @brief Unlink the dentry with its inode, and also remove the dentry from the
 * directory and free the dentry.
 * @param dir The parent directory which has the dentry in it.
 * @param dentry The dentry to be unlinked.
 */
static void tmpfs_dir_unlink(struct inode *dir, struct dentry *dentry)
{
#if DEBUG
        BUG_ON(dir->type != FS_DIR);
        BUG_ON(dentry->inode == NULL);
#endif

        struct inode *inode = dentry->inode;

        dir->d_ops->remove_dentry(dir, dentry);
        dir->d_ops->free_dentry(dentry);
        inode->base_ops->dec_nlinks(inode);
}

/**
 * @brief Make a new directory under a parent dir.
 * @param dir The parent dir to hold the new directory.
 * @param dentry The dentry of the new directory.
 * @param mode The access mode of the dir, ignored.
 * @return int 0 on success, -ENOMEM on failure.
 * @return inode Upon success, a new directory inode is created and can be
 * accessed by dentry->inode.
 */
static int tmpfs_dir_mkdir(struct inode *dir, struct dentry *dentry,
                           mode_t mode)
{
#if DEBUG
        BUG_ON(dir->type != FS_DIR);
#endif

        int err = dir->d_ops->mknod(dir, dentry, mode, FS_DIR);
        if (err) {
                return err;
        }

        struct inode *new_dir = dentry->inode;

        struct dentry *dot = new_dir->d_ops->alloc_dentry();
        if (CHCORE_IS_ERR(dot)) {
                err = CHCORE_PTR_ERR(dot);
                goto free_node;
        }

        err = new_dir->d_ops->add_dentry(new_dir, dot, ".", 1);
        if (err) {
                goto free_dot;
        }

        new_dir->d_ops->link(new_dir, dot, new_dir);

        struct dentry *dotdot = new_dir->d_ops->alloc_dentry();
        if (CHCORE_IS_ERR(dotdot)) {
                err = CHCORE_PTR_ERR(dotdot);
                goto remove_dot;
        }

        err = new_dir->d_ops->add_dentry(new_dir, dotdot, "..", 2);
        if (err) {
                goto free_dotdot;
        }

        new_dir->d_ops->link(new_dir, dotdot, dir);

        return 0;

free_dotdot:
        new_dir->d_ops->free_dentry(dotdot);
remove_dot:
        new_dir->d_ops->remove_dentry(new_dir, dot);
free_dot:
        new_dir->d_ops->free_dentry(dot);
free_node:
        dentry->inode->base_ops->free(dentry->inode);
        /* the caller-allocated dentry is not freed */
        dentry->inode = NULL;

        return err;
}

/**
 * @brief Remove an empty directory and its dentry under the parent directory.
 * @param dir The parent directory which holds the to-be-removed directory.
 * @param dentry The dentry of the directory to remove.
 * @return int 0 on success, -ENOTEMPTY if the to-be-removed directory is not
 * empty.
 */
static int tmpfs_dir_rmdir(struct inode *dir, struct dentry *dentry)
{
#if DEBUG
        BUG_ON(dir->type != FS_DIR);
        BUG_ON(dentry->inode->type != FS_DIR);
#endif

        struct inode *to_remove = dentry->inode;

        if (!to_remove->d_ops->is_empty(to_remove)) {
                return -ENOTEMPTY;
        }

        struct dentry *dot = to_remove->d_ops->dirlookup(to_remove, ".", 1);
        struct dentry *dotdot = to_remove->d_ops->dirlookup(to_remove, "..", 2);

#if DEBUG
        BUG_ON(dot == NULL || dotdot == NULL);
#endif

        to_remove->d_ops->unlink(to_remove, dot);
        to_remove->d_ops->unlink(to_remove, dotdot);

        dir->d_ops->unlink(dir, dentry);

        return 0;
}

/*
 * All illegal cases have been handled outside
 * Call to this function is guaranteed to be legal and will succeed
 */
/**
 * @brief Rename an inode by reclaiming its dentry.
 * @param old_dir The parent directory where the inode was under.
 * @param old_dentry The dentry for the inode under old_dir.
 * @param new_dir The parent directory where the inode is moving to.
 * @param new_dentry The dentry that the inode is moving to. Should be added to
 * the new_dir already.
 * @note The rename() system call is very different with this simple function
 * because of all the corner cases and checks. This operation is simple because
 * it presupposes all the checks have been done outside before the call to this
 * function so it can only handle the legal case and is guaranteed to succeed.
 */
static void tmpfs_dir_rename(struct inode *old_dir, struct dentry *old_dentry,
                             struct inode *new_dir, struct dentry *new_dentry)
{
#if DEBUG
        BUG_ON(new_dir->type != FS_DIR);
        BUG_ON(old_dir->type != FS_DIR);
#endif

        /* we just link the new_dentry to the inode and unlink the old_dentry */
        struct inode *inode = old_dentry->inode;

        new_dir->d_ops->link(new_dir, new_dentry, inode); /* link first */
        old_dir->d_ops->unlink(old_dir, old_dentry);

        if (inode->type == FS_DIR) {
                struct dentry *dotdot = inode->d_ops->dirlookup(inode, "..", 2);

#if DEBUG
                struct dentry *dot = inode->d_ops->dirlookup(inode, ".", 1);
                BUG_ON(!dot);
                BUG_ON(!dotdot);
                BUG_ON(dot->inode != inode);
                BUG_ON(dotdot->inode != old_dir);
#endif

                dotdot->inode = new_dir;

                /* dotdot is changed*/
                old_dir->base_ops->dec_nlinks(old_dir);
                new_dir->base_ops->inc_nlinks(new_dir);
        }
}

/**
 * @brief Make a new inode under the parent directory.
 * @param dir The parent directory to hold the newly created inode.
 * @param dentry The dentry for the new inode. It should be already allocated
 * and added into the dir.
 * @param mode The access mode of this new inode. Ignored.
 * @param type The type of the inode. FS_REG, FS_DIR, FS_SYM can be used.
 * @return int 0 on success, -ENOMEM if the type is wrong or no enough memory.
 * @return inode On success, the newly created inode is returned and can be
 * accessed in dentry->inode.
 */
static int tmpfs_dir_mknod(struct inode *dir, struct dentry *dentry,
                           mode_t mode, int type)
{
#if DEBUG
        BUG_ON(dir->type != FS_DIR);
#endif

        struct inode *inode = tmpfs_inode_init(type, mode);
        if (inode == NULL) {
                return -ENOMEM;
        }

        /* linking the inode and the dentry */
        dir->d_ops->link(dir, dentry, inode);

        return 0;
}

/**
 * @brief Lookup a given dentry name under the directory.
 * @param dir The directory to lookup.
 * @param name The name of the dentry to find.
 * @param len The length of the dentry name.
 * @return dentry NULL if not found, a pointer to the dentry if found.
 */
static struct dentry *tmpfs_dirlookup(struct inode *dir, const char *name,
                                      size_t len)
{
#if DEBUG
        BUG_ON(dir->type != FS_DIR);
#endif
        u64 hash;
        struct hlist_head *head;
        struct dentry *iter;

        hash = hash_chars(name, len);

        head = htable_get_bucket(&dir->dentries, (u32)hash);
        for_each_in_hlist (iter, node, head) {
                if (iter->name.len == len
                    && strncmp(iter->name.str, name, len) == 0) {
                        return iter;
                }
        }

        return NULL;
}

#define DIRENT_NAME_MAX 256

/**
 * @brief Fill a dirent with some metadata.
 * @param dirpp The pointer of pointer of the dirent struct.
 * @param end The end of the array of dirent.
 * @param name The name of the dirent.
 * @param off The offset of the dirent in the directory.
 * @param type The type of the dirent.
 * @param ino The size of the inode.
 * @return int The length of the written data.
 */
static int tmpfs_dir_fill_dirent(void **dirpp, void *end, char *name, off_t off,
                                 unsigned char type, ino_t ino)
{
        struct dirent *dirp = *(struct dirent **)dirpp;
        void *p = dirp;
        unsigned short len = sizeof(struct dirent);
        p = (char *)p + len;
        if (p > end)
                return -EAGAIN;
        dirp->d_ino = ino;
        dirp->d_off = off;
        dirp->d_reclen = len;
        dirp->d_type = type;
        strlcpy(dirp->d_name, name, DIRENT_NAME_MAX);
        *dirpp = p;
        return len;
}

/**
 * @brief Scan a directory's dentries and write them into a buffer.
 * @param dir The directory to scan.
 * @param start The index in directory's dentry table to scan with.
 * @param buf The caller provided buffer of the dirent array.
 * @param end The end of the dirent array.
 * @return int The number of dentries scanned.
 * @return read_bytes The number of bytes written to the buffer.
 */
static int tmpfs_dir_scan(struct inode *dir, unsigned int start, void *buf,
                          void *end, int *read_bytes)
{
#if DEBUG
        BUG_ON(dir->type != FS_DIR);
#endif

        int cnt = 0, b, ret;
        ino_t ino;
        void *p = buf;
        unsigned char type;
        struct dentry *iter;

        for_each_in_htable (iter, b, node, &dir->dentries) {
                if (cnt >= start) {
                        type = iter->inode->type;
                        ino = iter->inode->size;

                        ret = tmpfs_dir_fill_dirent(
                                &p, end, iter->name.str, cnt, type, ino);

                        if (ret <= 0) {
                                if (read_bytes) {
                                        *read_bytes = (int)((char *)p - (char *)buf);
                                }
                                return (int)(cnt - start);
                        }
                }
                cnt++;
        }

        if (read_bytes) {
                *read_bytes = (int)((char *)p - (char *)buf);
        }
        return (int)(cnt - start);
}

/* Symlink operations*/

/**
 * @brief Read the content of a symlink
 * @param symlink The symlink.
 * @param buff The buffer to read the symlink into.
 * @param len The length of the buffer
 * @return ssize_t The actual bytes read into the buffer.
 */
static ssize_t tmpfs_symlink_read(struct inode *symlink, char *buff, size_t len)
{
#if DEBUG
        BUG_ON(symlink->type != FS_SYM);
#endif

        len = len < symlink->size ? len : symlink->size;
        memcpy(buff, symlink->symlink, len);
        return (ssize_t)len;
}

/**
 * @brief Write a symlink.
 * @param symlink The symlink.
 * @param buff The buffer of the content to be written.
 * @param len The length of the symlink to be written.
 * @return ssize_t The length of the link successfully written, or -ENAMETOOLONG
 * if the link is too long, or -ENOMEM if there is no enough memory for the link
 */
static ssize_t tmpfs_symlink_write(struct inode *symlink, const char *buff,
                                   size_t len)
{
#if DEBUG
        BUG_ON(symlink->type != FS_SYM);
#endif

        if (len > MAX_SYM_LEN) {
                return -ENAMETOOLONG;
        }

        if (symlink->symlink) {
#if DEBUG_MEM_USAGE
                tmpfs_revoke_mem_usage(symlink->symlink, SYMLINK);
#endif
                free(symlink->symlink);
        }

        symlink->symlink = malloc(len + 1);
        if (!symlink->symlink) {
                return -ENOMEM;
        }
#if DEBUG_MEM_USAGE
        tmpfs_record_mem_usage(symlink->symlink, len + 1, SYMLINK);
#endif

        memcpy(symlink->symlink, buff, len);
        symlink->symlink[len] = '\0';

        symlink->size = (off_t)len;

        return (ssize_t)len;
}

static struct base_inode_ops base_inode_ops = {
        .open = tmpfs_inode_open,
        .close = tmpfs_inode_close,
        .inc_nlinks = tmpfs_inode_inc_nlinks,
        .dec_nlinks = tmpfs_inode_dec_nlinks,
        .free = tmpfs_inode_free,
        .stat = tmpfs_inode_stat,
};

static struct regfile_ops regfile_ops = {
        .read = tmpfs_file_read,
        .write = tmpfs_file_write,
        .truncate = tmpfs_file_truncate,
        .punch_hole = tmpfs_file_punch_hole,
        .collapse_range = tmpfs_file_collapse_range,
        .zero_range = tmpfs_file_zero_range,
        .insert_range = tmpfs_file_insert_range,
        .allocate = tmpfs_file_allocate,
};

static struct dir_ops dir_ops = {
        .alloc_dentry = tmpfs_alloc_dent,
        .free_dentry = tmpfs_free_dent,
        .add_dentry = tmpfs_dir_add_dent,
        .remove_dentry = tmpfs_dir_remove_dent,
        .is_empty = tmpfs_dir_empty,
        .dirlookup = tmpfs_dirlookup,
        .mknod = tmpfs_dir_mknod,
        .link = tmpfs_dir_link,
        .unlink = tmpfs_dir_unlink,
        .mkdir = tmpfs_dir_mkdir,
        .rmdir = tmpfs_dir_rmdir,
        .rename = tmpfs_dir_rename,
        .scan = tmpfs_dir_scan,
};

static struct symlink_ops symlink_ops = {
        .read_link = tmpfs_symlink_read,
        .write_link = tmpfs_symlink_write,
};

static int tmpfs_open(const char *path, int o_flags, int mode, ino_t *vnode_id,
               off_t *vnode_size, int *vnode_type, void **vnode_private)
{
        int err;
        struct nameidata nd;
        struct dentry *dentry;

        err = path_openat(&nd, path, o_flags, 0, &dentry);

        if (!err) {
                struct inode *inode = dentry->inode;

                *vnode_id = (ino_t)(uintptr_t)inode;
                *vnode_size = inode->size;
                *vnode_private = inode;

                /* vnode type can not be symlink? */
                switch (inode->type) {
                case FS_REG:
                        *vnode_type = FS_NODE_REG;
                        break;
                case FS_DIR:
                        *vnode_type = FS_NODE_DIR;
                        break;
                default:
                        break;
                }

                inode->base_ops->open(inode);
        }

        return err;
}

static int tmpfs_close(void *operator, bool is_dir /* not handled */, bool do_close)
{
        struct inode *inode = (struct inode *)operator;
        if (do_close) {
                inode->base_ops->close(inode);
        }

        return 0;
}

static ssize_t tmpfs_read(void *operator, off_t offset, size_t size, char *buf)
{
        struct inode *inode = (struct inode *)operator;
        BUG_ON(inode->type != FS_REG);

        return inode->f_ops->read(inode, buf, size, offset);
}

static ssize_t tmpfs_write(void *operator, off_t offset, size_t size, const char *buf)
{
        struct inode *inode = (struct inode *)operator;
        BUG_ON(inode->type != FS_REG);
        return inode->f_ops->write(inode, buf, size, offset);
}

/* Directory operations */
static int tmpfs_mkdir(const char *path, mode_t mode)
{
        int err;
        struct nameidata nd;
        struct dentry *d_parent, *d_new_dir;
        struct inode *i_parent;

        err = path_parentat(&nd, path, 0, &d_parent);
        if (err) {
                goto error;
        }
        /* only slashes */
        if (nd.last.str == NULL) {
                return -EBUSY;
        }

        /* creating the new dir */
        i_parent = d_parent->inode;
        d_new_dir =
                i_parent->d_ops->dirlookup(i_parent, nd.last.str, nd.last.len);
        if (d_new_dir) {
                err = -EEXIST;
                goto error;
        }

        d_new_dir = i_parent->d_ops->alloc_dentry();
        if (CHCORE_IS_ERR(d_new_dir)) {
                err = CHCORE_PTR_ERR(d_new_dir);
                goto error;
        }

        err = i_parent->d_ops->add_dentry(
                i_parent, d_new_dir, nd.last.str, nd.last.len);
        if (err) {
                goto free_dent;
        }

        err = i_parent->d_ops->mkdir(i_parent, d_new_dir, mode);
        if (err) {
                goto remove_dent;
        }

        free_string(&nd.last);
        return 0;

remove_dent:
        i_parent->d_ops->remove_dentry(i_parent, d_new_dir);
free_dent:
        i_parent->d_ops->free_dentry(d_new_dir);
error:
        free_string(&nd.last);
        return err;
}


static int tmpfs_getdents(int fd, unsigned int count, char *buff)
{
        struct inode *inode = (struct inode *)server_entrys[fd]->vnode->private;
        int ret = 0, read_bytes;
        if (inode) {
                if (inode->type == FS_DIR) {
                        ret = inode->d_ops->scan(inode,
                                                 server_entrys[fd]->offset,
                                                 buff,
                                                 buff + count,
                                                 &read_bytes);

                        server_entrys[fd]->offset += ret;
                        ret = read_bytes;
                } else {
                        ret = -ENOTDIR;
                }
        } else {
                ret = -ENOENT;
        }
        return ret;
}

/*
 * Some facts is ensured when tmpfs_rename is called by fs_base:
 *     1. the two paths is not ended with dots
 *     2. oldpath actually exists
 *     3. oldpath is not an ancestor of new
 *     4. newpath has a valid, existed prefix and it's a dir
 *     5. if newpath exists, the two paths' types match
 *     6. if newpath exists, the newpath is removed.
 *
 * NOTE: dependency on fs_base
 * The implementation relies on these facts so it can be simple,
 * but if the implementation of fs_base changed, the implementation
 * here may also need modification
 */
static int tmpfs_rename(const char *oldpath, const char *newpath)
{
        int err;
        struct nameidata nd;
        struct dentry *d_old_parent, *d_new_parent, *d_old, *d_new;
        struct inode *i_old_parent, *i_new_parent;

        err = path_parentat(&nd, oldpath, 0, &d_old_parent);
        if (err) {
                printf("oldpath should exist!\n");
                goto error;
        }
        /* only slashes */
        if (nd.last.str == NULL) {
                return -EBUSY;
        }

        i_old_parent = d_old_parent->inode;

        d_old = i_old_parent->d_ops->dirlookup(
                i_old_parent, nd.last.str, nd.last.len);

        free_string(&nd.last);

        err = path_parentat(&nd, newpath, 0, &d_new_parent);
        if (err) {
                printf("newpath prefix should exist!\n");
                goto error;
        }
        /* only slashes */
        if (nd.last.str == NULL) {
                return -EBUSY;
        }

        i_new_parent = d_new_parent->inode;

        d_new = i_new_parent->d_ops->alloc_dentry();
        if (CHCORE_IS_ERR(d_new)) {
                err = CHCORE_PTR_ERR(d_new);
                goto error;
        }

        err = i_new_parent->d_ops->add_dentry(
                i_new_parent, d_new, nd.last.str, nd.last.len);
        if (err) {
                goto free_dent;
        }

        i_old_parent->d_ops->rename(i_old_parent, d_old, i_new_parent, d_new);

        free_string(&nd.last);
        return 0;

free_dent:
        i_new_parent->d_ops->free_dentry(d_new);
error:
        free_string(&nd.last);
        return err;
}

static int tmpfs_fstat(int fd, struct stat *stat)
{
        struct inode *inode;

        BUG_ON(!server_entrys[fd]);
        inode = (struct inode *)server_entrys[fd]->vnode->private;

        inode->base_ops->stat(inode, stat);

        return 0;
}

static int tmpfs_fstatat(const char *path, struct stat *st, int flags)
{
        int err;
        struct nameidata nd;
        struct dentry *dentry;
        struct inode *inode;

        /*
         * POSIX says we should follow the trailing symlink,
         * except AT_SYMLINK_NOFOLLOW is set in @flags
         */
        err = path_lookupat(&nd,
                            path,
                            flags & AT_SYMLINK_NOFOLLOW ? 0 : ND_FOLLOW,
                            &dentry);
        if (err) {
                return err;
        }

        inode = dentry->inode;
        inode->base_ops->stat(inode, st);
        return 0;
}

static int tmpfs_ftruncate(void *operator, off_t len)
{
        struct inode *inode = (struct inode *)operator;

        if (inode->type == FS_DIR)
                return -EISDIR;

        if (inode->type != FS_REG)
                return -EINVAL;

        return inode->f_ops->truncate(inode, len);
}

static int tmpfs_rmdir(const char *path, int flags)
{
        int err;
        struct nameidata nd;
        struct dentry *d_parent, *d_to_remove;
        struct inode *i_parent;

        err = path_parentat(&nd, path, 0, &d_parent);
        if (err) {
                goto error;
        }
        /* only slashes */
        if (nd.last.str == NULL) {
                return -EBUSY;
        }
        i_parent = d_parent->inode;

        d_to_remove =
                i_parent->d_ops->dirlookup(i_parent, nd.last.str, nd.last.len);
        if (!d_to_remove) {
                err = -ENOENT;
                goto error;
        }

        if (d_to_remove->inode->type != FS_DIR) {
                err = -ENOTDIR;
                goto error;
        }

        err = i_parent->d_ops->rmdir(i_parent, d_to_remove);

error:
        free_string(&nd.last);
        return err;
}

/* File and directory operations */
static int tmpfs_unlink(const char *path, int flags)
{
        int err;
        struct nameidata nd;
        struct dentry *d_parent, *d_unlink;
        struct inode *i_parent;

        if (flags & (~AT_SYMLINK_NOFOLLOW)) {
                return -EINVAL;
        }

        err = path_parentat(&nd, path, 0, &d_parent);
        if (err) {
                goto error;
        }
        /* only slashes */
        if (nd.last.str == NULL) {
                return -EBUSY;
        }

        i_parent = d_parent->inode;

        d_unlink =
                i_parent->d_ops->dirlookup(i_parent, nd.last.str, nd.last.len);
        if (!d_unlink) {
                err = -ENOENT;
                goto error;
        }

        if (d_unlink->inode->type == FS_DIR) {
                err = -EISDIR;
                goto error;
        }

        i_parent->d_ops->unlink(i_parent, d_unlink);

error:
        free_string(&nd.last);
        return err;
}

int libtmpfs_open(const char *pathname, int flags, mode_t mode)
{
        int entry_id;
        int ret;

        ino_t vnode_id;
        int vnode_type;
        off_t vnode_size;
        void *vnode_private;

        struct fs_vnode *vnode;

        off_t entry_off;

        if (strlen(pathname) == 0) {
                return -ENOENT;
        }

        /*
         * If O_CREAT and O_EXCL are set, open() shall fail if the file exists.
         */
        if ((flags & O_CREAT) && (flags & O_EXCL)) {
                struct stat st;
                ret = tmpfs_fstatat(pathname, &st, AT_SYMLINK_NOFOLLOW);
                if (ret == 0) {
                        return -EEXIST;
                }
        }

        ret = tmpfs_open(pathname,
                              flags,
                              mode,
                              &vnode_id,
                              &vnode_size,
                              &vnode_type,
                              &vnode_private);
        if (ret != 0) {
                return ret;
        }

        if ((flags & O_DIRECTORY) && vnode_type != FS_NODE_DIR) {
                tmpfs_close(
                        vnode_private, (vnode_type == FS_NODE_DIR), true);
                return -ENOTDIR;
        }

        if ((flags & (O_RDWR | O_WRONLY)) && vnode_type == FS_NODE_DIR) {
                tmpfs_close(
                        vnode_private, (vnode_type == FS_NODE_DIR), true);
                return -ENOTDIR;
        }

        if (flags & O_NOCTTY) {
                BUG_ON(1);
        }

        if (!(flags & (O_RDWR | O_WRONLY)) && (flags & (O_TRUNC | O_APPEND))) {
                tmpfs_close(
                        vnode_private, (vnode_type == FS_NODE_DIR), true);
                return -EACCES;
        }

        if ((flags & O_TRUNC) && (vnode_type == FS_NODE_REG)) {
                tmpfs_ftruncate(vnode_private, 0);
        }

        entry_id = alloc_entry();
        if (entry_id < 0) {
                tmpfs_close(
                        vnode_private, (vnode_type == FS_NODE_DIR), true);
                return -EMFILE;
        }

        if ((flags & O_APPEND) && (vnode_type == FS_NODE_REG)) {
                entry_off = vnode_size;
        } else {
                entry_off = 0;
        }

        vnode = get_fs_vnode_by_id(vnode_id);
        if (NULL != vnode) {
                /* Assign new entry to existing vnode, close newly opened struct
                 */
                inc_ref_fs_vnode(vnode);
                assign_entry(server_entrys[entry_id],
                             flags,
                             entry_off,
                             1,
                             (void *)strdup(pathname),
                             vnode);
                tmpfs_close(
                        vnode_private, (vnode_type == FS_NODE_DIR), false);
        } else {
                vnode = alloc_fs_vnode(
                        vnode_id, vnode_type, vnode_size, vnode_private);
                if (vnode == NULL) {
                        tmpfs_close(vnode_private,
                                         (vnode_type == FS_NODE_DIR),
                                         true);
                        free_entry(entry_id);
                        return -ENOMEM;
                }
                push_fs_vnode(vnode);
                assign_entry(server_entrys[entry_id],
                             flags,
                             entry_off,
                             1,
                             (void *)strdup(pathname),
                             vnode);
        }

        return entry_id;
}

int libtmpfs_close(int fd)
{
        int entry_id = fd;
        struct fs_vnode *vnode;

        /* Parsing and check arguments */
        if (fd_type_invalid(entry_id, true)
            && fd_type_invalid(entry_id, false)) {
                return -ENOENT;
        }

        vnode = server_entrys[entry_id]->vnode;
        server_entrys[entry_id]->refcnt--;
        if (server_entrys[entry_id]->refcnt == 0) {
                free_entry(entry_id);
                dec_ref_fs_vnode(vnode);
        }

        /*
         * To preserve page cache even after we close the file,
         * we don't revoke vnode when user call close().
         */

        /* Revoke vnode, if refcnt == 0 */

        return 0;
}

int libtmpfs_mkdir(const char *pathname, mode_t mode)
{
        int ret;

        if (strlen(pathname) == 0) {
                return -ENOENT;
        }

        ret = tmpfs_mkdir(pathname, mode);
        return ret;
}

int libtmpfs_rename(const char *oldpath, const char *newpath)
{
        int ret;
        char new_path_prefix[FS_REQ_PATH_BUF_LEN];
        struct stat st;
        bool old_is_dir, new_is_dir;
        ino_t old_ino;

        if (strlen(oldpath) == 0 || strlen(newpath) == 0) {
                return -ENOENT;
        }

        /* Check . and .. in the final component */
        if ((ret = check_path_leaf_is_not_dot(oldpath)) != 0)
                return ret;
        if ((ret = check_path_leaf_is_not_dot(newpath)) != 0)
                return ret;

        /* Check if oldpath exists */
        ret = tmpfs_fstatat(oldpath, &st, AT_SYMLINK_NOFOLLOW);
        if (ret != 0) {
                return ret;
        }

        old_is_dir = (st.st_mode & S_IFDIR) ? true : false;
        old_ino = st.st_ino;

        /* Check old is not a ancestor of new */
        if (strncmp(oldpath, newpath, strlen(oldpath)) == 0) {
                if (newpath[strlen(oldpath)] == '/')
                        return -EINVAL;
        }

        /* Check if new_path_prefix valid*/
        if (get_path_prefix(newpath, new_path_prefix) == -1) {
                return -EINVAL;
        }
        if (new_path_prefix[0]) {
                /* this is a prefix, so we should follow the symlink? */
                ret = tmpfs_fstatat(
                        new_path_prefix, &st, AT_SYMLINK_FOLLOW);
                if (ret)
                        return ret;

                if (!(st.st_mode & S_IFDIR))
                        return -ENOTDIR;
        }

        /* If oldpath and newpath both exists */
        ret = tmpfs_fstatat(newpath, &st, AT_SYMLINK_NOFOLLOW);
        if (ret != -ENOENT) {
                new_is_dir = (st.st_mode & S_IFDIR) ? true : false;
                /* oldpath and newpath are the same file, do nothing */
                if (old_ino == st.st_ino) {
                        return 0;
                }
                if (old_is_dir && !new_is_dir)
                        return -ENOTDIR;
                if (!old_is_dir && new_is_dir)
                        return -EISDIR;
                if (old_is_dir) {
                        /* both old and new are dirs */
                        ret = tmpfs_rmdir(newpath, AT_SYMLINK_NOFOLLOW);
                        if (ret == -ENOTEMPTY)
                                return ret;
                        BUG_ON(ret);
                } else {
                        /* both regular */
                        ret = tmpfs_unlink(newpath, AT_SYMLINK_NOFOLLOW);
                        if (ret)
                                return ret;
                        BUG_ON(ret);
                }
        }

        ret = tmpfs_rename(oldpath, newpath);

        return ret;
}

ssize_t libtmpfs_read(int fd, void *buf, size_t size)
{
        off_t offset;
        void *operator;
        int ret;
        struct fs_vnode *vnode;

        ret = 0;

        pthread_mutex_lock(&server_entrys[fd]->lock);
        pthread_rwlock_rdlock(&server_entrys[fd]->vnode->rwlock);

        offset = (off_t)server_entrys[fd]->offset;
        vnode = server_entrys[fd]->vnode;
        operator= server_entrys[fd]->vnode->private;

        /* Checking open flags: reading file opened as write-only */
        if (server_entrys[fd]->flags & O_WRONLY) {
                return -EBADF;
        }

        /* Do not read a directory directly */
        if (server_entrys[fd]->vnode->type == FS_NODE_DIR) {
                return -EISDIR;
        }

        /*
         * If offset is already outside the file,
         *      do nothing and return 0
         */
        if (offset >= server_entrys[fd]->vnode->size) {
                goto out;
        }

        /*
         * If offset + size > file_size,
         * 	change size to (file_size - offset).
         */
        if (offset + size > server_entrys[fd]->vnode->size) {
                size = server_entrys[fd]->vnode->size - offset;
        }

        /**
         * read(2):
         * On Linux, read() (and similar system calls) will transfer at most
         * 0x7ffff000 (2,147,479,552) bytes, returning the number of bytes
         * actually transferred.  (This is true on both 32-bit and 64-bit
         * systems.)
         */
        size = size <= READ_SIZE_MAX ? size : READ_SIZE_MAX;

        /*
         * Server-side read operation should implement like:
         * - Base: read file from `offset` for `size` length,
         *      if it touch a file ending, return content from offset to end
         *      and return bytes read.
         */
        ret = tmpfs_read(operator, offset, size, buf);

        /* Update server_entry and vnode metadata */
        server_entrys[fd]->offset += ret;

out:
        pthread_rwlock_unlock(&server_entrys[fd]->vnode->rwlock);
        pthread_mutex_unlock(&server_entrys[fd]->lock);
        return ret;
}

ssize_t libtmpfs_write(int fd, const void *buf, size_t size)
{
        off_t offset;
        void *operator;
        int ret;
        struct fs_vnode *vnode;

        ret = 0;

        pthread_mutex_lock(&server_entrys[fd]->lock);
        pthread_rwlock_wrlock(&server_entrys[fd]->vnode->rwlock);

        offset = (off_t)server_entrys[fd]->offset;
        vnode = server_entrys[fd]->vnode;
        operator= server_entrys[fd]->vnode->private;

        /* Checking open flags: writing file opened as read-only */
        if (server_entrys[fd]->flags & O_RDONLY) {
                return -EBADF;
        }

        /*
         * If size == 0, do nothing and return 0
         * Even the offset is outside of the file, inode size is not changed!
         */
        if (size == 0) {
                goto out;
        }

        /*
         * POSIX: Before each write(2), the file offset is positioned at the end
         * of the file, as if with lseek(2).
         */
        if (server_entrys[fd]->flags & O_APPEND) {
                offset = (off_t)server_entrys[fd]->vnode->size;
                server_entrys[fd]->offset = offset;
        }

        /** see fs_wrapper_read */
        size = size <= READ_SIZE_MAX ? size : READ_SIZE_MAX;

        /*
         * Server-side write operation should implement like:
         * - Base: write file and return bytes written
         * - If offset is outside the file (notice size=0 is handled)
         *      Filling '\0' until offset pos, then append file
         */

        ret = tmpfs_write(operator, offset, size, buf);

        /* Update server_entry and vnode metadata */
        server_entrys[fd]->offset += ret;
        if (server_entrys[fd]->offset > server_entrys[fd]->vnode->size) {
                server_entrys[fd]->vnode->size = server_entrys[fd]->offset;
        }

out:
        pthread_rwlock_unlock(&server_entrys[fd]->vnode->rwlock);
        pthread_mutex_unlock(&server_entrys[fd]->lock);
        return ret;
}

static void fix_stat_time(struct stat *statbuf)
{
        clock_gettime(CLOCK_REALTIME, &statbuf->st_atim);
        clock_gettime(CLOCK_REALTIME, &statbuf->st_ctim);
        clock_gettime(CLOCK_REALTIME, &statbuf->st_mtim);
}

int libtmpfs_fstat(int fd, struct stat *statbuf)
{
        int err;
        
        err = tmpfs_fstat(fd, statbuf);
        if (!err) {
                fix_stat_time(statbuf);
        }
        
        return err;
}

int libtmpfs_fstatat(int dirfd, const char *pathname, struct stat *statbuf,
                     int flags)
{
        BUG_ON(dirfd != AT_FDROOT);
        int err;

        if (strlen(pathname) == 0) {
                return -ENOENT;
        }

        err = tmpfs_fstatat(pathname, statbuf, flags);
        if (err)
                return err;

        struct fs_vnode *vnode;
        vnode = get_fs_vnode_by_id(statbuf->st_ino);
        if (vnode && (statbuf->st_mode & S_IFREG)) {
                /* vnode is cached in memory, update size in stat */
                statbuf->st_size = vnode->size;
        }

        fix_stat_time(statbuf);

        return 0;
}

off_t libtmpfs_lseek(int fd, off_t offset, int whence)
{
        off_t target_off;

        switch (whence) {
        case SEEK_SET: {
                target_off = offset;
                break;
        }
        case SEEK_CUR: {
                target_off = server_entrys[fd]->offset + offset;
                break;
        }
        case SEEK_END:
                target_off = server_entrys[fd]->vnode->size + offset;
                break;
        default: {
                printf("%s: %d Not impelemented yet\n", __func__, whence);
                target_off = -1;
                break;
        }
        }
        if (target_off < 0)
                return -EINVAL;

        server_entrys[fd]->offset = target_off;

        return target_off;
}

int libtmpfs_getdents64(unsigned int fd, void *dirp,
                        unsigned int count)
{
        return tmpfs_getdents(fd, count, dirp);
}

ssize_t libtmpfs_readv(int fd, const struct iovec *iov, int iovcnt)
{
        int i;
        ssize_t n, s;

        s = 0;
        for (i = 0; i < iovcnt; i++) {
                n = libtmpfs_read(fd, iov[i].iov_base, iov[i].iov_len);
                BUG_ON(n < 0);

                s += n;
                if (n != iov[i].iov_len) {
                        goto out;
                }
        }

out:
        return s;
}

ssize_t libtmpfs_writev(int fd, const struct iovec *iov, int iovcnt)
{
        int i;
        ssize_t n, s;

        s = 0;
        for (i = 0; i < iovcnt; i++) {
                n = libtmpfs_write(fd, iov[i].iov_base, iov[i].iov_len);
                BUG_ON(n < 0);

                s += n;
                if (n != iov[i].iov_len) {
                        goto out;
                }
        }

out:
        return s;
}

/* init tmpfs root, creating . and .. inside */
static void init_root(void)
{
        int err;
        tmpfs_root_dent = malloc(sizeof(struct dentry));
        assert(tmpfs_root_dent);

        tmpfs_root = tmpfs_inode_init(FS_DIR, 0);
        assert(tmpfs_root);
        tmpfs_root_dent->inode = tmpfs_root;

        struct dentry *d_root_dot = tmpfs_root->d_ops->alloc_dentry();
        assert(!CHCORE_IS_ERR(d_root_dot));
        err = tmpfs_root->d_ops->add_dentry(tmpfs_root, d_root_dot, ".", 1);
        assert(!err);

        struct dentry *d_root_dotdot = tmpfs_root->d_ops->alloc_dentry();
        assert(!CHCORE_IS_ERR(d_root_dotdot));
        err = tmpfs_root->d_ops->add_dentry(tmpfs_root, d_root_dotdot, "..", 2);
        assert(!err);

        tmpfs_root->d_ops->link(tmpfs_root, d_root_dot, tmpfs_root);
        tmpfs_root->d_ops->link(tmpfs_root, d_root_dotdot, tmpfs_root);
}

static void init_fs_wrapper(void)
{
        /* fs wrapper */
        fs_vnode_init();
        pthread_rwlock_init(&fs_wrapper_meta_rwlock, NULL);
}

void libtmpfs_init(void)
{
        init_root();
        init_fs_wrapper();
}
