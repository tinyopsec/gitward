#ifndef GITWARD_H
#define GITWARD_H

#include <stddef.h>
#include <time.h>

#define GITWARD_VERSION "0.3"
#define CLUE_VALUE_MAX  4096
#define CLUE_FIELD_MAX  512

typedef enum {
    CLUE_EMAIL,
    CLUE_URL,
    CLUE_DOMAIN,
    CLUE_AUTHOR,
    CLUE_COMMIT,
    CLUE_FILEPATH,
    CLUE_REFNAME,
    CLUE_TIMESTAMP,
    CLUE_SECRET,
    CLUE_SUSPICIOUS,
    CLUE_TAG,
    CLUE_STASH,
    CLUE_USERNAME,
    CLUE_RELATION,
    CLUE_IP,
    CLUE_UNKNOWN
} ClueType;

typedef struct {
    ClueType type;
    char value[CLUE_VALUE_MAX];
    char commit[64];
    char author[CLUE_FIELD_MAX];
    char path[CLUE_FIELD_MAX];
    char utc[64];
    char extra[CLUE_VALUE_MAX];
} Clue;

typedef struct {
    Clue  *items;
    size_t count;
    size_t cap;
    char   repo_path[CLUE_FIELD_MAX];
    char   scanned_utc[64];
} ClueList;

ClueList   *cluelist_new(void);
void        cluelist_free(ClueList *cl);
int         cluelist_add(ClueList *cl, Clue *c);
int         cluelist_has(ClueList *cl, ClueType type, const char *value);

int  scan_repo(const char *path, ClueList *cl);
void inspect_repo(const char *path, ClueList *cl);
void search_clues(ClueList *cl, const char *query);
int  save_clues(ClueList *cl, const char *outpath);

const char *clue_type_str(ClueType t);
void        clue_now_utc(char *buf, size_t n);

#endif
