#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "gitward.h"

ClueList *cluelist_new(void)
{
    ClueList *cl = calloc(1, sizeof(ClueList));
    if (!cl) return NULL;
    cl->cap   = 256;
    cl->items = calloc(cl->cap, sizeof(Clue));
    if (!cl->items) { free(cl); return NULL; }
    return cl;
}

void cluelist_free(ClueList *cl)
{
    if (!cl) return;
    free(cl->items);
    free(cl);
}

int cluelist_add(ClueList *cl, Clue *c)
{
    if (cl->count >= cl->cap) {
        size_t newcap = cl->cap * 2;
        Clue *tmp = realloc(cl->items, newcap * sizeof(Clue));
        if (!tmp) return -1;
        cl->items = tmp;
        cl->cap   = newcap;
    }
    cl->items[cl->count++] = *c;
    return 0;
}

int cluelist_has(ClueList *cl, ClueType type, const char *value)
{
    for (size_t i = 0; i < cl->count; i++) {
        if (cl->items[i].type == type &&
            strcmp(cl->items[i].value, value) == 0)
            return 1;
    }
    return 0;
}

const char *clue_type_str(ClueType t)
{
    switch (t) {
    case CLUE_EMAIL:      return "email";
    case CLUE_URL:        return "url";
    case CLUE_DOMAIN:     return "domain";
    case CLUE_AUTHOR:     return "author";
    case CLUE_COMMIT:     return "commit";
    case CLUE_FILEPATH:   return "filepath";
    case CLUE_REFNAME:    return "refname";
    case CLUE_TIMESTAMP:  return "timestamp";
    case CLUE_SECRET:     return "secret";
    case CLUE_SUSPICIOUS: return "suspicious";
    case CLUE_TAG:        return "tag";
    case CLUE_STASH:      return "stash";
    case CLUE_USERNAME:   return "username";
    case CLUE_RELATION:   return "relation";
    case CLUE_IP:         return "ip";
    default:              return "unknown";
    }
}

void clue_now_utc(char *buf, size_t n)
{
    time_t t = time(NULL);
    struct tm *tm = gmtime(&t);
    strftime(buf, n, "%Y-%m-%dT%H:%M:%SZ", tm);
}
