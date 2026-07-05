#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gitward.h"

static void usage(void)
{
    puts("usage: gitward <command> [args]");
    puts("");
    puts("commands:");
    puts("  scan    [path]              scan a local git repository (default: .)");
    puts("  inspect [path]              inspect and summarize findings (default: .)");
    puts("  search  <path> <query>      search clues in repo");
    puts("  save    <path> [outfile]    save results to file");
    puts("  version                     print version");
    puts("  help                        print this help");
    puts("");
    puts("aliases: s=scan  i=inspect  f=search  o=save");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage();
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "version") == 0) {
        printf("gitward %s\n", GITWARD_VERSION);
        return 0;
    }

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0 ||
        strcmp(cmd, "--help") == 0) {
        usage();
        return 0;
    }

    if (strcmp(cmd, "scan") == 0 || strcmp(cmd, "s") == 0) {
        const char *path = (argc >= 3) ? argv[2] : ".";
        ClueList *cl = cluelist_new();
        if (!cl) { fprintf(stderr, "error: out of memory\n"); return 1; }
        int ret = 0;
        if (scan_repo(path, cl) != 0) { ret = 1; goto done_scan; }
        inspect_repo(path, cl);
done_scan:
        cluelist_free(cl);
        return ret;
    }

    if (strcmp(cmd, "inspect") == 0 || strcmp(cmd, "i") == 0) {
        const char *path = (argc >= 3) ? argv[2] : ".";
        ClueList *cl = cluelist_new();
        if (!cl) { fprintf(stderr, "error: out of memory\n"); return 1; }
        int ret = 0;
        if (scan_repo(path, cl) != 0) { ret = 1; goto done_inspect; }
        inspect_repo(path, cl);
done_inspect:
        cluelist_free(cl);
        return ret;
    }

    if (strcmp(cmd, "search") == 0 || strcmp(cmd, "f") == 0) {
        if (argc < 4) {
            fprintf(stderr, "error: search requires <path> and <query>\n");
            return 1;
        }
        const char *path  = argv[2];
        const char *query = argv[3];
        ClueList *cl = cluelist_new();
        if (!cl) { fprintf(stderr, "error: out of memory\n"); return 1; }
        int ret = 0;
        if (scan_repo(path, cl) != 0) { ret = 1; goto done_search; }
        search_clues(cl, query);
done_search:
        cluelist_free(cl);
        return ret;
    }

    if (strcmp(cmd, "save") == 0 || strcmp(cmd, "o") == 0) {
        if (argc < 3) {
            fprintf(stderr, "error: save requires <path>\n");
            return 1;
        }
        const char *path    = argv[2];
        const char *outfile = (argc >= 4) ? argv[3] : "gitward.out";
        ClueList *cl = cluelist_new();
        if (!cl) { fprintf(stderr, "error: out of memory\n"); return 1; }
        int ret = 0;
        if (scan_repo(path, cl) != 0) { ret = 1; goto done_save; }
        if (save_clues(cl, outfile) != 0) { ret = 1; goto done_save; }
        printf("saved: %s\n", outfile);
done_save:
        cluelist_free(cl);
        return ret;
    }

    fprintf(stderr, "error: unknown command: %s\n", cmd);
    usage();
    return 1;
}
