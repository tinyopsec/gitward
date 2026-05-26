#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>

#include "gitward.h"

#define POPEN_CMD_MAX 8192
#define LINE_BUF      8192
#define HOOK_RISK_MAX 200

#define COLOR_BOLD   "\033[1m"
#define COLOR_GREEN  "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_RED    "\033[31m"
#define COLOR_RESET  "\033[0m"

static int g_color   = 0;
static int g_verbose = 0;
static int g_debug   = 0;

typedef struct HMapEntry {
    char key[CLUE_VALUE_MAX];
    char val[CLUE_VALUE_MAX];
    struct HMapEntry *next;
} HMapEntry;

#define HMAP_BUCKETS 1024
typedef struct {
    HMapEntry *buckets[HMAP_BUCKETS];
    size_t     count;
} HMap;

static unsigned int hmap_hash(const char *s)
{
    unsigned int h = 5381u;
    while (*s) h = ((h << 5) + h) ^ (unsigned char)*s++;
    return h % HMAP_BUCKETS;
}

static HMap *hmap_new(void)
{
    return calloc(1, sizeof(HMap));
}

static void hmap_free(HMap *m)
{
    if (!m) return;
    for (int i = 0; i < HMAP_BUCKETS; i++) {
        HMapEntry *e = m->buckets[i];
        while (e) { HMapEntry *nx = e->next; free(e); e = nx; }
    }
    free(m);
}

static int hmap_set(HMap *m, const char *key, const char *val)
{
    if (!m || !key || m->count >= 10000) return 0;
    unsigned int idx = hmap_hash(key);
    HMapEntry *e = m->buckets[idx];
    while (e) {
        if (strncmp(e->key, key, CLUE_VALUE_MAX - 1) == 0) {
            strncpy(e->val, val ? val : "", CLUE_VALUE_MAX - 1);
            return 1;
        }
        e = e->next;
    }
    HMapEntry *n = calloc(1, sizeof(HMapEntry));
    if (!n) return 0;
    strncpy(n->key, key, CLUE_VALUE_MAX - 1);
    strncpy(n->val, val ? val : "", CLUE_VALUE_MAX - 1);
    n->next = m->buckets[idx];
    m->buckets[idx] = n;
    m->count++;
    return 1;
}

static const char *hmap_get(HMap *m, const char *key)
{
    if (!m || !key) return NULL;
    unsigned int idx = hmap_hash(key);
    HMapEntry *e = m->buckets[idx];
    while (e) {
        if (strncmp(e->key, key, CLUE_VALUE_MAX - 1) == 0) return e->val;
        e = e->next;
    }
    return NULL;
}

static const char *SECRET_PATTERNS[] = {
    "AKIA[0-9A-Z]{16}",
    "ASIA[0-9A-Z]{16}",
    "ghp_[a-zA-Z0-9]{36}",
    "ghs_[a-zA-Z0-9]{36}",
    "github_pat_[a-zA-Z0-9_]{82}",
    "glpat-[a-zA-Z0-9_-]{20}",
    "xox[baprs]-[0-9a-zA-Z-]{10,}",
    "-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY",
    "[Pp]assword[[:space:]]*=[[:space:]]*['\"][^'\"]{6,}['\"]",
    "[Ss]ecret[[:space:]]*=[[:space:]]*['\"][^'\"]{6,}['\"]",
    "[Aa][Pp][Ii][_-]?[Kk]ey[[:space:]]*=[[:space:]]*['\"][^'\"]{8,}['\"]",
    "[Tt]oken[[:space:]]*=[[:space:]]*['\"][^'\"]{8,}['\"]",
    "AIza[0-9A-Za-z_-]{35}",
    "ya29\\.[0-9A-Za-z_-]{68,}",
    "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
    "mongodb(\\+srv)?://[^[:space:]\"]{12,}",
    "sk_live_[0-9a-zA-Z]{24,}",
    "rk_live_[0-9a-zA-Z]{24,}",
    "SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}",
    "AC[a-z0-9]{32}",
    "SK[a-z0-9]{32}",
    "sq0atp-[0-9A-Za-z_-]{22}",
    "sq0csp-[0-9A-Za-z_-]{43}",
    "[0-9a-fA-F]{64}",
    "private_key.*['\"]-----BEGIN",
    "169\\.254\\.169\\.254",
    "DOCKER_PASSWORD[[:space:]]*=",
    "HEROKU_API_KEY[[:space:]]*=",
    "[Dd][Bb][_-]?[Pp]ass(word)?[[:space:]]*=[[:space:]]*[^[:space:]\"]{4,}",
    "[Nn][Pp][Mm][_-]?[Tt]oken[[:space:]]*=[[:space:]]*[^[:space:]\"]{10,}",
    NULL
};

static const char *SUSPICIOUS_PATTERNS[] = {
    "curl.*|.*sh",
    "wget.*|.*sh",
    "base64 -d",
    "base64 --decode",
    "eval.*base64",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/cron",
    "chmod 777",
    "chmod 666",
    "rm -rf /",
    ".onion",
    "runOn.*folderOpen",
    "allowAutomaticTasks",
    NULL
};

static const char *HOOK_RISK_PATTERNS[] = {
    "curl ",
    "wget ",
    "base64",
    "/dev/tcp",
    "nc ",
    "netcat",
    "bash -i",
    "python -c",
    "perl -e",
    "ruby -e",
    "ncat ",
    "socat ",
    NULL
};

static const char *SENSITIVE_FILENAMES[] = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".bash_history",
    ".zsh_history",
    ".psql_history",
    ".mysql_history",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "credentials",
    "secrets.yml",
    "secrets.yaml",
    NULL
};

static void strip_nl(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r')) s[--n] = '\0';
}

static int is_git_repo(const char *path)
{
    char buf[CLUE_FIELD_MAX + 8];
    struct stat st;
    snprintf(buf, sizeof(buf), "%s/.git", path);
    return stat(buf, &st) == 0 && S_ISDIR(st.st_mode);
}

static void add_clue(ClueList *cl, ClueType type, const char *value,
                     const char *commit, const char *author,
                     const char *path, const char *extra, const char *utc)
{
    if (!value || value[0] == '\0') return;
    if (cluelist_has(cl, type, value)) return;
    Clue c;
    memset(&c, 0, sizeof(c));
    c.type = type;
    strncpy(c.value,  value,  CLUE_VALUE_MAX  - 1);
    strncpy(c.commit, commit ? commit : "", 63);
    strncpy(c.author, author ? author : "", CLUE_FIELD_MAX - 1);
    strncpy(c.path,   path   ? path   : "", CLUE_FIELD_MAX - 1);
    strncpy(c.extra,  extra  ? extra  : "", CLUE_VALUE_MAX  - 1);
    if (utc && utc[0]) strncpy(c.utc, utc, sizeof(c.utc) - 1);
    cluelist_add(cl, &c);
}

static FILE *git_cmd(const char *repo, const char *args)
{
    char cmd[POPEN_CMD_MAX];
    const char *redir = g_debug ? "" : " 2>/dev/null";
    snprintf(cmd, sizeof(cmd), "git -C %s %s%s", repo, args, redir);
    return popen(cmd, "r");
}

static void extract_username_from_email(const char *email, char *out, size_t n)
{
    const char *at = strchr(email, '@');
    size_t len = at ? (size_t)(at - email) : strlen(email);
    if (len >= n) len = n - 1;
    strncpy(out, email, len);
    out[len] = '\0';
}

static void extract_domain(const char *url, char *out, size_t n)
{
    const char *p = strstr(url, "://");
    if (!p) { snprintf(out, n, "%s", url); return; }
    p += 3;
    const char *end = strpbrk(p, "/:?#");
    size_t len = end ? (size_t)(end - p) : strlen(p);
    if (len >= n) len = n - 1;
    strncpy(out, p, len);
    out[len] = '\0';
}

static int looks_like_url(const char *s)
{
    return strncmp(s, "http://", 7) == 0 || strncmp(s, "https://", 8) == 0 ||
           strncmp(s, "git://", 6) == 0  || strncmp(s, "ssh://", 6) == 0;
}

static void parse_grep_line(char *line, char *fpath, size_t fpsz,
                             char *lnum, size_t lnsz, char **content)
{
    char *c1 = strchr(line, ':');
    char *c2 = c1 ? strchr(c1 + 1, ':') : NULL;
    *content = line;
    if (c1 && c2) {
        size_t fl = (size_t)(c1 - line); if (fl >= fpsz) fl = fpsz - 1;
        memcpy(fpath, line, fl); fpath[fl] = '\0';
        size_t nl = (size_t)(c2 - c1 - 1); if (nl >= lnsz) nl = lnsz - 1;
        memcpy(lnum, c1 + 1, nl); lnum[nl] = '\0';
        *content = c2 + 1;
        while (**content == ' ') (*content)++;
    }
}

static FILE *grep_pattern(const char *repo, const char *pat, int extended, int max)
{
    char tmp[] = "/tmp/gw_pat_XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) return NULL;
    FILE *tf = fdopen(fd, "w");
    if (!tf) { close(fd); unlink(tmp); return NULL; }
    fprintf(tf, "%s\n", pat);
    fclose(tf);
    char cmd[POPEN_CMD_MAX];
    snprintf(cmd, sizeof(cmd),
        "git -C %s grep -nI %s -f %s 2>/dev/null | head -%d",
        repo, extended ? "-E" : "-F", tmp, max);
    FILE *fp = popen(cmd, "r");
    unlink(tmp);
    return fp;
}

static void collect_commits(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "log --all --pretty=format:'%H%x09%ae%x09%an%x09%ai%x09%ce%x09%s'");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        char *hash  = strtok(line, "\t");
        char *aemail= strtok(NULL, "\t");
        char *aname = strtok(NULL, "\t");
        char *ts    = strtok(NULL, "\t");
        char *cemail= strtok(NULL, "\t");
        char *subj  = strtok(NULL, "\t");
        if (!hash) continue;
        add_clue(cl, CLUE_COMMIT,    hash,  hash, aname, NULL, subj, ts);
        if (aname)  add_clue(cl, CLUE_AUTHOR,    aname,  hash, aname, NULL, NULL, ts);
        if (ts)     add_clue(cl, CLUE_TIMESTAMP, ts,     hash, aname, NULL, NULL, ts);
        if (aemail) {
            add_clue(cl, CLUE_EMAIL, aemail, hash, aname, NULL, "author", ts);
            char u[CLUE_FIELD_MAX];
            extract_username_from_email(aemail, u, sizeof(u));
            if (u[0]) add_clue(cl, CLUE_USERNAME, u, hash, aname, NULL, "from-author-email", ts);
        }
        if (cemail && aemail && strcmp(cemail, aemail) != 0) {
            add_clue(cl, CLUE_EMAIL, cemail, hash, aname, NULL, "committer", ts);
            char u[CLUE_FIELD_MAX];
            extract_username_from_email(cemail, u, sizeof(u));
            if (u[0]) add_clue(cl, CLUE_USERNAME, u, hash, aname, NULL, "from-committer-email", ts);
        }
    }
    pclose(fp);
}

static void collect_committer_names(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "log --all --pretty=format:'%H%x09%cn%x09%ce%x09%ai'");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        char *hash  = strtok(line, "\t");
        char *cname = strtok(NULL, "\t");
        char *ceml  = strtok(NULL, "\t");
        char *ts    = strtok(NULL, "\t");
        if (!hash || !cname) continue;
        add_clue(cl, CLUE_AUTHOR, cname, hash, cname, NULL, "committer-name", ts);
        if (ceml) add_clue(cl, CLUE_EMAIL, ceml, hash, cname, NULL, "committer", ts);
    }
    pclose(fp);
}

static void collect_refs(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "for-each-ref --format='%(refname:short)%x09%(objectname:short)%x09%(creatordate:iso)'");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        char *ref  = strtok(line, "\t");
        char *sha  = strtok(NULL, "\t");
        char *date = strtok(NULL, "\t");
        if (!ref) continue;
        add_clue(cl, CLUE_REFNAME, ref, sha, NULL, NULL, date, date);
    }
    pclose(fp);
}

static void collect_tags(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo, "tag -l");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        if (line[0]) add_clue(cl, CLUE_TAG, line, NULL, NULL, NULL, NULL, NULL);
    }
    pclose(fp);
}

static void collect_stashes(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo, "stash list");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        if (line[0]) add_clue(cl, CLUE_STASH, line, NULL, NULL, NULL, NULL, NULL);
    }
    pclose(fp);
}

static void collect_reflog(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "reflog --all --pretty=format:'%H%x09%gd%x09%gs%x09%ai'");
    if (!fp) return;
    char line[LINE_BUF];
    int seen = 0;
    while (fgets(line, sizeof(line), fp) && seen < 500) {
        strip_nl(line);
        char *sha  = strtok(line, "\t");
        char *ref  = strtok(NULL, "\t");
        char *msg  = strtok(NULL, "\t");
        char *date = strtok(NULL, "\t");
        if (!sha) continue;
        char val[CLUE_VALUE_MAX];
        snprintf(val, sizeof(val), "%s %s", ref ? ref : "", sha);
        add_clue(cl, CLUE_REFNAME, val, sha, NULL, NULL, msg, date);
        seen++;
    }
    pclose(fp);
}

static void collect_notes(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo, "notes list");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        if (line[0]) add_clue(cl, CLUE_REFNAME, line, NULL, NULL, NULL, "note", NULL);
    }
    pclose(fp);
}

static void collect_files(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo, "ls-files");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        if (!line[0]) continue;
        add_clue(cl, CLUE_FILEPATH, line, NULL, NULL, line, NULL, NULL);
        const char *bn = strrchr(line, '/');
        const char *name = bn ? bn + 1 : line;
        for (int i = 0; SENSITIVE_FILENAMES[i]; i++) {
            if (strcmp(name, SENSITIVE_FILENAMES[i]) == 0) {
                char val[CLUE_VALUE_MAX];
                snprintf(val, sizeof(val), "sensitive-file:%s", line);
                add_clue(cl, CLUE_SUSPICIOUS, val, NULL, NULL, line, "sensitive-filename", NULL);
                break;
            }
        }
    }
    pclose(fp);
}

static void collect_remotes(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo, "remote -v");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        char *name = strtok(line, "\t ");
        char *url  = strtok(NULL, "\t ");
        if (url) {
            add_clue(cl, CLUE_URL, url, NULL, NULL, NULL, name, NULL);
            char dom[CLUE_VALUE_MAX];
            extract_domain(url, dom, sizeof(dom));
            if (dom[0]) add_clue(cl, CLUE_DOMAIN, dom, NULL, NULL, NULL, "remote", NULL);
        }
    }
    pclose(fp);
}

static void collect_git_config(const char *repo, ClueList *cl)
{
    char cfgpath[CLUE_FIELD_MAX + 32];
    snprintf(cfgpath, sizeof(cfgpath), "%s/.git/config", repo);
    FILE *fp = fopen(cfgpath, "r");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "url", 3) == 0 || strncmp(p, "email", 5) == 0 ||
            strncmp(p, "name", 4) == 0 || strncmp(p, "proxy", 5) == 0) {
            char *eq = strchr(p, '=');
            if (eq) {
                eq++; while (*eq == ' ') eq++;
                if (strncmp(p, "url", 3) == 0)
                    add_clue(cl, CLUE_URL, eq, NULL, NULL, ".git/config", NULL, NULL);
                else if (strncmp(p, "email", 5) == 0) {
                    add_clue(cl, CLUE_EMAIL, eq, NULL, NULL, ".git/config", "config", NULL);
                    char u[CLUE_FIELD_MAX];
                    extract_username_from_email(eq, u, sizeof(u));
                    if (u[0]) add_clue(cl, CLUE_USERNAME, u, NULL, NULL, ".git/config", "from-config-email", NULL);
                } else if (strncmp(p, "proxy", 5) == 0) {
                    add_clue(cl, CLUE_URL, eq, NULL, NULL, ".git/config", "proxy", NULL);
                } else {
                    add_clue(cl, CLUE_USERNAME, eq, NULL, NULL, ".git/config", "from-config-name", NULL);
                }
            }
        }
    }
    fclose(fp);
}

static void collect_urls_from_log(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "log --all --pretty=format: -p | grep -oE 'https?://[^[:space:]\"<>]+' | head -2000");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        if (!looks_like_url(line)) continue;
        add_clue(cl, CLUE_URL, line, NULL, NULL, NULL, "from-log", NULL);
        char dom[CLUE_VALUE_MAX];
        extract_domain(line, dom, sizeof(dom));
        if (dom[0]) add_clue(cl, CLUE_DOMAIN, dom, NULL, NULL, NULL, NULL, NULL);
    }
    pclose(fp);
}

static void collect_ips(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "log --all -p | grep -oE '\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b' | sort -u | head -500");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        if (line[0]) add_clue(cl, CLUE_IP, line, NULL, NULL, NULL, NULL, NULL);
    }
    pclose(fp);
}

static void collect_ipv6(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "log --all -p | grep -oE '([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}' | sort -u | head -200");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        if (line[0]) {
            char val[CLUE_VALUE_MAX];
            snprintf(val, sizeof(val), "ipv6:%s", line);
            add_clue(cl, CLUE_IP, val, NULL, NULL, NULL, "ipv6", NULL);
        }
    }
    pclose(fp);
}

static void collect_internal_domains(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "log --all -p | grep -oE '[a-zA-Z0-9._-]+\\.(corp|internal|local|lan|intranet|int)[^[:space:]]*' | sort -u | head -200");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        if (line[0]) add_clue(cl, CLUE_DOMAIN, line, NULL, NULL, NULL, "internal", NULL);
    }
    pclose(fp);
}

static void collect_submodules(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo, "submodule status");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        char *p = line;
        while (*p == ' ' || *p == '+' || *p == '-' || *p == 'U') p++;
        char *sha  = strtok(p, " ");
        char *path = strtok(NULL, " ");
        if (sha && path) {
            char val[CLUE_VALUE_MAX];
            snprintf(val, sizeof(val), "submodule:%s", path);
            add_clue(cl, CLUE_RELATION, val, sha, NULL, path, NULL, NULL);
        }
    }
    pclose(fp);
}

static void collect_gpg_signatures(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo, "log --all --pretty=format:'%H%x09%G?%x09%GS%x09%GK'");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        char *hash = strtok(line, "\t");
        char *sig  = strtok(NULL, "\t");
        char *signer = strtok(NULL, "\t");
        char *key    = strtok(NULL, "\t");
        if (!hash || !sig || sig[0] == 'N' || sig[0] == '\0') continue;
        char val[CLUE_VALUE_MAX];
        snprintf(val, sizeof(val), "gpg-signed:%s", hash);
        char ex[CLUE_VALUE_MAX];
        snprintf(ex, sizeof(ex), "sig=%s signer=%s key=%s",
                 sig, signer ? signer : "", key ? key : "");
        add_clue(cl, CLUE_RELATION, val, hash, NULL, NULL, ex, NULL);
        if (key && key[0]) add_clue(cl, CLUE_USERNAME, key, hash, NULL, NULL, "gpg-key", NULL);
    }
    pclose(fp);
}

static int score_hook_content(const char *hookpath)
{
    FILE *fp = fopen(hookpath, "r");
    if (!fp) return 0;
    int score = 0;
    int lines = 0;
    int comments = 0;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        lines++;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#') comments++;
        for (int i = 0; HOOK_RISK_PATTERNS[i]; i++) {
            if (strstr(line, HOOK_RISK_PATTERNS[i])) {
                score += 15;
                break;
            }
        }
        if (strstr(line, "base64") && strstr(line, "-d"))  score += 25;
        if (strstr(line, "exec "))  score += 10;
        if (strstr(line, "|sh"))    score += 20;
        if (strstr(line, "|bash"))  score += 20;
        if (strstr(line, "chmod"))  score += 5;
    }
    fclose(fp);
    if (lines > 0 && comments * 100 / lines > 60) score += 15;
    if (score > HOOK_RISK_MAX) score = HOOK_RISK_MAX;
    return score;
}

static void scan_hook_dir(const char *repo, const char *rel, ClueList *cl)
{
    char hookdir[CLUE_FIELD_MAX + 64];
    snprintf(hookdir, sizeof(hookdir), "%s/%s", repo, rel);
    DIR *d = opendir(hookdir);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        const char *name = ent->d_name;
        size_t len = strlen(name);
        if (len > 7 && strcmp(name + len - 7, ".sample") == 0) continue;
        if (name[0] == '.') continue;
        char fullpath[CLUE_FIELD_MAX + 128];
        snprintf(fullpath, sizeof(fullpath), "%s/%s/%s", repo, rel, name);
        struct stat st;
        if (stat(fullpath, &st) != 0) continue;
        if (!S_ISREG(st.st_mode)) continue;
        int score = score_hook_content(fullpath);
        char val[CLUE_VALUE_MAX];
        snprintf(val, sizeof(val), "hook:%s/%s score=%d", rel, name, score);
        char ex[CLUE_VALUE_MAX];
        snprintf(ex, sizeof(ex), "risk-score=%d", score);
        add_clue(cl, score >= 30 ? CLUE_SECRET : CLUE_SUSPICIOUS,
                 val, NULL, NULL, fullpath, ex, NULL);
    }
    closedir(d);
}

static void collect_hooks(const char *repo, ClueList *cl)
{
    scan_hook_dir(repo, ".git/hooks",  cl);
    scan_hook_dir(repo, ".githooks",   cl);
    scan_hook_dir(repo, ".husky",      cl);
}

static void collect_vscode(const char *repo, ClueList *cl)
{
    const char *vscode_files[] = {
        ".vscode/tasks.json",
        ".vscode/settings.json",
        NULL
    };
    for (int i = 0; vscode_files[i]; i++) {
        char fullpath[CLUE_FIELD_MAX + 64];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", repo, vscode_files[i]);
        FILE *fp = fopen(fullpath, "r");
        if (!fp) continue;
        char line[LINE_BUF];
        int lineno = 0;
        while (fgets(line, sizeof(line), fp)) {
            lineno++;
            if (strstr(line, "runOn") || strstr(line, "folderOpen") ||
                strstr(line, "allowAutomaticTasks")) {
                char val[CLUE_VALUE_MAX];
                line[200] = '\0';
                snprintf(val, sizeof(val), "%s:%d: %.200s", vscode_files[i], lineno, line);
                strip_nl(val);
                add_clue(cl, CLUE_SUSPICIOUS, val, NULL, NULL, fullpath, "vscode-autorun", NULL);
            }
        }
        fclose(fp);
    }
}

static void collect_force_push_indicators(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "log --walk-reflogs --pretty=format:'%gd%x09%gs%x09%H' 2>/dev/null | grep -i 'force\\|reset\\|rebase' | head -100");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        char *ref  = strtok(line, "\t");
        char *msg  = strtok(NULL, "\t");
        char *hash = strtok(NULL, "\t");
        if (!ref) continue;
        char val[CLUE_VALUE_MAX];
        snprintf(val, sizeof(val), "force-push-indicator:%s %s", ref, msg ? msg : "");
        add_clue(cl, CLUE_SUSPICIOUS, val, hash, NULL, NULL, "force-push", NULL);
    }
    pclose(fp);
}

static void collect_dangling_commits(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "fsck --unreachable --no-reflogs 2>/dev/null | grep '^unreachable commit' | head -100");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        char *tok = strrchr(line, ' ');
        if (!tok) continue;
        tok++;
        char val[CLUE_VALUE_MAX];
        snprintf(val, sizeof(val), "dangling-commit:%s", tok);
        add_clue(cl, CLUE_SUSPICIOUS, val, tok, NULL, NULL, "unreachable", NULL);
    }
    pclose(fp);
}

static void collect_dangling_blobs(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "fsck --unreachable --no-reflogs 2>/dev/null | grep '^unreachable blob' | awk '{print $3}' | head -50");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        if (!line[0]) continue;
        char cmd[POPEN_CMD_MAX];
        snprintf(cmd, sizeof(cmd),
            "git -C %s cat-file -p %s 2>/dev/null | grep -oE '['\''\"](AKIA|ghp_|glpat-|sk_live_)[A-Za-z0-9_-]{10,}['\''\"']' | head -5",
            repo, line);
        FILE *fp2 = popen(cmd, "r");
        if (!fp2) continue;
        char hit[LINE_BUF];
        while (fgets(hit, sizeof(hit), fp2)) {
            strip_nl(hit);
            if (!hit[0]) continue;
            char val[CLUE_VALUE_MAX];
            snprintf(val, sizeof(val), "dangling-blob-secret:%s", hit);
            add_clue(cl, CLUE_SECRET, val, line, NULL, NULL, "unreachable-blob", NULL);
        }
        pclose(fp2);
    }
    pclose(fp);
}

static void collect_ci_configs(const char *repo, ClueList *cl)
{
    const char *ci_files[] = {
        ".github/workflows",
        ".gitlab-ci.yml",
        ".travis.yml",
        "Jenkinsfile",
        NULL
    };
    char fullpath[CLUE_FIELD_MAX + 64];
    struct stat st;
    for (int i = 0; ci_files[i]; i++) {
        snprintf(fullpath, sizeof(fullpath), "%s/%s", repo, ci_files[i]);
        if (stat(fullpath, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            DIR *d = opendir(fullpath);
            if (!d) continue;
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                char fp2[CLUE_FIELD_MAX + 128];
                snprintf(fp2, sizeof(fp2), "%s/%s/%s", repo, ci_files[i], ent->d_name);
                add_clue(cl, CLUE_FILEPATH, fp2, NULL, NULL, fp2, "ci-workflow", NULL);
            }
            closedir(d);
        } else {
            add_clue(cl, CLUE_FILEPATH, fullpath, NULL, NULL, fullpath, "ci-config", NULL);
        }
    }
}

static void collect_docker_info(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "log --all --pretty=format: -p -- '*Dockerfile*' | grep -E '^\\+FROM |^\\+EXPOSE ' | sort -u | head -100");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        if (!line[0]) continue;
        char *p = line;
        if (*p == '+') p++;
        add_clue(cl, CLUE_SUSPICIOUS, p, NULL, NULL, "Dockerfile", "docker-directive", NULL);
    }
    pclose(fp);
}

static void collect_signed_off_by(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "log --all --pretty=format:'%H%x09%B' | grep -i 'Signed-off-by:' | head -200");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        char *sob = strcasestr(line, "Signed-off-by:");
        if (!sob) continue;
        sob += 14;
        while (*sob == ' ') sob++;
        char *email_start = strchr(sob, '<');
        if (email_start) {
            char *email_end = strchr(email_start, '>');
            if (email_end) {
                size_t len = (size_t)(email_end - email_start - 1);
                char email[CLUE_FIELD_MAX];
                if (len >= sizeof(email)) len = sizeof(email) - 1;
                strncpy(email, email_start + 1, len);
                email[len] = '\0';
                add_clue(cl, CLUE_EMAIL, email, NULL, NULL, NULL, "signed-off-by", NULL);
                char u[CLUE_FIELD_MAX];
                extract_username_from_email(email, u, sizeof(u));
                if (u[0]) add_clue(cl, CLUE_USERNAME, u, NULL, NULL, NULL, "from-sob-email", NULL);
            }
        }
    }
    pclose(fp);
}

static void collect_timezone_anomalies(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "log --all --pretty=format:'%H%x09%ai%x09%an'");
    if (!fp) return;
    HMap *tzmap = hmap_new();
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        char *hash  = strtok(line, "\t");
        char *ts    = strtok(NULL, "\t");
        char *aname = strtok(NULL, "\t");
        if (!hash || !ts || !aname) continue;
        const char *tz = strrchr(ts, ' ');
        if (!tz) continue;
        tz++;
        if (!hmap_get(tzmap, aname)) {
            hmap_set(tzmap, aname, tz);
        } else {
            const char *prev = hmap_get(tzmap, aname);
            if (prev && strcmp(prev, tz) != 0) {
                char val[CLUE_VALUE_MAX];
                snprintf(val, sizeof(val),
                    "tz-shift:%s prev=%s new=%s commit=%s", aname, prev, tz, hash);
                add_clue(cl, CLUE_SUSPICIOUS, val, hash, aname, NULL, "timezone-shift", ts);
                hmap_set(tzmap, aname, tz);
            }
        }
    }
    hmap_free(tzmap);
    pclose(fp);
}

static void collect_commit_hour_anomalies(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "log --all --pretty=format:'%H%x09%ai%x09%an'");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        char *hash  = strtok(line, "\t");
        char *ts    = strtok(NULL, "\t");
        char *aname = strtok(NULL, "\t");
        if (!hash || !ts || !aname) continue;
        int hour = -1;
        const char *T = strchr(ts, 'T');
        if (!T) {
            const char *sp = strchr(ts, ' ');
            if (sp) sscanf(sp + 1, "%d:", &hour);
        } else {
            sscanf(T + 1, "%d:", &hour);
        }
        if (hour < 0) continue;
        if (hour >= 0 && hour < 6) {
            char val[CLUE_VALUE_MAX];
            snprintf(val, sizeof(val),
                "odd-hour-commit:%s at=%02d:xx author=%s", hash, hour, aname);
            add_clue(cl, CLUE_SUSPICIOUS, val, hash, aname, NULL, "midnight-commit", ts);
        }
    }
    pclose(fp);
}

static void collect_churn(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "log --all --numstat --pretty=format:'%H%x09%an' | head -5000");
    if (!fp) return;
    HMap *add_map = hmap_new();
    HMap *del_map = hmap_new();
    char cur_author[CLUE_FIELD_MAX] = {0};
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        if (!line[0]) continue;
        char *first = strtok(line, "\t");
        char *second = strtok(NULL, "\t");
        if (!second) {
            snprintf(cur_author, sizeof(cur_author), "%s", first ? first : "unknown");
            continue;
        }
        if (!cur_author[0]) continue;
        int adds = 0, dels = 0;
        if (first && strcmp(first, "-") != 0) adds = atoi(first);
        if (second && strcmp(second, "-") != 0) dels = atoi(second);
        const char *pa = hmap_get(add_map, cur_author);
        const char *pd = hmap_get(del_map, cur_author);
        int ta = pa ? atoi(pa) : 0;
        int td = pd ? atoi(pd) : 0;
        ta += adds; td += dels;
        char ab[32], db[32];
        snprintf(ab, sizeof(ab), "%d", ta);
        snprintf(db, sizeof(db), "%d", td);
        hmap_set(add_map, cur_author, ab);
        hmap_set(del_map, cur_author, db);
    }
    for (int i = 0; i < HMAP_BUCKETS; i++) {
        HMapEntry *e = add_map->buckets[i];
        while (e) {
            const char *da = hmap_get(del_map, e->key);
            int adds = atoi(e->val);
            int dels = da ? atoi(da) : 0;
            if (adds + dels > 0) {
                int del_pct = (dels * 100) / (adds + dels + 1);
                if (del_pct > 70) {
                    char val[CLUE_VALUE_MAX];
                    snprintf(val, sizeof(val),
                        "high-churn-deletion:%.200s adds=%d dels=%d pct=%d%%",
                        e->key, adds, dels, del_pct);
                    add_clue(cl, CLUE_SUSPICIOUS, val, NULL, e->key, NULL, "churn", NULL);
                }
            }
            e = e->next;
        }
    }
    hmap_free(add_map);
    hmap_free(del_map);
    pclose(fp);
}

static void collect_deleted_readded_files(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "log --all --diff-filter=D --name-only --pretty=format: | grep -v '^$' | sort | uniq -d | head -50");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        if (!line[0]) continue;
        char val[CLUE_VALUE_MAX];
        snprintf(val, sizeof(val), "deleted-readded:%s", line);
        add_clue(cl, CLUE_SUSPICIOUS, val, NULL, NULL, line, "delete-readd", NULL);
    }
    pclose(fp);
}

static void collect_secrets(const char *repo, ClueList *cl)
{
    for (int i = 0; SECRET_PATTERNS[i]; i++) {
        FILE *fp = grep_pattern(repo, SECRET_PATTERNS[i], 1, 2000);
        if (!fp) continue;
        char line[LINE_BUF];
        int added = 0;
        while (fgets(line, sizeof(line), fp) && added < 500) {
            strip_nl(line);
            char fpath[CLUE_FIELD_MAX] = {0};
            char lnum[64] = {0};
            char *content = NULL;
            parse_grep_line(line, fpath, sizeof(fpath), lnum, sizeof(lnum), &content);
            char extra[CLUE_VALUE_MAX];
            snprintf(extra, sizeof(extra), "%s:%s", fpath, lnum);
            add_clue(cl, CLUE_SECRET, content ? content : line,
                     NULL, NULL, fpath, extra, NULL);
            added++;
        }
        pclose(fp);
    }
}

static void collect_secrets_from_history(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo,
        "log --all --patch --follow -S 'AKIA' -- '*.env' '*.env.*' '.env' '.env.*' 2>/dev/null | grep '^+' | grep -v '^+++' | head -500");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        char *p = line;
        if (*p == '+') p++;
        if (!p[0]) continue;
        char val[CLUE_VALUE_MAX];
        snprintf(val, sizeof(val), "history-env:%.4080s", p);
        add_clue(cl, CLUE_SECRET, val, NULL, NULL, ".env-history", "from-git-history", NULL);
    }
    pclose(fp);
}

static void collect_suspicious(const char *repo, ClueList *cl)
{
    for (int i = 0; SUSPICIOUS_PATTERNS[i]; i++) {
        FILE *fp = grep_pattern(repo, SUSPICIOUS_PATTERNS[i], 0, 200);
        if (!fp) continue;
        char line[LINE_BUF];
        while (fgets(line, sizeof(line), fp)) {
            strip_nl(line);
            add_clue(cl, CLUE_SUSPICIOUS, line, NULL, NULL, NULL, SUSPICIOUS_PATTERNS[i], NULL);
        }
        pclose(fp);
    }
}

static void collect_relations(const char *repo, ClueList *cl)
{
    FILE *fp = git_cmd(repo, "log --all --pretty=format:'%H%x09%P'");
    if (!fp) return;
    char line[LINE_BUF];
    int added = 0;
    while (fgets(line, sizeof(line), fp) && added < 1000) {
        strip_nl(line);
        char *hash    = strtok(line, "\t");
        char *parents = strtok(NULL, "\t");
        if (!hash || !parents || parents[0] == '\0') continue;
        char *par = strtok(parents, " ");
        while (par) {
            char val[CLUE_VALUE_MAX];
            snprintf(val, sizeof(val), "parent:%s->%s", par, hash);
            add_clue(cl, CLUE_RELATION, val, hash, NULL, NULL, NULL, NULL);
            par = strtok(NULL, " ");
            added++;
        }
    }
    pclose(fp);
}

static void collect_packed_refs(const char *repo, ClueList *cl)
{
    char prpath[CLUE_FIELD_MAX + 32];
    snprintf(prpath, sizeof(prpath), "%s/.git/packed-refs", repo);
    FILE *fp = fopen(prpath, "r");
    if (!fp) return;
    char line[LINE_BUF];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        if (line[0] == '#' || line[0] == '^') continue;
        char *sha = strtok(line, " ");
        char *ref = strtok(NULL, " ");
        if (sha && ref) {
            char val[CLUE_VALUE_MAX];
            snprintf(val, sizeof(val), "packed:%s", ref);
            add_clue(cl, CLUE_REFNAME, val, sha, NULL, NULL, "packed-ref", NULL);
        }
    }
    fclose(fp);
}

static void collect_git_log_refs(const char *repo, ClueList *cl)
{
    char reflogdir[CLUE_FIELD_MAX + 32];
    snprintf(reflogdir, sizeof(reflogdir), "%s/.git/logs/refs", repo);
    DIR *d = opendir(reflogdir);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char val[CLUE_VALUE_MAX];
        snprintf(val, sizeof(val), "log-ref:%s/%s", "refs", ent->d_name);
        add_clue(cl, CLUE_REFNAME, val, NULL, NULL, NULL, "deleted-branch-candidate", NULL);
    }
    closedir(d);
}

int scan_repo(const char *path, ClueList *cl)
{
    if (!is_git_repo(path)) {
        fprintf(stderr, "error: not a git repository: %s\n", path);
        return -1;
    }
    strncpy(cl->repo_path, path, CLUE_FIELD_MAX - 1);
    clue_now_utc(cl->scanned_utc, sizeof(cl->scanned_utc));

    collect_commits(path, cl);
    collect_committer_names(path, cl);
    collect_refs(path, cl);
    collect_tags(path, cl);
    collect_stashes(path, cl);
    collect_reflog(path, cl);
    collect_notes(path, cl);
    collect_files(path, cl);
    collect_remotes(path, cl);
    collect_git_config(path, cl);
    collect_urls_from_log(path, cl);
    collect_ips(path, cl);
    collect_ipv6(path, cl);
    collect_internal_domains(path, cl);
    collect_submodules(path, cl);
    collect_hooks(path, cl);
    collect_vscode(path, cl);
    collect_force_push_indicators(path, cl);
    collect_dangling_commits(path, cl);
    collect_dangling_blobs(path, cl);
    collect_ci_configs(path, cl);
    collect_docker_info(path, cl);
    collect_signed_off_by(path, cl);
    collect_timezone_anomalies(path, cl);
    collect_commit_hour_anomalies(path, cl);
    collect_churn(path, cl);
    collect_deleted_readded_files(path, cl);
    collect_gpg_signatures(path, cl);
    collect_packed_refs(path, cl);
    collect_git_log_refs(path, cl);
    collect_secrets(path, cl);
    collect_secrets_from_history(path, cl);
    collect_suspicious(path, cl);
    collect_relations(path, cl);
    return 0;
}

static void col(const char *code, const char *text)
{
    if (g_color) printf("%s%s%s", code, text, COLOR_RESET);
    else printf("%s", text);
}

static void print_section(const char *title)
{
    if (g_color) printf("\n%s%s%s\n", COLOR_BOLD, title, COLOR_RESET);
    else printf("\n%s\n", title);
}

static void print_clue_group(ClueList *cl, ClueType type, const char *name, int max)
{
    int total = 0;
    int shown = 0;
    for (size_t i = 0; i < cl->count; i++) {
        if (cl->items[i].type != type) continue;
        total++;
        if (shown < max) {
            if (shown == 0) print_section(name);
            printf("  ");
            col(COLOR_GREEN, cl->items[i].value);
            if (cl->items[i].extra[0]) printf("  %s", cl->items[i].extra);
            printf("\n");
            shown++;
        }
    }
    if (total > max) {
        char msg[64];
        snprintf(msg, sizeof(msg), "  ... and %d more\n", total - max);
        col(COLOR_YELLOW, msg);
    }
}

static void print_secrets_section(ClueList *cl)
{
    int found = 0;
    for (size_t i = 0; i < cl->count; i++) {
        if (cl->items[i].type != CLUE_SECRET) continue;
        if (!found) { print_section("SECRETS"); found = 1; }
        char line[CLUE_VALUE_MAX * 3];
        snprintf(line, sizeof(line), "  [CRIT] %.4000s  location=%.4000s\n",
                 cl->items[i].value,
                 cl->items[i].extra[0] ? cl->items[i].extra : "unknown");
        col(COLOR_RED, line);
    }
    if (!found) col(COLOR_GREEN, "  [INFO] no secrets detected\n");
}

static void print_suspicious_section(ClueList *cl)
{
    int found = 0;
    for (size_t i = 0; i < cl->count; i++) {
        if (cl->items[i].type != CLUE_SUSPICIOUS) continue;
        if (!found) { print_section("SUSPICIOUS"); found = 1; }
        char line[CLUE_VALUE_MAX + 16];
        snprintf(line, sizeof(line), "  [WARN] %.4080s\n", cl->items[i].value);
        col(COLOR_YELLOW, line);
    }
    if (!found) col(COLOR_GREEN, "  [INFO] no suspicious patterns detected\n");
}

static int count_type(ClueList *cl, ClueType type)
{
    int n = 0;
    for (size_t i = 0; i < cl->count; i++)
        if (cl->items[i].type == type) n++;
    return n;
}

static int compute_risk_score(ClueList *cl)
{
    int score = 0;
    int tz_shifts = 0;
    int midnight_commits = 0;
    for (size_t i = 0; i < cl->count; i++) {
        Clue *c = &cl->items[i];
        if (c->type == CLUE_SUSPICIOUS) {
            if (strncmp(c->value, "tz-shift:", 9) == 0)      { tz_shifts++; }
            if (strncmp(c->value, "odd-hour-commit:", 16) == 0) { midnight_commits++; score += 2; }
            if (strncmp(c->value, "force-push-indicator:", 21) == 0) { score += 30; }
            if (strncmp(c->value, "dangling-commit:", 16) == 0)      { score += 10; }
            if (strncmp(c->value, "hook:", 5) == 0) {
                char *rs = strstr(c->value, "score=");
                if (rs) {
                    int hs = atoi(rs + 6);
                    if (hs >= 50) score += 100;
                    else if (hs >= 30) score += 30;
                    else score += 5;
                }
            }
            if (strncmp(c->value, "high-churn-deletion:", 20) == 0) { score += 15; }
            if (strncmp(c->value, "deleted-readded:", 16) == 0)      { score += 20; }
        }
        if (c->type == CLUE_SECRET) {
            if (strstr(c->extra, "unreachable-blob")) score += 80;
            else score += 20;
        }
    }
    if (tz_shifts >= 3) score += 10;
    score += midnight_commits;
    (void)g_verbose;
    (void)g_debug;
    return score;
}

static void print_count(const char *label, int n, const char *warn_color)
{
    printf("  %-14s ", label);
    if (g_color && warn_color && n > 0) printf("%s%d%s\n", warn_color, n, COLOR_RESET);
    else printf("%d\n", n);
}

static void print_repo_size(const char *path)
{
    char cmd[POPEN_CMD_MAX];
    snprintf(cmd, sizeof(cmd), "du -sh %s/.git 2>/dev/null", path);
    FILE *fp = popen(cmd, "r");
    if (!fp) return;
    char line[256];
    if (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        char *tab = strchr(line, '\t');
        if (tab) *tab = '\0';
        printf("  %-14s %s\n", "git-size:", line);
    }
    pclose(fp);

    snprintf(cmd, sizeof(cmd), "git -C %s count-objects -vH 2>/dev/null", path);
    fp = popen(cmd, "r");
    if (!fp) return;
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        if (strncmp(line, "size-pack:", 10) == 0) {
            printf("  %-14s %s\n", "pack-size:", line + 11);
            break;
        }
    }
    pclose(fp);
}

static void print_repo_metadata(const char *path, ClueList *cl)
{
    int risk = compute_risk_score(cl);
    print_section("REPOSITORY");
    printf("  %-14s %s\n", "path:", path);
    printf("  %-14s %s\n", "scanned:", cl->scanned_utc);
    print_repo_size(path);
    print_count("commits:",    count_type(cl, CLUE_COMMIT),    NULL);
    print_count("authors:",    count_type(cl, CLUE_AUTHOR),    NULL);
    print_count("refs:",       count_type(cl, CLUE_REFNAME),   NULL);
    print_count("tags:",       count_type(cl, CLUE_TAG),       NULL);
    print_count("stashes:",    count_type(cl, CLUE_STASH),     NULL);
    print_count("files:",      count_type(cl, CLUE_FILEPATH),  NULL);
    print_count("emails:",     count_type(cl, CLUE_EMAIL),     NULL);
    print_count("usernames:",  count_type(cl, CLUE_USERNAME),  NULL);
    print_count("ips:",        count_type(cl, CLUE_IP),        COLOR_YELLOW);
    print_count("secrets:",    count_type(cl, CLUE_SECRET),    COLOR_RED);
    print_count("suspicious:", count_type(cl, CLUE_SUSPICIOUS),COLOR_YELLOW);
    printf("  %-14s ", "risk-score:");
    if (g_color) {
        const char *rc = risk >= 100 ? COLOR_RED : risk >= 30 ? COLOR_YELLOW : COLOR_GREEN;
        printf("%s%d%s\n", rc, risk, COLOR_RESET);
    } else {
        printf("%d\n", risk);
    }
}

void inspect_repo(const char *path, ClueList *cl)
{
    g_color = isatty(STDOUT_FILENO);
    print_repo_metadata(path, cl);
    print_clue_group(cl, CLUE_FILEPATH,  "TRACKED FILES",  20);
    print_clue_group(cl, CLUE_REFNAME,   "REFS",           20);
    print_clue_group(cl, CLUE_TAG,       "TAGS",           20);
    print_clue_group(cl, CLUE_STASH,     "STASHES",        10);
    print_clue_group(cl, CLUE_EMAIL,     "EMAILS",         30);
    print_clue_group(cl, CLUE_URL,       "URLS",           20);
    print_clue_group(cl, CLUE_DOMAIN,    "DOMAINS",        20);
    print_clue_group(cl, CLUE_AUTHOR,    "AUTHORS",        20);
    print_clue_group(cl, CLUE_COMMIT,    "COMMITS",        20);
    print_clue_group(cl, CLUE_USERNAME,  "USERNAMES",      20);
    print_clue_group(cl, CLUE_IP,        "IP ADDRESSES",   20);
    print_clue_group(cl, CLUE_RELATION,  "RELATIONS",      20);
    print_secrets_section(cl);
    print_suspicious_section(cl);
    printf("\n");
}

void search_clues(ClueList *cl, const char *query)
{
    if (!query || !query[0]) return;
    g_color = isatty(STDOUT_FILENO);
    int found = 0;
    for (size_t i = 0; i < cl->count; i++) {
        Clue *c = &cl->items[i];
        if (strcasestr(c->value,  query) || strcasestr(c->author, query) ||
            strcasestr(c->path,   query) || strcasestr(c->extra,  query)) {
            printf("[%s] %s", clue_type_str(c->type), c->value);
            if (c->commit[0]) printf("  commit=%s", c->commit);
            if (c->path[0])   printf("  path=%s",   c->path);
            if (c->utc[0])    printf("  utc=%s",    c->utc);
            printf("\n");
            found++;
        }
    }
    if (!found) printf("no matches for: %s\n", query);
}

static void write_json_string(FILE *fp, const char *s)
{
    fputc('"', fp);
    for (; *s; s++) {
        if (*s == '"')  { fputs("\\\"", fp); continue; }
        if (*s == '\\') { fputs("\\\\", fp); continue; }
        if (*s == '\n') { fputs("\\n",  fp); continue; }
        if (*s == '\r') { fputs("\\r",  fp); continue; }
        if (*s == '\t') { fputs("\\t",  fp); continue; }
        fputc(*s, fp);
    }
    fputc('"', fp);
}

static void save_json(ClueList *cl, const char *outpath)
{
    char jsonpath[CLUE_FIELD_MAX + 8];
    size_t plen = strlen(outpath);
    if (plen > 5 && strcmp(outpath + plen - 5, ".json") == 0)
        snprintf(jsonpath, sizeof(jsonpath), "%s", outpath);
    else
        snprintf(jsonpath, sizeof(jsonpath), "%s.json", outpath);

    FILE *fp = fopen(jsonpath, "w");
    if (!fp) return;

    fprintf(fp, "{\n");
    fprintf(fp, "  \"gitward_version\": \"%s\",\n", GITWARD_VERSION);
    fprintf(fp, "  \"repo\": ");
    write_json_string(fp, cl->repo_path);
    fprintf(fp, ",\n  \"scanned\": ");
    write_json_string(fp, cl->scanned_utc);
    fprintf(fp, ",\n  \"risk_score\": %d,\n", compute_risk_score(cl));
    fprintf(fp, "  \"clue_count\": %zu,\n", cl->count);
    fprintf(fp, "  \"clues\": [\n");

    for (size_t i = 0; i < cl->count; i++) {
        Clue *c = &cl->items[i];
        fprintf(fp, "    {");
        fprintf(fp, "\"type\":"); write_json_string(fp, clue_type_str(c->type)); fprintf(fp, ",");
        fprintf(fp, "\"value\":"); write_json_string(fp, c->value);
        if (c->commit[0]) { fprintf(fp, ",\"commit\":"); write_json_string(fp, c->commit); }
        if (c->author[0]) { fprintf(fp, ",\"author\":"); write_json_string(fp, c->author); }
        if (c->path[0])   { fprintf(fp, ",\"path\":");   write_json_string(fp, c->path);   }
        if (c->extra[0])  { fprintf(fp, ",\"extra\":");  write_json_string(fp, c->extra);  }
        if (c->utc[0])    { fprintf(fp, ",\"utc\":");    write_json_string(fp, c->utc);    }
        fprintf(fp, "}");
        if (i + 1 < cl->count) fprintf(fp, ",");
        fprintf(fp, "\n");
    }
    fprintf(fp, "  ]\n}\n");
    fclose(fp);
    printf("saved (json): %s\n", jsonpath);
}

int save_clues(ClueList *cl, const char *outpath)
{
    FILE *fp = fopen(outpath, "w");
    if (!fp) {
        fprintf(stderr, "error: cannot open %s for writing\n", outpath);
        return -1;
    }
    fprintf(fp, "# gitward %s\n", GITWARD_VERSION);
    fprintf(fp, "# repo=%s\n", cl->repo_path);
    fprintf(fp, "# scanned=%s\n", cl->scanned_utc);
    fprintf(fp, "# risk_score=%d\n", compute_risk_score(cl));
    fprintf(fp, "# clues=%zu\n\n", cl->count);

    for (size_t i = 0; i < cl->count; i++) {
        Clue *c = &cl->items[i];
        fprintf(fp, "type=%s value=%s", clue_type_str(c->type), c->value);
        if (c->commit[0]) fprintf(fp, " commit=%s", c->commit);
        if (c->author[0]) fprintf(fp, " author=%s", c->author);
        if (c->path[0])   fprintf(fp, " path=%s",   c->path);
        if (c->extra[0])  fprintf(fp, " extra=%s",  c->extra);
        if (c->utc[0])    fprintf(fp, " utc=%s",    c->utc);
        fprintf(fp, "\n");
    }
    fclose(fp);

    const char *dot = strrchr(outpath, '.');
    int is_json = dot && strcmp(dot, ".json") == 0;
    if (is_json) save_json(cl, outpath);

    return 0;
}
