#include "usage.h"
#include <stdio.h>
#include <delta.h>
#include <chunk.h>

void print_usage(void) {
  printf("Usage:\n");
  printf("  fastsync [options] <source> <destination>\n");
  printf("  fastsync [options] --source-dir <src> --dest-dir <dst>\n");
  printf("\n");
  printf("Destination formats:\n");
  printf("  user@host:/path     SSH transport (rsync-style)\n");
  printf("  host:/path          SSH transport (current user)\n");
  printf("  /local/path         TCP transport (requires server on localhost:8080)\n");
  printf("\n");
  printf("Options:\n");
  printf("  -c [level]          Enable compression (level 1-22, default 5)\n");
  printf("  -z [level]          Alias for -c\n");
  printf("  -a, --archive       Archive mode (-c -m -M)\n");
  printf("  -n, --dry-run       Show what would be transferred\n");
  printf("  --remove-source-files  Remove regular source files after successful transfer\n");
  printf("  -p <port>           SSH port (default: 22)\n");
  printf("  --progress          Show transfer progress\n");
  printf("  -P                  Partial mode with progress (retention incomplete)\n");
  printf("  -8, --8-bit-output  Leave high-bit characters unescaped in output\n");
  printf("  --delete            Delete files on receiver not in source\n");
  printf("  --ignore-existing  Skip files that already exist on receiver\n");
  printf(
      "  --dirs, --old-dirs, --old-d  Transfer directories without recursing (not implemented)\n");
  printf("  --del               Alias for --delete-during (not implemented)\n");
  printf("  --exclude <pattern> Exclude files matching pattern\n");
  printf("  --include <pattern> Only include files matching pattern\n");
  printf("  --exclude-from <file> Read exclude patterns from file\n");
  printf("  --include-from <file> Read include patterns from file\n");
  printf("  --max-size <n>      Skip files larger than n bytes\n");
  printf("  --min-size <n>      Skip files smaller than n bytes\n");
  printf("  --max-alloc <SIZE>  Maximum single allocation (default: 1G)\n");
  printf("  --incremental       Skip files unchanged since last transfer\n");
  printf("  --size-only         Skip incremental files matching in size, ignoring mtime\n");
  printf("  -I, --ignore-times  Transfer files even when size and mtime match\n");
  printf("  -@, --modify-window <sec>  Modification time tolerance\n");
  printf("  -u, --update        Skip files newer than the source on receiver\n");
  printf("  --existing          Skip files not already present at destination\n");
  printf("  --checksum-choice, --cc <alg>  Checksum algorithm (not supported yet; xxHash64 is "
         "used)\n");
  printf("  --delta             Delta transfer for changed files (requires --incremental)\n");
  printf("  -W, --whole-file    Transfer changed files without delta processing\n");
  printf("  --delta-block <n>   Delta block size in bytes (default: %d)\n",
         DELTA_BLOCK_SIZE_DEFAULT);
  printf("  --delta-max <n>     Max file size for delta transfer (default: %llu)\n",
         DELTA_MAX_FILE_SIZE);
  printf("  -m                  Enable multithreading\n");
  printf("  -s                  Enable chunk serialization\n");
  printf("  --secluded-args    Accept rsync compatibility option (no effect)\n");
  printf("  -f                  Enable sendfile (TCP only, not with -c or -s)\n");
  printf("  --compress-choice <alg>  Compression algorithm (default: zstd)\n");
  printf("  --zc <alg>          Alias for --compress-choice\n");
  printf("  -v, --verbose       Enable debug logging\n");
  printf("  -q, --quiet         Suppress non-error output\n");
  printf("  --debug=FLAGS       Fine-grained debug logging (use --debug=help for flags)\n");
  printf("  --info=FLAGS        Fine-grained info: copy,misc,skip,stats,all,none\n");
  printf("                      none suppresses info even with --verbose\n");
  printf("  -M, --preserve      Preserve file metadata\n");
  printf("  -E, --executability Preserve executable permission bits\n");
  printf("  --chmod <changes>   Modify transferred permissions (rsync syntax)\n");
  printf("  --chunk-size <n>    Chunk size in bytes (default: %d)\n", DEFAULT_CHUNK_SIZE);
  printf("  --source-dir <path> Source directory\n");
  printf("  --dest-dir <path>   Destination directory\n");
  printf("  --save-to-disk      Write received files to disk\n");
  printf("  --server-host <ip>  Server IP address (default: 127.0.0.1)\n");
  printf("  --server-port <n>   Server port (default: 8080)\n");
  printf("  --bwlimit <KB/s>    Bandwidth limit in kilobytes per second\n");
  printf("  --tls               Enable TLS encryption\n");
  printf("  --cert <path>       TLS certificate file (PEM)\n");
  printf("  --key <path>        TLS private key file (PEM)\n");
  printf("  --ca <path>         TLS CA certificate file (PEM)\n");
  printf("  --timeout <sec>     I/O timeout in seconds (default: 30)\n");
  printf("  -T <sec>            Alias for --timeout\n");
  printf("  --contimeout <sec>  Connection timeout in seconds (default: 10)\n");
  printf("  --backup            Backup existing files before overwriting\n");
  printf("  --backup-dir <dir>  Directory for backups (requires --backup)\n");
  printf("  --suffix <str>      Backup suffix (default: ~)\n");
  printf("  --stats             Print transfer statistics at end\n");
  printf("  -h, --human-readable  Print byte sizes in human-readable form\n");
  printf("  --max-depth <n>     Maximum directory depth (0=unlimited)\n");
  printf("  -x, --one-file-system  Do not cross filesystem boundaries\n");
  printf("  --log-file <path>   Write log messages to file\n");
  printf("  --stderr=MODE       Route logging to stderr: errors or all\n");
  printf("  --partial           Keep partial files on interrupted transfer\n");
  printf("  --partial-dir <dir> Directory for partial files\n");
  printf("  --fastsync-server-path <path>\n");
  printf("                      Path to fastsync-server on remote (default: fastsync-server)\n");
  printf(
      "  --old-args          Disable safe SSH command argument quoting (legacy compatibility)\n");
  printf("  -l, --links         Copy symlinks as symlinks\n");
  printf("  --copy-links        Transform symlinks into referent files\n");
  printf("  --safe-links        Skip symlinks that point outside transfer tree\n");
  printf("  --copy-unsafe-links  Only transform unsafe symlinks into referent files\n");
  printf("  -S, --sparse        Handle sparse files efficiently\n");
  printf("  --inplace           Update files in-place (no temp+rename)\n");
  printf("  --fsync             Fsync every written file before publication\n");
  printf("  --compress-level <n>    Compression level (default: 5)\n");
  printf("  --zl <n>             Alias for --compress-level\n");
  printf("  --skip-compress=LIST    Skip compression for comma-separated suffixes\n");
  printf("  --compress-threads <n> Compression worker threads (requires zstd threaded support)\n");
  printf("  --no-OPTION         Disable a supported boolean option\n");
  printf("  --help              Show this help\n");
  printf("  -V, --version       Show version\n");
}

void print_debug_usage(void) {
  printf("Supported debug flags: IO,PROTO,PACK,UTIL,ALL,NONE\n");
  printf("Flags may be comma-separated, for example: --debug=io,proto\n");
  printf("Other rsync debug flags are unsupported and rejected.\n");
}
