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
  printf("  -p <port>           SSH port (default: 22)\n");
  printf("  --progress          Show transfer progress\n");
  printf("  --delete            Delete files on receiver not in source\n");
  printf("  --exclude <pattern> Exclude files matching pattern\n");
  printf("  --include <pattern> Only include files matching pattern\n");
  printf("  --exclude-from <file> Read exclude patterns from file\n");
  printf("  --include-from <file> Read include patterns from file\n");
  printf("  --max-size <n>      Skip files larger than n bytes\n");
  printf("  --min-size <n>      Skip files smaller than n bytes\n");
  printf("  --incremental       Skip files unchanged since last transfer\n");
  printf("  --delta             Delta transfer for changed files (requires --incremental)\n");
  printf("  --delta-block <n>   Delta block size in bytes (default: %d)\n",
         DELTA_BLOCK_SIZE_DEFAULT);
  printf("  --delta-max <n>     Max file size for delta transfer (default: %llu)\n",
         DELTA_MAX_FILE_SIZE);
  printf("  -m                  Enable multithreading\n");
  printf("  -s                  Enable chunk serialization\n");
  printf("  -f                  Enable sendfile (TCP only, not with -c or -s)\n");
  printf("  -v, --verbose       Enable debug logging\n");
  printf("  --debug=FLAGS       Fine-grained debug logging (use --debug=help for flags)\n");
  printf("  -M, --preserve      Preserve file metadata\n");
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
  printf("  --max-depth <n>     Maximum directory depth (0=unlimited)\n");
  printf("  --log-file <path>   Write log messages to file\n");
  printf("  --partial           Keep partial files on interrupted transfer\n");
  printf("  --partial-dir <dir> Directory for partial files\n");
  printf("  --fastsync-server-path <path>\n");
  printf("                      Path to fastsync-server on remote (default: fastsync-server)\n");
  printf("  -l, --links         Copy symlinks as symlinks\n");
  printf("  --copy-links        Transform symlinks into referent files\n");
  printf("  --safe-links        Skip symlinks that point outside transfer tree\n");
  printf("  --copy-unsafe-links  Only transform unsafe symlinks into referent files\n");
  printf("  -S, --sparse        Handle sparse files efficiently\n");
  printf("  --inplace           Update files in-place (no temp+rename)\n");
  printf("  --compress-level <n>    Compression level (default: 5)\n");
  printf("  --help              Show this help\n");
  printf("  -V, --version       Show version\n");
}

void print_debug_usage(void) {
  printf("Supported debug flags: IO,PROTO,PACK,UTIL,ALL,NONE\n");
  printf("Flags may be comma-separated, for example: --debug=io,proto\n");
  printf("Other rsync debug flags are unsupported and rejected.\n");
}
