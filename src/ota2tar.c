// Copyright (c) 2015 Eric Monti
//
// ota2tar
//
// Parses an Apple iOS OTA file and converts it to tar
//
// Only the Format 3.0 described here is supported:
// https://www.theiphonewiki.com/wiki/OTA_Updates
//
// This code is based heavily on Jonathan Levin's example code
// found here: http://newosxbook.com/articles/OTA.html
//
// Dependencies:
//   libarchive (a "recent-ish version"?)
//
// Credit:
//
//   Thanks to Jonathan Levin for his awesome series of posts about
//   the OTA format.
//
// License:
//   See LICENSE.TXT

#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <archive.h>
#include <archive_entry.h>

#define PBZX_MAGIC ((uint32_t)0x70627a78)
#define XZ_HEAD_MAGIC ("\xfd""7zXZ\x00")
#define XZ_TAIL_MAGIC ("YZ")

const char *cmdlineopts = "?hvkzEo:";
bool g_verbose = false;
bool g_executables = false;

#define error_msg(fmt, msg...) fprintf(stderr, "!!! Error (%s): " fmt, __func__, ##msg)
#define warn_msg(fmt, msg...) fprintf(stderr, "... Warning (%s): " fmt, __func__, ##msg)
#define verbose_msg(fmt, msg...) if (g_verbose) { printf("... " fmt, ##msg); }

static void usage(const char *progname)
{
    fprintf(stderr, "Usage: %s [%s] /path/to/ota/payload\n", progname, cmdlineopts);
    fprintf(stderr, "  Options:\n");
    fprintf(stderr, "    -?/-h        Show this help message\n");
    fprintf(stderr, "    -v           Verbose output\n");
    fprintf(stderr, "    -k           Keep intermediate payload.ota file\n");
    fprintf(stderr, "    -z           Compress the resulting tar-ball\n");
    fprintf(stderr, "    -E           Extract executables only\n");
    fprintf(stderr, "    -o path      Output to path\n");
}

struct ota_entry
{
    uint8_t unk1[6]; // usually 10 01 00 00 00 00
    uint32_t fileSize;
    uint32_t unk2;
    uint32_t timestamp;
    uint32_t unk3;
    uint16_t namelen;
    uint16_t uid;
    uint16_t gid;
    uint16_t perms;

    char name[0];
    // Followed by file contents
} __attribute__((packed));

#define DYLD_SHARED_CACHE_CMP "System/Library/Caches/com.apple.dyld/dyld_shared_cache"


bool is_executable(const char *name, void* filedata, size_t filesize)
{
    if (memcmp(name, DYLD_SHARED_CACHE_CMP, sizeof(DYLD_SHARED_CACHE_CMP)-1) == 0) {
        return true;
    }

    if (filesize < sizeof(uint32_t)) {
        return false;
    }

    uint32_t magic = *(uint32_t*)filedata;
    return ( (magic & 0xFFFFFFF0) == 0xFEEDFAC0 || (magic & 0xF0FFFFFF) == 0xC0FAEDFE || magic == 0xCAFEBABE || magic == 0xBEBAFECA );
}


static bool add_to_archive(const struct ota_entry *ota_ent, struct archive *ar_out)
{
    uint16_t namelen = ntohs(ota_ent->namelen);
    char name[PATH_MAX + 1];
    if (namelen > PATH_MAX) {
        error_msg("Filename too large\n");
        return false;
    }

    memcpy(name, ota_ent->name, namelen);
    name[namelen] = 0;

    mode_t mode = (mode_t)ntohs(ota_ent->perms);
    uint32_t timestamp = ntohl(ota_ent->timestamp);
    size_t filesize = ntohl(ota_ent->fileSize);

    uid_t uid = ntohs(ota_ent->uid);
    gid_t gid = ntohs(ota_ent->gid);
    uint8_t *filedata = (void *)ota_ent + sizeof(struct ota_entry) + namelen;

    if (g_executables) {
        if (!is_executable(name, filedata, filesize)) {
            verbose_msg("Skipping %s - not a mach-o file\n", name);
            return true;
        }
    }

    verbose_msg("Archiving %s (filesize:%zu mode:0%o uid:%u gid:%u timestamp:%u)\n", name, filesize, mode, uid, gid, timestamp);

    struct archive_entry *ar_ent = archive_entry_new();
    assert (ar_ent != NULL);

    archive_entry_set_pathname(ar_ent, name);
    archive_entry_set_filetype(ar_ent, (mode & S_IFMT));
    archive_entry_set_perm(ar_ent, (mode & (~S_IFMT)));
    archive_entry_set_size(ar_ent, filesize);
    archive_entry_set_uid(ar_ent, uid);
    archive_entry_set_gid(ar_ent, gid);

    archive_entry_set_atime(ar_ent, timestamp, 0);
    archive_entry_set_birthtime(ar_ent, timestamp, 0);
    archive_entry_set_ctime(ar_ent, timestamp, 0);
    archive_entry_set_mtime(ar_ent, timestamp, 0);

    int r = archive_write_header(ar_out, ar_ent);
    archive_entry_free(ar_ent);

    if (r != ARCHIVE_OK) {
        error_msg("archive_write_header error %s - %s\n", name, archive_error_string(ar_out));
        return false;
    }


    if (S_ISLNK(mode)) {
        // For symlinks, the link target is stored where file contents would normally go
        char link_name[PATH_MAX + 1];
        assert(filesize < PATH_MAX);
        if (filesize > PATH_MAX) {
            error_msg("Link target filename for %s too large: %zu\n", name, filesize);
            return false;
        }

        memcpy(link_name, filedata, filesize);
        link_name[filesize] = 0;

    } else if (filesize != 0) {
        ssize_t written = archive_write_data(ar_out, filedata, filesize);
        if (written != filesize) {
            error_msg("archive_write_data error %s (%zi != %zu) %s\n", name, written, filesize, archive_error_string(ar_out));
            return false;
        }
    }

    return true;
}


static bool extract_ota(const uint8_t *chunk, size_t chunk_size, struct archive *ar_out)
{
    const uint8_t *p = chunk;
    ssize_t chunk_left = chunk_size;

    while (chunk_left > 0) {
        if (chunk_left < sizeof(struct ota_entry)) {
            error_msg("Entry out of bounds (chunk_left=%zx > sizeof(struct ota_entry)\n", chunk_left);
            return false;
        }

        const struct ota_entry *ent = (const struct ota_entry *)p;
        uint16_t namelen = ntohs(ent->namelen);
        size_t filesize = ntohl(ent->fileSize);

        size_t ent_size = sizeof(struct ota_entry) + namelen + filesize;
        if (ent_size > chunk_left) {
            error_msg("Entry out of bounds (ent_size=%zx > chunk_left=%zx)\n", ent_size, chunk_left);
            return false;
        }

        if (! add_to_archive(ent, ar_out)) {
            error_msg("Archive error - quitting\n");
            return false;
        }

        chunk_left -= ent_size;
        p += ent_size;
    }

    return true;
}


static bool decompress_xz(const void *buf, uint64_t length, int outfd)
{
    if (length > (size_t)-2) {
        error_msg("Compressed chunk is too big\n");
        return false;
    }

    struct archive *ar = archive_read_new();
    assert(ar != NULL);

#if ARCHIVE_VERSION_NUMBER < 3000000
    archive_read_support_compression_xz(ar);
#else
    archive_read_support_filter_xz(ar);
#endif

    archive_read_support_format_empty(ar);
    archive_read_support_format_raw(ar);

    bool ret = false;

    if (archive_read_open_memory(ar, (void*)buf, length) == ARCHIVE_OK) {
        struct archive_entry *ae;
        int r = archive_read_next_header(ar, &ae);
        if (r == ARCHIVE_OK) {
            size_t bufsize = 0x8000;
            uint8_t buf[bufsize];
            for (;;) {
                ssize_t readsz = archive_read_data(ar, buf, bufsize);

                if (readsz < 0) {
                    error_msg("archive_read_data error - %s\n", archive_error_string(ar));
                    break;
                } else if (bufsize < readsz) {
                    error_msg("bad size returned by archive_read_data - %zi\n", readsz);
                    break;
                } else if (readsz == 0) {
                    // read finished
                    ret = true;
                    break;
                } else {
                    write(outfd, buf, readsz);
                }
            }
        } else if (r == ARCHIVE_EOF) {
            error_msg("Empty archive entry?\n");
        }
        archive_read_close(ar);
    } else {
        error_msg("archive_read_open_memory error - %s\n", archive_error_string(ar));

    }


    if (!ret) {
    }
    return ret;
}


static bool extract_pbzx(const void *pbzx_data, size_t pbzx_size, int outfd)
{
    if (pbzx_size < 32) {
        error_msg("Input is too small to be a pbzx\n");
        return false;
    }

    uint32_t magic = ntohl( *((uint32_t*)pbzx_data) ); // XXX assumes little-endian

    if (magic != PBZX_MAGIC) {
        error_msg("Invalid magic value 0x%0.8x\n", magic);
        return false;
    }

    const void *p = pbzx_data + 4;
    const void *file_end = pbzx_data + pbzx_size;

    uint64_t flags = __builtin_bswap64(*((uint64_t*)p)); // one flag before all the chunks
    p += sizeof(uint64_t);

    int chunk_idx = 0;

    while(p < file_end) { // have more chunks
        if (20 > file_end-p) {
            error_msg("Reached premature end of file\n");
            return false;
        }
        chunk_idx++;

        flags = __builtin_bswap64(*((uint64_t*)p));
        p += sizeof(uint64_t);

        uint64_t length = __builtin_bswap64(*((uint64_t*)p));
        p += sizeof(uint64_t);

        verbose_msg("Processing PBZX Chunk #%d @0x%zx (flags: %llx, length: %lld bytes)\n",
                chunk_idx, (p - pbzx_data), flags, length);

        if (length > (file_end - p)) {
            error_msg("Chunk length out of bounds: %lld bytes?", length);
        }

        bool is_xz_chunk = (memcmp(p, XZ_HEAD_MAGIC, sizeof(XZ_HEAD_MAGIC)-1) == 0);
        if (is_xz_chunk) {
            const void *xz_tail = (p + length) - 2;
            if (memcmp(xz_tail, XZ_TAIL_MAGIC, sizeof(XZ_TAIL_MAGIC)-1) != 0) {
                error_msg("Expected XZ trailer magic at offset 0x%zx\n", (xz_tail - pbzx_data));
                return false;
            }

            if (!decompress_xz(p, length, outfd)) {
                return false;
            }
        } else {
            verbose_msg("Non-XZ chunk detected #%d @0x%zx (written as is to file)\n", chunk_idx, (p - pbzx_data));
            uint64_t written = 0;
            while (written < length) {
                size_t wlen = ((length-written) < SIZE_T_MAX)? (length-written) : SIZE_T_MAX;
                ssize_t n = write(outfd, (p+written), wlen);
                assert(n > 0);
                written += n;
            }
        }
        p += length;
    }

    if (p == file_end) {
        printf("PBZX Parsing Complete\n");
        return true;
    } else {
        error_msg("Parse failed early at file offset 0x%zx\n", (p - pbzx_data));
        return false;
    }
}


int main(int argc, char * argv[])
{
    const char *progname = argv[0];

    bool compress = false;
    bool keep = false;
    const char *ar_ext = "tar";
    char *ar_outfile = NULL;

    int ch;
    while ((ch = getopt(argc, argv, cmdlineopts)) != -1) {
        switch (ch) {
            case 'h':
            case '?':
            {
                usage(progname);
                return EXIT_SUCCESS;
                break;
            }

            case 'o':
            {
                ar_outfile = optarg;
                break;
            }

            case 'z':
            {
                compress = true;
                ar_ext = "tar.bz2";
                break;
            }

            case 'k':
            {
                keep = true;
                break;
            }

            case 'v':
            {
                g_verbose = true;
                break;
            }

            case 'E':
            {
                g_executables = true;
                break;
            }

            default:
            {
                usage(progname);
                return EXIT_FAILURE;
                break;
            }
        }
    }

    argc -= optind;
    argv += optind;

    if (argc < 1) {
        usage(progname);
        return EXIT_FAILURE;
    }

    char infile[PATH_MAX + 1];
    if (!realpath(argv[0], infile)) {
        error_msg("realpath error - %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    // we need a little extra pathname room for extensions
    if (strlen(infile) > (PATH_MAX - 10)) {
        error_msg("Filename too long\n");
        return EXIT_FAILURE;
    }

    char ota_outfile[PATH_MAX + 1];

    snprintf(ota_outfile, PATH_MAX, "%s.ota", infile);
    if (!ar_outfile) {
        ar_outfile = alloca(PATH_MAX + 1);
        assert(ar_outfile != NULL);
        snprintf(ar_outfile, PATH_MAX, "%s.%s", infile, ar_ext);
    }

    bool ota_done = false;
    bool pbzx_done = false;

    int ota_fd;

    bool our_pbzx = false;
    if (access(ota_outfile, F_OK) == 0) {
        printf("*** PBZX appears to have already been extracted. Using: %s\n", ota_outfile);
        ota_fd = open(ota_outfile, O_RDONLY);
        pbzx_done = true;
    } else {
        printf("*** Extracting PBZX payload file %s -> %s\n", infile, ota_outfile);
        ota_fd = open(ota_outfile, (O_RDWR | O_TRUNC | O_CREAT), 0600);
        our_pbzx = true;
    }

    if (ota_fd < 0) {
        error_msg("Unable to open file: %s - %s\n", ota_outfile, strerror(errno));
        return EXIT_FAILURE;
    }

    if (!pbzx_done) {
        int pbzx_fd = open(infile, O_RDONLY);
        if (pbzx_fd >= 0) {
            struct stat st;
            if (fstat(pbzx_fd, &st) == 0) {
                if (S_ISREG(st.st_mode)) {
                    void *pbzx_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, pbzx_fd, 0);
                    if (pbzx_data) {
                        pbzx_done = extract_pbzx(pbzx_data, st.st_size, ota_fd);
                        munmap(pbzx_data, st.st_size);
                    } else {
                        error_msg("mmap failed: %s\n", strerror(errno));
                    }
                } else {
                    error_msg("Not a file: %s\n", infile);
                }
            } else {
                error_msg("Unable to fstat %s - %s\n", infile, strerror(errno));
            }
            close(pbzx_fd);
        } else {
            error_msg("Unable to open %s - %s\n", infile, strerror(errno));
        }
    }

    if (pbzx_done) {
        struct archive *ar_out = archive_write_new();
        assert(ar_out != NULL);
        assert(archive_write_set_format_gnutar(ar_out) == ARCHIVE_OK);

        if (compress) {
#if ARCHIVE_VERSION_NUMBER < 3000000
            assert(archive_write_set_compression_bzip2(ar_out) == ARCHIVE_OK);
#else
            assert(archive_write_add_filter_bzip2(ar_out) == ARCHIVE_OK);
#endif
        }

        if (archive_write_open_filename(ar_out, ar_outfile) == ARCHIVE_OK) {
            printf("*** Converting OTA archive to tarball %s -> %s\n", ota_outfile, ar_outfile);
            struct stat st;
            if (fstat(ota_fd, &st) == 0) {
                if (S_ISREG(st.st_mode)) {
                    void *ota_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, ota_fd, 0);
                    if (ota_data) {
                        ota_done = extract_ota(ota_data, st.st_size, ar_out);
                        munmap(ota_data, st.st_size);
                    } else {
                        error_msg("mmap failed: %s\n", strerror(errno));
                    }
                } else {
                    error_msg("Not a file: %s\n", ota_outfile);
                }
            } else {
                error_msg("Unable to fstat %s - %s\n", ota_outfile, strerror(errno));
            }
        } else {
            error_msg("Unable to create archive %s - %s\n", ar_outfile, archive_error_string(ar_out));
        }

        printf("*** Finished %s writing %s\n", (ota_done ? "successfulliy" : "with errors"), ar_outfile);
        archive_write_close(ar_out);
    }

    close(ota_fd);

    if (!keep && our_pbzx) {
        verbose_msg("Cleaning up %s\n", ota_outfile);
        unlink(ota_outfile);
    } else {
        verbose_msg("Leaving %s\n", ota_outfile);
    }

    return (pbzx_done && ota_done) ? EXIT_SUCCESS : EXIT_FAILURE;
}
