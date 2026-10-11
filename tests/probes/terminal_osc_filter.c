/* Checks src/terminal_osc_filter.h against a second, independent implementation
 * that sees the whole stream at once, on random streams cut at random places.
 *
 *     cc -std=c11 -fsanitize=address,undefined -I src -o filter tests/probes/terminal_osc_filter.c
 *     ./filter [cases]
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "terminal_osc_filter.h"

#define MAX_STREAM 40000U

static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;

static uint32_t random_below(uint32_t limit)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)((rng_state >> 11) % limit);
}

/* The rules, written for a complete buffer: after ESC ] 3008 ; read up to BODY_MAX
 * printable bytes; BEL or ESC \ ends the string and drops it; a control byte, an
 * ESC followed by something else, or a longer string cancels it, and reading goes
 * on from the byte that cancelled it. A string still open at the end is dropped. */
static size_t reference(const unsigned char *in, size_t size, unsigned char *out)
{
    size_t kept = 0;
    size_t i = 0;

    while (i < size) {
        size_t k;
        size_t body;

        if (in[i] != 0x1b || size - i < 7 || memcmp(in + i, "\x1b]3008;", 7) != 0) {
            out[kept++] = in[i++];
            continue;
        }
        body = i + 7;
        for (k = body;; k++) {
            if (k >= size) {              /* open at the end of the stream */
                i = size;
                break;
            }
            if (in[k] == 0x07) {
                i = k + 1;
                break;
            }
            if (in[k] == 0x1b) {
                if (k + 1 >= size) {      /* ESC is the last byte */
                    i = size;
                    break;
                }
                if (in[k + 1] == '\\') {
                    i = k + 2;
                    break;
                }
                i = k;                    /* cancelled; the ESC starts over */
                break;
            }
            if (in[k] < 0x20 || in[k] == 0x7f || k - body >= UURB_OSC_FILTER_BODY_MAX) {
                i = k;
                break;
            }
        }
    }
    return kept;
}

static size_t put(unsigned char *stream, size_t used, const void *text, size_t length)
{
    if (used + length > MAX_STREAM)
        return used;
    memcpy(stream + used, text, length);
    return used + length;
}

static size_t put_text(unsigned char *stream, size_t used, const char *text)
{
    return put(stream, used, text, strlen(text));
}

static size_t put_random(unsigned char *stream, size_t used, unsigned int low,
                         unsigned int span, size_t length)
{
    while (length-- > 0 && used < MAX_STREAM)
        stream[used++] = (unsigned char)(low + random_below(span));
    return used;
}

static size_t build_stream(unsigned char *stream)
{
    static const char *const pieces[] = {
        "\x1b]3008;start=1;type=shell\x1b\\",
        "\x1b]3008;end=1;exit=success\x1b\\",
        "\x1b]3008;start=2;type=command;cwd=/tmp\a",
        "\x1b]3008;\x1b\\",
        "\x1b]3008",                 /* no semicolon: not ours */
        "\x1b]300",                  /* partial introducers */
        "\x1b]",
        "\x1b",
        "\x1b\x1b",
        "\x1b]0;a title\a",
        "\x1b]7;file:///tmp\x1b\\",
        "\x1b[31mred\x1b[0m",
        "\x1b[?2004h",
        "\x1b]3008;start=3\nafter a newline",   /* control byte cancels */
        "\x1b]3008;start=4\x1b[Kmore",           /* ESC [ cancels */
        "\x1b]3008;start=5\x1b]3008;end=5\x1b\\", /* ESC ] cancels, then a whole one */
        "\x1b]3008;\x1b]3008;\x1b\\",
        "\x1b]30089;not\x1b\\",
        "plain text\r\n",
        "\\",
        "\a",
        "\xe2\x8d\xb0 utf-8 \xe2\x9c\x93",
        "\x1b]3008;user=\xe2\x8d\xb0;cwd=/h\xc3\xb6me\x1b\\",
    };
    size_t used = 0;
    unsigned int count = 1 + random_below(40);

    while (count-- > 0 && used < MAX_STREAM) {
        unsigned int pick = random_below(12);

        if (pick < 7) {
            used = put_text(stream, used, pieces[random_below(sizeof(pieces) / sizeof(pieces[0]))]);
        } else if (pick == 7) {
            used = put_random(stream, used, 0, 256, 1 + random_below(40));
        } else if (pick == 8) {
            used = put_random(stream, used, 0x20, 0x5f, 1 + random_below(200));
        } else if (pick == 9) {
            /* a string around the length limit */
            size_t length = UURB_OSC_FILTER_BODY_MAX - 2 + random_below(5);
            static const char *const endings[] = {"\x1b\\", "\a", "", "\n"};

            used = put_text(stream, used, "\x1b]3008;");
            used = put_random(stream, used, 0x20, 0x5e, length);
            used = put_text(stream, used, endings[random_below(4)]);
            used = put_text(stream, used, "tail");
        } else {
            used = put_text(stream, used, "\x1b]3008;");
            used = put_random(stream, used, 0x20, 0x5e, random_below(300));
            used = put_text(stream, used, random_below(2) ? "\x1b\\" : "\a");
        }
    }
    return used;
}

/* Runs the filter over `stream` cut into pieces of 1..`largest` bytes. */
static size_t stream_filter(const unsigned char *stream, size_t size,
                            unsigned int largest, unsigned char *out)
{
    struct uurb_osc_filter filter;
    size_t kept = 0;
    size_t at = 0;

    memset(&filter, 0, sizeof(filter));
    while (at < size) {
        size_t piece = largest == 0 ? size - at : 1 + random_below(largest);
        unsigned char *buffer;
        unsigned char *copy;

        if (piece > size - at)
            piece = size - at;
        /* Heap copies of exactly the right size let AddressSanitizer see any
         * read or write past the end. */
        copy = malloc(piece);
        buffer = malloc(piece + UURB_OSC_FILTER_HELD_MAX);
        if (copy == NULL || buffer == NULL)
            abort();
        memcpy(copy, stream + at, piece);
        {
            size_t written = uurb_osc_filter_run(&filter, copy, piece, buffer);

            memcpy(out + kept, buffer, written);
            kept += written;
        }
        free(copy);
        free(buffer);
        at += piece;
    }
    {
        unsigned char held[UURB_OSC_FILTER_HELD_MAX];
        size_t released = uurb_osc_filter_flush(&filter, held);

        memcpy(out + kept, held, released);
        kept += released;
    }
    return kept;
}

static void fail(unsigned int round, const char *what, const unsigned char *stream, size_t size)
{
    size_t i;

    fprintf(stderr, "FAIL case %u: %s\n  stream (%zu bytes):", round, what, size);
    for (i = 0; i < size && i < 160; i++)
        fprintf(stderr, " %02x", stream[i]);
    fprintf(stderr, "%s\n", size > 160 ? " ..." : "");
    exit(1);
}

static void check_known_streams(void)
{
    struct {
        const char *input;
        size_t input_size;
        const char *expected;
        size_t expected_size;
    } const known[] = {
#define CASE(in, out) {in, sizeof(in) - 1, out, sizeof(out) - 1}
        CASE("a\x1b]3008;start=x;type=shell\x1b\\b", "ab"),
        CASE("a\x1b]3008;end=x;exit=success\ab", "ab"),
        CASE("\x1b]3008;start=x\x1b\\\x1b]3008;end=x\x1b\\", ""),
        CASE("\x1b]0;title\a\x1b[31mx", "\x1b]0;title\a\x1b[31mx"),
        CASE("\x1b]300", "\x1b]300"),
        CASE("\x1b]3008", "\x1b]3008"),
        CASE("\x1b", "\x1b"),
        CASE("\x1b]3008;start=x\nline", "\nline"),
        CASE("\x1b]3008;start=x\x1b[Kk", "\x1b[Kk"),
#undef CASE
    };
    unsigned char out[256];
    size_t i;
    unsigned int largest;

    for (i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
        for (largest = 0; largest <= 3; largest++) {
            size_t kept = stream_filter((const unsigned char *)known[i].input,
                                        known[i].input_size, largest, out);

            if (kept != known[i].expected_size ||
                memcmp(out, known[i].expected, kept) != 0)
                fail((unsigned int)i, "known stream", (const unsigned char *)known[i].input,
                     known[i].input_size);
        }
    }
}

/* The length of a string literal, counted by the compiler. */
#define RUN(filter, literal, out) \
    uurb_osc_filter_run((filter), (const unsigned char *)(literal), sizeof(literal) - 1, (out))

static void check_flush_and_release(void)
{
    struct uurb_osc_filter filter;
    unsigned char out[32];
    size_t kept;

    memset(&filter, 0, sizeof(filter));
    /* "ESC ] 3 0" is held back until it is clear what it is ... */
    kept = RUN(&filter, "ab\x1b]30", out);
    if (kept != 2 || !uurb_osc_filter_holding(&filter))
        fail(0, "a possible introducer must be held back", out, kept);
    /* ... and then it is either a sequence ... */
    kept = RUN(&filter, "08;start=x\x1b\\z", out);
    if (kept != 1 || out[0] != 'z' || uurb_osc_filter_holding(&filter))
        fail(1, "a sequence split inside its introducer must be removed", out, kept);
    /* ... or something else, which must come back whole, in order. */
    kept = RUN(&filter, "\x1b]30", out);
    kept += RUN(&filter, "1;q", out + kept);
    if (kept != 7 || memcmp(out, "\x1b]301;q", 7) != 0)
        fail(2, "held bytes must be released in front of what follows", out, kept);
    /* An idle shell releases a lone ESC at once. */
    kept = RUN(&filter, "\x1b", out);
    if (kept != 0 || !uurb_osc_filter_holding(&filter))
        fail(3, "a lone ESC is held back", out, kept);
    kept = uurb_osc_filter_flush(&filter, out);
    if (kept != 1 || out[0] != 0x1b || uurb_osc_filter_holding(&filter) ||
        uurb_osc_filter_flush(&filter, out) != 0)
        fail(4, "flush must release the held ESC exactly once", out, kept);
}

int main(int argc, char **argv)
{
    unsigned int cases = argc > 1 ? (unsigned int)strtoul(argv[1], NULL, 10) : 20000;
    unsigned char *stream = malloc(MAX_STREAM);
    unsigned char *expected = malloc(MAX_STREAM);
    unsigned char *actual = malloc(MAX_STREAM + UURB_OSC_FILTER_HELD_MAX + 16);
    unsigned int round;

    if (stream == NULL || expected == NULL || actual == NULL)
        return 2;
    check_known_streams();
    check_flush_and_release();
    for (round = 0; round < cases; round++) {
        size_t size = build_stream(stream);
        size_t want = reference(stream, size, expected);
        unsigned int largest;
        static const unsigned int cuts[] = {0, 1, 2, 7, 64, 4096};

        for (largest = 0; largest < sizeof(cuts) / sizeof(cuts[0]); largest++) {
            size_t got = stream_filter(stream, size, cuts[largest], actual);

            if (got != want || memcmp(actual, expected, want) != 0)
                fail(round, "streamed output differs from the whole-buffer reference",
                     stream, size);
            if (got > size)
                fail(round, "the filter must never add bytes", stream, size);
        }
    }
    printf("ok: %u random streams, 6 cut sizes each, plus the fixed cases\n", cases);
    free(stream);
    free(expected);
    free(actual);
    return 0;
}
