#ifndef UURB_TERMINAL_OSC_FILTER_H
#define UURB_TERMINAL_OSC_FILTER_H

#include <stddef.h>
#include <string.h>

/* Removes OSC 3008 ("hierarchical context signalling", UAPI.15) from the
 * output of the shell before it reaches the viewer. Ubuntu 26.04 (systemd
 * 258+) makes every interactive bash print
 *
 *     ESC ] 3008 ; start=<id> ; ... ESC \      and      ESC ] 3008 ; end=<id> ; ... ESC \
 *
 * around each prompt and command. UU's terminal does not know the sequence and
 * shows it as text. A terminal that does not know an OSC string drops it
 * silently, so this does the same for the one OSC string known to be sent.
 * Every other sequence passes through untouched.
 *
 * The filter keeps its state between calls, because a sequence can be split
 * across two reads of the pseudo-terminal. It follows the usual rules for an
 * OSC string: it ends at ST (ESC \) or BEL; an ESC followed by anything else,
 * or any other control character, cancels it and is then read as ordinary
 * output, so a damaged sequence cannot swallow the rest of the session. The
 * specification allows only printable characters inside the string. */

#define UURB_OSC_FILTER_HELD_MAX 6U   /* the introducer without its last byte */
#define UURB_OSC_FILTER_BODY_MAX 8192U

enum uurb_osc_filter_state {
    UURB_OSC_NORMAL = 0,
    UURB_OSC_INTRODUCER,   /* matched 1..HELD_MAX bytes of ESC ] 3 0 0 8 ; */
    UURB_OSC_BODY,         /* inside the string, dropping it */
    UURB_OSC_BODY_ESCAPE,  /* inside the string, just after an ESC */
};

struct uurb_osc_filter {
    enum uurb_osc_filter_state state;
    unsigned int matched;
    unsigned int swallowed;
};

static const unsigned char uurb_osc_introducer[UURB_OSC_FILTER_HELD_MAX + 1] =
    {0x1b, ']', '3', '0', '0', '8', ';'};

/* Filters `size` bytes into `output`, which must hold `size` plus
 * UURB_OSC_FILTER_HELD_MAX bytes (bytes held back from the previous call may be
 * released in front of this one). Returns the number of bytes written. The tail
 * of `input` that could still turn out to start a sequence is held back; see
 * uurb_osc_filter_flush(). */
static inline size_t uurb_osc_filter_run(struct uurb_osc_filter *filter,
                                         const unsigned char *input, size_t size,
                                         unsigned char *output)
{
    size_t kept = 0;
    size_t index = 0;

    while (index < size) {
        const unsigned char byte = input[index];

        switch (filter->state) {
        case UURB_OSC_NORMAL: {
            const unsigned char *escape =
                (const unsigned char *)memchr(input + index, 0x1b, size - index);
            const size_t plain = escape != NULL ? (size_t)(escape - (input + index))
                                                : size - index;

            memcpy(output + kept, input + index, plain);
            kept += plain;
            index += plain;
            if (escape != NULL) {
                index++;
                filter->state = UURB_OSC_INTRODUCER;
                filter->matched = 1;
            }
            break;
        }
        case UURB_OSC_INTRODUCER:
            if (byte == uurb_osc_introducer[filter->matched]) {
                index++;
                if (++filter->matched == sizeof(uurb_osc_introducer)) {
                    filter->state = UURB_OSC_BODY;
                    filter->swallowed = 0;
                }
            } else {
                /* Not ours after all: give back what was held and read this
                 * byte again as ordinary output. */
                memcpy(output + kept, uurb_osc_introducer, filter->matched);
                kept += filter->matched;
                filter->state = UURB_OSC_NORMAL;
                filter->matched = 0;
            }
            break;
        case UURB_OSC_BODY:
            if (byte == 0x07) {
                filter->state = UURB_OSC_NORMAL;
                index++;
            } else if (byte == 0x1b) {
                filter->state = UURB_OSC_BODY_ESCAPE;
                index++;
            } else if (byte < 0x20 || byte == 0x7f ||
                       filter->swallowed >= UURB_OSC_FILTER_BODY_MAX) {
                /* Cancelled: this byte is ordinary output again. */
                filter->state = UURB_OSC_NORMAL;
            } else {
                filter->swallowed++;
                index++;
            }
            break;
        case UURB_OSC_BODY_ESCAPE:
            if (byte == '\\') {
                filter->state = UURB_OSC_NORMAL;
                index++;
            } else {
                /* The ESC cancelled the string and begins a new sequence. */
                filter->state = UURB_OSC_INTRODUCER;
                filter->matched = 1;
            }
            break;
        }
    }
    return kept;
}

static inline int uurb_osc_filter_holding(const struct uurb_osc_filter *filter)
{
    return filter->state == UURB_OSC_INTRODUCER;
}

/* Releases the bytes held back (at most UURB_OSC_FILTER_HELD_MAX). Call it when
 * the shell has been quiet for a moment: a lone ESC at the end of a read is
 * usually a complete sequence and must not wait for the next byte. */
static inline size_t uurb_osc_filter_flush(struct uurb_osc_filter *filter,
                                           unsigned char *output)
{
    size_t held = 0;

    if (filter->state == UURB_OSC_INTRODUCER) {
        held = filter->matched;
        memcpy(output, uurb_osc_introducer, held);
        filter->state = UURB_OSC_NORMAL;
        filter->matched = 0;
    }
    return held;
}

#endif
