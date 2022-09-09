/*
 ******************************************************************************
 *                                   mm.c                                     *
 *           64-bit struct-based implicit free list memory allocator          *
 *                  15-213: Introduction to Computer Systems                  *
 *                                                                            *
 *  ************************************************************************  *
 *                  TODO: insert your documentation here. :)                  *
 *  This is an implementation of dynamic memory allocator.                    *
 *  It uses segregated lists to keep track of free blocks.                    *
 *  Block structure contains a header and a payload union.                    *
 *  Header consists of block size and allocated flag.                         *
 *  Union consists of data when block is alloctaed.                           *
 *  Union consists of pointers to next and previous blocks when not allocated.*
 *                                                                            *  
 *  Hints refered from:                                                       *
 *  https://gist.github.com/Ulu2005/906a10d5f5af6101e689                      *  
 *  https://powcoder.com/2019/11/20/代写-c-data-structure-algorithm-html-scala *
 *  -shell-compiler-cse-361-fall-2019/                                        *
 *  Washington university CSE361 course website.                              *                        
 *  ************************************************************************  *
 *  ** ADVICE FOR STUDENTS. **                                                *
 *  Step 0: Please read the writeup!                                          *
 *  Step 1: Write your heap checker. Write. Heap. checker.                    *
 *  Step 2: Place your contracts / debugging assert statements.               *
 *  Good luck, and have fun!                                                  *
 *                                                                            *
 ******************************************************************************
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include <stddef.h>
#include <unistd.h>
#include <inttypes.h>

#include "mm.h"
#include "memlib.h"

/* Do not change the following! */

#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#define memset mem_memset
#define memcpy mem_memcpy
#endif /* def DRIVER */

/* You can change anything from here onward */

/*
 * If DEBUG is defined (such as when running mdriver-dbg), these macros
 * are enabled. You can use them to print debugging output and to check
 * contracts only in debug mode.
 *
 * Only debugging macros with names beginning "dbg_" are allowed.
 * You may not define any other macros having arguments.
 */
#ifdef DEBUG
/* When DEBUG is defined, these form aliases to useful functions */
#define dbg_printf(...)     printf(__VA_ARGS__)
#define dbg_requires(expr)  assert(expr)
#define dbg_assert(expr)    assert(expr)
#define dbg_ensures(expr)   assert(expr)
#define dbg_printheap(...)  print_heap(__VA_ARGS__)
#else
/* When DEBUG is not defined, no code gets generated for these */
/* The sizeof() hack is used to avoid "unused variable" warnings */
#define dbg_printf(...)     (sizeof(__VA_ARGS__), -1)
#define dbg_requires(expr)  (sizeof(expr), 1)
#define dbg_assert(expr)    (sizeof(expr), 1)
#define dbg_ensures(expr)   (sizeof(expr), 1)
#define dbg_printheap(...)  ((void) sizeof(__VA_ARGS__))
#endif

#define NEXTBLOCK block->payload.node.next //next_block_pointer
#define PREVBLOCK block->payload.node.prev //previous_block_pointer
#define THRESH 10 //threshold value for better fit algorithm
#define LISTSIZE 12 //number of segregated lists

/* Basic constants */

typedef uint64_t word_t;

// Word and header size (bytes)
static const size_t wsize = sizeof(word_t);

// Double word size (bytes)
static const size_t dsize = 2 * wsize;

// Minimum block size (bytes)
static const size_t min_block_size = 2 * dsize;

// TODO: explain what chunksize is
// (Must be divisible by dsize)
// All blocks as dsize alligned.
// If heap size is not dsize alligned, 
//excess memory will never be allocated
static const size_t chunksize = (1 << 15);

// TODO: explain what alloc_mask is
// Last bit of header is alloc_mask
static const word_t alloc_mask = 0x1;

// TODO: explain what size_mask is
// mask to extract size from header
static const word_t size_mask = ~(word_t)0xF;


/* Represents the header and payload of one block in the heap */
typedef struct block block_t;
struct block
{
    /* Header contains size + allocation flag */
    word_t header;

    /*
     * TODO: feel free to delete this comment once you've read it carefully.
     * We don't know what the size of the payload will be, so we will declare
     * it as a zero-length array, which is a GCC compiler extension. This will
     * allow us to obtain a pointer to the start of the payload.
     *
     * WARNING: A zero-length array must be the last element in a struct, so
     * there should not be any struct fields after it. For this lab, we will
     * allow you to include a zero-length array in a union, as long as the
     * union is the last field in its containing struct. However, this is
     * compiler-specific behavior and should be avoided in general.
     *
     * WARNING: DO NOT cast this pointer to/from other types! Instead, you
     * should use a union to alias this zero-length array with another struct,
     * in order to store additional types of data in the payload memory.
     */
    union {
        struct {
          block_t *next;
          block_t *prev;
        } node;
        char data[0];
    } payload;

    /*
     * TODO: delete or replace this comment once you've thought about it.
     * Why can't we declare the block footer here as part of the struct?
     * Why do we even have footers -- will the code work fine without them?
     * which functions actually use the data contained in footers?
     * char data will have dynamic size. Hence location of footer in memory
     * cannot be determined while defining the struct.
     */
};


/* Global variables */
static block_t *head = NULL; //pointer to prologue
static block_t *heap_start[LISTSIZE]; //array of all heads of segrated lists
bool is_intialized = false; //flag to check if init function is called
unsigned free_blocks_in_list = 0; //counts free blocks in segrated list

/* Function prototypes for internal helper routines */

bool mm_checkheap(int lineno);

static block_t *extend_heap(size_t size);
static block_t *find_fit(size_t asize);
static block_t *coalesce_block(block_t *block);
static void split_block(block_t *block, size_t asize);

static size_t max(size_t x, size_t y);
static size_t round_up(size_t size, size_t n);
static word_t pack(size_t size, bool alloc);

static size_t extract_size(word_t header);
static size_t get_size(block_t *block);
static size_t get_payload_size(block_t *block);

static bool extract_alloc(word_t header);
static bool get_alloc(block_t *block);

static void write_header(block_t *block, size_t size, bool alloc);
static void write_footer(block_t *block, size_t size, bool alloc);

static block_t *payload_to_header(void *bp);
static void *header_to_payload(block_t *block);
static word_t *header_to_footer(block_t *block);

static block_t *find_next(block_t *block);
static word_t *find_prev_footer(block_t *block);
static block_t *find_prev(block_t *block);

static unsigned get_list(size_t size);
static void insert(block_t *block);
static void delete(block_t *block);



/*
 * Initializes the heap
 * no arguments
 * returns bool. true is succesful.
 * 
 */
bool mm_init(void)
{
    // Create the initial empty heap
    word_t *start = (word_t *) (mem_sbrk(2 * wsize));

    if (start == (void *)-1)
    {
        return false;
    }

    /*
     * TODO: delete or replace this comment once you've thought about it.
     * Think about why we need a heap prologue and epilogue. Why do
     * they correspond to a block footer and header respectively?
     */

    start[0] = pack(0, true);  // Heap prologue (block footer)
    start[1] = pack(0, true);  // Heap epilogue (block header)

    // Heap starts with first "block header", currently the epilogue
    head = (block_t *) &(start[1]);
    
    for (unsigned i = 0; i < LISTSIZE; i++)
        heap_start[i] = NULL;

    // Extend the empty heap with a free block of chunksize bytes
    if (extend_heap(chunksize) == NULL)
    {
        return false;
    }
    is_intialized = true;
    return true;
}


/*
 * Assigns memory in the heap of given size.
 * Argument is required memory size
 * Returns generic pointer to memory block
 * 
 */
void *malloc(size_t size)
{
    dbg_requires(mm_checkheap(__LINE__));

    size_t asize;      // Adjusted block size
    size_t extendsize; // Amount to extend heap if no fit is found
    block_t *block;
    void *bp = NULL;

    if (!is_intialized) // Initialize heap if it isn't initialized
    {
        mm_init();
    }

    if (size == 0) // Ignore spurious request
    {
        dbg_ensures(mm_checkheap(__LINE__));
        return bp;
    }

    // Adjust block size to include overhead and to meet alignment requirements
    asize = round_up(size + dsize, dsize);

    // Search the free list for a fit
    block = find_fit(asize);

    // If no fit is found, request more memory, and then and place the block
    if (block == NULL)
    {
        // Always request at least chunksize
        extendsize = max(asize, chunksize);
        block = extend_heap(extendsize);
        if (block == NULL) // extend_heap returns an error
        {
            return bp;
        }

    }

    // The block should be marked as free
    dbg_assert(!get_alloc(block));

    // Mark block as allocated
    size_t block_size = get_size(block);
    write_header(block, block_size, true);
    write_footer(block, block_size, true);

    // Try to split the block if too large
    split_block(block, asize);

    bp = header_to_payload(block);

    dbg_ensures(mm_checkheap(__LINE__));
    return bp;
}


/*
 * Returs the memory block to segrated list
 * Argument is block to free
 * Return nothing
 * Argument block must be allocated
 */
void free(void *bp)
{
    dbg_requires(mm_checkheap(__LINE__));

    if (bp == NULL)
    {
        return;
    }

    block_t *block = payload_to_header(bp);
    size_t size = get_size(block);

    // The block should be marked as allocated
    dbg_assert(get_alloc(block));

    // Mark the block as free
    write_header(block, size, false);
    write_footer(block, size, false);

    // Try to coalesce the block with its neighbors
    block = coalesce_block(block);

    dbg_ensures(mm_checkheap(__LINE__));
}


/*
 * Reassigns memory in the heap of atleast given size.
 * Argument is required memory size and memory block.
 * Returns generic pointer to memory block
 * 
 */
void *realloc(void *ptr, size_t size)
{
    block_t *block = payload_to_header(ptr);
    size_t copysize;
    void *newptr;

    // If size == 0, then free block and return NULL
    if (size == 0)
    {
        free(ptr);
        return NULL;
    }

    // If ptr is NULL, then equivalent to malloc
    if (ptr == NULL)
    {
        return malloc(size);
    }

    // Otherwise, proceed with reallocation
    newptr = malloc(size);

    // If malloc fails, the original block is left untouched
    if (newptr == NULL)
    {
        return NULL;
    }

    // Copy the old data
    copysize = get_payload_size(block); // gets size of old payload
    if (size < copysize)
    {
        copysize = size;
    }
    memcpy(newptr, ptr, copysize);

    // Free the old block
    free(ptr);

    return newptr;
}


/*
 * Assigns memory block will writing the memory to 0.
 * Argument is element size and required memory size.
 * Returns generic pointer to memory block
 * 
 */
void *calloc(size_t elements, size_t size)
{
    void *bp;
    size_t asize = elements * size;

    if (asize/elements != size)
    {
        // Multiplication overflowed
        return NULL;
    }

    bp = malloc(asize);
    if (bp == NULL)
    {
        return NULL;
    }

    // Initialize all bits to 0
    memset(bp, 0, asize);

    return bp;
}


/******** The remaining content below are helper and debug routines ********/

/*
 * Creates space on the heap.
 * Argument size by which the heap should be extended.
 * Returns a block pointer to the new memory.
 *
 */
static block_t *extend_heap(size_t size)
{
    void *bp;

    if ((bp = mem_sbrk(size)) == (void *)-1)
    {
        return NULL;
    }

    /*
     * TODO: delete or replace this comment once you've thought about it.
     * Think about what bp represents. Why do we write the new block
     * starting one word BEFORE bp, but with the same size that we
     * originally requested?
     * we need to move epilogue to the end of the heap.
     * hence this epilogue space is used up by the block.
     */

    // Initialize free block header/footer
    block_t *block = payload_to_header(bp);
    write_header(block, size, false);
    write_footer(block, size, false);

    // Create new epilogue header
    block_t *block_next = find_next(block);
    write_header(block_next, 0, true);

    // Coalesce in case the previous block was free
    block = coalesce_block(block);

    return block;
}


/*
 * Merges previous and next free blocks into single block.
 * Argument is pointer to the memort block.
 * Returns pointer to new memory block.
 * 
 */
static block_t *coalesce_block(block_t *block)
{
    dbg_requires(!get_alloc(block));

    size_t size = get_size(block);

    /*
     * TODO: delete or replace this comment once you've thought about it.
     * Think about how we find the prev and next blocks. What information
     * do we need to have about the heap in order to do this? Why doesn't
     * "bool prev_alloc = get_alloc(block_prev)" work properly?
     */

    block_t *block_next = find_next(block);
    block_t *block_prev = find_prev(block);

    bool prev_alloc = extract_alloc(*find_prev_footer(block));
    bool next_alloc = get_alloc(block_next);

    if (prev_alloc && next_alloc)              // Case 1
    {
        insert(block);
    }

    else if (prev_alloc && !next_alloc)        // Case 2
    {
        delete(block_next);
        size += get_size(block_next);
        write_header(block, size, false);
        write_footer(block, size, false);
        insert(block);
    }

    else if (!prev_alloc && next_alloc)        // Case 3
    {
        delete(block_prev);
        size += get_size(block_prev);
        write_header(block_prev, size, false);
        write_footer(block_prev, size, false);
        block = block_prev;
        insert(block);
    }

    else                                        // Case 4
    {
        delete(block_prev);
        delete(block_next);
        size += get_size(block_next) + get_size(block_prev);
        write_header(block_prev, size, false);
        write_footer(block_prev, size, false);
        block = block_prev;
        insert(block);
    }

    dbg_ensures(!get_alloc(block));

    return block;
}


/*
 * Splits a block of block size exceeds data size.
 * Adds free block to the segregated list.
 * Argument pointer to block and payload size.
 * Return nothing
 */
static void split_block(block_t *block, size_t asize)
{
    dbg_requires(get_alloc(block));
    /* TODO: Can you write a precondition about the value of asize? */

    size_t block_size = get_size(block);
    delete(block);

    if ((block_size - asize) >= min_block_size)
    {
        block_t *block_next;
        write_header(block, asize, true);
        write_footer(block, asize, true);

        block_next = find_next(block);
        write_header(block_next, block_size - asize, false);
        write_footer(block_next, block_size - asize, false);
        coalesce_block(block_next);
    }

    dbg_ensures(get_alloc(block));
}


/*
 * Finds the empty block in segrated list for the given size
 * Implements better fit algorithm.
 * Argument is the block size.
 * Returns block pointer to the free memory.
 * 
 */
static block_t *find_fit(size_t asize)
{
    unsigned better_fit_count = 0;
    block_t *block = NULL;
    block_t *best_block = NULL;

    size_t heap_size = mem_heapsize();
    size_t list_index = get_list(asize);

    for (unsigned i = list_index; i < LISTSIZE; i++) {
        block = heap_start[i];
        while(block != NULL) {
            size_t block_size = get_size(block);
            if (asize < block_size) {
                if (better_fit_count++ == THRESH)
                    return best_block;
                if ((block_size - asize) < (heap_size - asize)) {
                    heap_size = block_size;
                    best_block = block;
                }
            } else if (asize == block_size) {
                return block;
            }
            block = NEXTBLOCK;
        }
    }
    return best_block; // no fit found
}


/*
 * Checks heap consistency.
 * Argument is line number from where the function is called.
 * Returns bool. true if no discrepancy found.
 */
bool mm_checkheap(int line)
{
    /*
     * TODO: Delete this comment!
     *
     * You will need to write the heap checker yourself.
     * Please keep modularity in mind when you're writing the heap checker!
     *
     * As a filler: one guacamole is equal to 6.02214086 x 10**23 guacas.
     * One might even call it...  the avocado's number.
     *
     * Internal use only: If you mix guacamole on your bibimbap,
     * do you eat it with a pair of chopsticks, or with a spoon?
     */

    block_t *block;
    unsigned free_blocks_in_heap = 0;

    //check epilogue prologue
    if (*((word_t *)mem_heap_lo()) != pack(0, true)) {
        printf("error: prologue incorrect\n");
        return false;
    }
    if (*((word_t *)mem_heap_hi()) != pack(0, true)) {
        printf("error: epilogue incorrect\n");
        return false;
    }

    //traverse heap
    for (block = head; get_size(block) > 0; block = find_next(block)) {
        //check allignment
        if ((int)header_to_payload % dsize != 0) {
            printf("error: %p not alligned\n", block);
            return false;
        }

        //check free blocks
        if (!get_alloc(block)) {
            free_blocks_in_heap++;
            //check header footer
            if (block->header != *(header_to_footer(block))) {
                printf("error: %p header footer mismatch\n", block);
                return false;
            }

            //check coalesing
            if (find_next(block) && !get_alloc(find_next(block))) {
                printf("error: %p not coalesced\n", block);
                return false;
            }
            if (find_prev(block) && !get_alloc(find_prev(block))) {
                printf("error: %p not coalesced\n", block);
                return true;
            }
        }
    }

    //traverse segragated list
    for (unsigned list_index = 0; list_index < LISTSIZE; list_index++) {
        if (heap_start[list_index] == NULL)
            continue;
        for (block = heap_start[list_index]; block != NULL; block = NEXTBLOCK) {
            //check links
            if (NEXTBLOCK != NULL) {
                if (block != NEXTBLOCK->payload.node.prev) {
                    printf("error: %p links mismatch\n", block);
                    return false;
                }
            }

            //check if correct segregated list
            if (list_index == 0 && get_size(block) > (1 << 6)) {
                printf("error: %p incorrect list\n", block);
                return false;
            } else if (list_index == 11 && get_size(block) <= (1 << 16)) {
                printf("error: %p incorrect list\n", block);
                return false;
            } else if (get_size(block) < (1 << (list_index + 6)) || get_size(block) >= (1 << (list_index + 7))) {
                printf("error: %p incorrect list\n", block);
                return false;
            }
        }
    }

    //free block count
    if (free_blocks_in_list != free_blocks_in_heap) {
        printf("error: free blocks discrepancy\n");
        return false;
    }

    return true;

}


/*
 *****************************************************************************
 * The functions below are short wrapper functions to perform                *
 * bit manipulation, pointer arithmetic, and other helper operations.        *
 *                                                                           *
 * We've given you the function header comments for the functions below      *
 * to help you understand how this baseline code works.                      *
 *                                                                           *
 * Note that these function header comments are short since the functions    *
 * they are describing are short as well; you will need to provide           *
 * adequate details within your header comments for the functions above!     *
 *                                                                           *
 *                                                                           *
 * Do not delete the following super-secret(tm) lines!                       *
 *                                                                           *
 * 53 6f 20 79 6f 75 27 72 65 20 74 72 79 69 6e 67 20 74 6f 20               *
 *                                                                           *
 * 66 69 67 75 72 65 20 6f 75 74 20 77 68 61 74 20 74 68 65 20               *
 * 68 65 78 61 64 65 63 69 6d 61 6c 20 64 69 67 69 74 73 20 64               *
 * 6f 2e 2e 2e 20 68 61 68 61 68 61 21 20 41 53 43 49 49 20 69               *
 *                                                                           *
 * 73 6e 27 74 20 74 68 65 20 72 69 67 68 74 20 65 6e 63 6f 64               *
 * 69 6e 67 21 20 4e 69 63 65 20 74 72 79 2c 20 74 68 6f 75 67               *
 * 68 21 20 2d 44 72 2e 20 45 76 69 6c 0a de ba c1 e1 52 13 0a               *
 *                                                                           *
 *****************************************************************************
 */


/*
 * max: returns x if x > y, and y otherwise.
 */
static size_t max(size_t x, size_t y)
{
    return (x > y) ? x : y;
}


/*
 * round_up: Rounds size up to next multiple of n
 */
static size_t round_up(size_t size, size_t n)
{
    return n * ((size + (n-1)) / n);
}


/*
 * pack: returns a header reflecting a specified size and its alloc status.
 *       If the block is allocated, the lowest bit is set to 1, and 0 otherwise.
 */
static word_t pack(size_t size, bool alloc)
{
    return alloc ? (size | alloc_mask) : size;
}


/*
 * extract_size: returns the size of a given header value based on the header
 *               specification above.
 */
static size_t extract_size(word_t word)
{
    return (word & size_mask);
}


/*
 * get_size: returns the size of a given block by clearing the lowest 4 bits
 *           (as the heap is 16-byte aligned).
 */
static size_t get_size(block_t *block)
{
    return extract_size(block->header);
}


/*
 * get_payload_size: returns the payload size of a given block, equal to
 *                   the entire block size minus the header and footer sizes.
 */
static word_t get_payload_size(block_t *block)
{
    size_t asize = get_size(block);
    return asize - dsize;
}


/*
 * extract_alloc: returns the allocation status of a given header value based
 *                on the header specification above.
 */
static bool extract_alloc(word_t word)
{
    return (bool) (word & alloc_mask);
}


/*
 * get_alloc: returns true when the block is allocated based on the
 *            block header's lowest bit, and false otherwise.
 */
static bool get_alloc(block_t *block)
{
    return extract_alloc(block->header);
}


/*
 * write_header: given a block and its size and allocation status,
 *               writes an appropriate value to the block header.
 * TODO: Are there any preconditions or postconditions?
 * block pointer should not be NULL
 */
static void write_header(block_t *block, size_t size, bool alloc)
{
    dbg_requires(block != NULL);
    block->header = pack(size, alloc);
}


/*
 * write_footer: given a block and its size and allocation status,
 *               writes an appropriate value to the block footer by first
 *               computing the position of the footer.
 * TODO: Are there any preconditions or postconditions?
 * block pointer should not be NULL
 * footer address should not cross heap boundry
 */
static void write_footer(block_t *block, size_t size, bool alloc)
{
    dbg_requires(block != NULL);
    dbg_requires(get_size(block) == size && size > 0);
    word_t *footerp = header_to_footer(block);
    *footerp = block->header;
}


/*
 * find_next: returns the next consecutive block on the heap by adding the
 *            size of the block.
 */
static block_t *find_next(block_t *block)
{
    dbg_requires(block != NULL);
    dbg_requires(get_size(block) != 0);
    return (block_t *) ((char *) block + get_size(block));
}


/*
 * find_prev_footer: returns the footer of the previous block.
 */
static word_t *find_prev_footer(block_t *block)
{
    // Compute previous footer position as one word before the header
    return &(block->header) - 1;
}


/*
 * find_prev: returns the previous block position by checking the previous
 *            block's footer and calculating the start of the previous block
 *            based on its size.
 */
static block_t *find_prev(block_t *block)
{
    dbg_requires(block != NULL);
    dbg_requires(get_size(block) != 0);
    word_t *footerp = find_prev_footer(block);
    size_t size = extract_size(*footerp);
    return (block_t *) ((char *) block - size);
}


/*
 * payload_to_header: given a payload pointer, returns a pointer to the
 *                    corresponding block.
 */
static block_t *payload_to_header(void *bp)
{
    return (block_t *) ((char *) bp - offsetof(block_t, payload.data));
}


/*
 * header_to_payload: given a block pointer, returns a pointer to the
 *                    corresponding payload.
 */
static void *header_to_payload(block_t *block)
{
    return (void *) (block->payload.data);
}


/*
 * header_to_footer: given a block pointer, returns a pointer to the
 *                   corresponding footer.
 */
static word_t *header_to_footer(block_t *block)
{
    return (word_t *) (block->payload.data + get_size(block) - dsize);
}

/*
 * Inserts block at start of appropriate segregated list.
 * Argument is block pointer to be added.
 * Returns nothing.
 */
static void insert(block_t *block) {
    dbg_requires(!get_alloc(block));
    size_t size = get_size(block);
    unsigned list_index = get_list(size);

    NEXTBLOCK = heap_start[list_index];
    PREVBLOCK = NULL;

    if (NEXTBLOCK != NULL)
        heap_start[list_index]->payload.node.prev = block;
    heap_start[list_index] = block;

    free_blocks_in_list++;
}

/*
 * deletes block of appropriate segregated list.
 * Argument is block pointer to be deleted.
 * Returns nothing.
 */
static void delete(block_t *block) {
    dbg_requires(get_alloc(block));
    size_t size = get_size(block);
    unsigned list_index = get_list(size);

    block_t *block_next = NEXTBLOCK;
    block_t *block_prev = PREVBLOCK;

    if (block_prev == NULL) 
        heap_start[list_index] = block_next;
    else
        block_prev->payload.node.next = block_next;

    if (block_next != NULL)
        block_next->payload.node.prev = block_prev;

    free_blocks_in_list--;
}

/*
 * Finds appropriate segregated list for the memory size.
 * Argument memory size.
 * Returns segregated list index.
 */
static unsigned get_list(size_t size) {
    unsigned least = 32;
    for (unsigned count = 0; count < LISTSIZE; count++) {
        if (size <= least)
            return count;
        least *= 2;
    }
    return LISTSIZE - 1;
}



