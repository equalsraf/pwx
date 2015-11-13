//
// Some sanity checks to make sure the rust bindings are not
// making wrong assumption
//
#include "twofish.h"

// STATIC_ASSERT, do check the full and interesting read at
// http://www.pixelbeat.org/programming/gcc/static_assert.html

#define ASSERT_CONCAT_(a, b) a##b
#define ASSERT_CONCAT(a, b) ASSERT_CONCAT_(a, b)
/* These can't be used after statements in c89. */
#ifdef __COUNTER__
  #define STATIC_ASSERT(e,m) \
    ;enum { ASSERT_CONCAT(static_assert_, __COUNTER__) = 1/(!!(e)) }
#else
  /* This can't be used twice on the same line so ensure if using in headers
   * that the headers are not included twice (by wrapping in #ifndef...#endif)
   * Note it doesn't cause an issue when used on same line of separate modules
   * compiled with gcc -combine -fwhole-program.  */
  #define STATIC_ASSERT(e,m) \
    ;enum { ASSERT_CONCAT(assert_line_, __LINE__) = 1/(!!(e)) }
#endif

// Make sure we are allocating enough memory for Twofish_key
STATIC_ASSERT(sizeof(Twofish_key) <= 4256, "Twofish_key size is broken in your platform, this is a BUG, please report it");

