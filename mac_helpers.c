/**
 * @brief Some useful C functions to manage mac addresses
 * @file
 */

#include <stdio.h>
#include <inttypes.h>
#include <limits.h>

/** Convert hex mac address to uint64_t
 *  @param[in] hwaddr hex mac address
 *  @return mac address as uint64_t
 */
uint64_t mac2int(const uint8_t hwaddr[])
{
    int8_t i;
    uint64_t ret = 0;
    const uint8_t *p = hwaddr;

    for (i = 5; i >= 0; i--) {
        ret |= (uint64_t) *p++ << (CHAR_BIT * i);
    }

    return ret;
}

/** Convert uint64_t mac address to hex
 * @param[in] mac uint64_t mac address
 * @param[out] hwaddr hex mac address
 */
void int2mac(const uint64_t mac, uint8_t *hwaddr)
{
    int8_t i;
    uint8_t *p = hwaddr;

    for (i = 5; i >= 0; i--) {
        *p++ = mac >> (CHAR_BIT * i);
    }
}