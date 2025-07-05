/******************************************************************************
*
* Copyright (c) 2013 TP-LINK Technologies CO.,LTD.
* All rights reserved.
*
* FILE NAME  :   memtest.c	
* VERSION    :   1.0
* DESCRIPTION:   This file is used for the memory testing when factoring test
*
* 01	1/11/2013	zj	create
* 02	4/11/2013	zj	annotation added
******************************************************************************/
#include <rt_mmap.h>
#include <configs/rt2880.h>
#include <common.h>
#include "memtest.h"

#include "spi_api.h"
#include "led.h"

#define RT2880_MYREG(x)		(*((volatile u8 *)(x)))


#define MEMTEST_ORDER_ADDR	PHYS_FLASH_START+0x31100

#define MEMTEST_ORDER_SUCCESS	0xcc
#define MEMTEST_ORDER_FAILED	0xbc
#define MEMTEST_ORDER_START		0xaa


#define SDRAM_MAX_SIZE			0x02000000

typedef volatile unsigned int vu32;


int do_my_mem_test(void)
{
	int rcode = 0;
	
	vu_long * start = (ulong *)(CFG_MEMTEST_START);
	vu_long * end = (ulong *)(CFG_MEMTEST_END);
	vu_long * addr;
	ulong val;
	ulong readback;
	static const ulong patterns[] = {
		0x00000000, 
		0xffffffff, 
		0xaaaaaaaa, 
		0x55555555, 
	};

	
	ulong pattern = 0x00000000;
	
	ulong incr = 1;
	int iter = 100;
	for( ; iter-- ; ) 
	{
		if (ctrlc()) {
			putc ('\n');
			return 1;
		}
		printf ("\rPattern %08lX  Writing..."
			"%12s"
			"\b\b\b\b\b\b\b\b\b\b",
			pattern, "");

		for (addr=start,val=pattern; addr<end; addr++) 
		{
			*addr = val;
			val  += incr;
		}

		puts ("Reading...");

		for (addr=start,val=pattern; addr<end; addr++) 
		{
			readback = *addr;
			if (readback != val) {
				printf ("\nMem error @ 0x%08X: "
					"found %08lX, expected %08lX\n",
					(uint)addr, readback, val);
				rcode = 1;
			}	
			val += incr;
		}

		/*
		 * Flip the pattern each time to make lots of zeros and
		 * then, the next time, lots of ones.  We decrement
		 * the "negative" patterns and increment the "positive"
		 * patterns to preserve this feature.
		 */
		if(pattern & 0x80000000) 
			pattern = -pattern;	/* complement & increment */
		else
			pattern = ~pattern;
		
		printf("pattern is:0x%08x\n", pattern);
		incr = -incr;
	}
	
	return rcode;
}



void start_memory_test(void)
{
	u8 order = RT2880_MYREG(MEMTEST_ORDER_ADDR);

	if( order == MEMTEST_ORDER_SUCCESS )		//test pass
	{
		printf("\nMem Test Pass\n");
		return ;
	}
	else if( order == MEMTEST_ORDER_START )	//test start
	{
		printf("MemTest start...\n");
		light_red_led();
		//start memtest here
		int mTestSucceed = !do_my_mem_test();
		u8 ret =  mTestSucceed ? MEMTEST_ORDER_SUCCESS : MEMTEST_ORDER_FAILED;

		raspi_erase_write(&ret, MEMTEST_ORDER_ADDR - PHYS_FLASH_START, sizeof(ret));

		printf("MemTest recheck: 0x%02x\n", RT2880_MYREG(MEMTEST_ORDER_ADDR));
		light_green_led();
		udelay(100);
		light_off();
		return;
	}
	printf("\nunknow define order: 0x%02x\n", order);
	return ;
	
}


/**********************************************************************
 *
 * Function:    TestDataBus()
 *
 * Description: Test the data bus wiring in a memory region by
 *              performing a walking 1's test at a fixed address
 *              within that region.  stuck high, stuck low and any shorted
 *              lines can be identified.
 *
 * Inputs:      
 * Outputs:     test pattern, actual value and error lines
 *
 * Returns:     0 if the test succeeds. 
 *                  1 if the test fails.
 *
 **********************************************************************/
int TestDataBus (unsigned int *errline, u32 *expected, u32 *actual)
{
    vu32    *addr;
    u32    val;
    u32    readback;
   
    unsigned int lineindex;
   
    addr = CFG_MEMTEST_START;
   
    /* stuck high test, all 0 */
    *addr = 0;
    readback = *addr;
    if(readback != 0)
	{
	    *expected = 0;
	    *actual = readback;
	    printf ("Data bus stuck high test fail: expected 0x%08lx, actual 0x%08lx/n", *expected, *actual);
	    return 1;
    }

    /* stuck low test, all 1 */
    *addr = ~(int)0;
    readback = *addr;
    if(readback != ~(int)0)
	{
	    *expected = ~(int)0;
	    *actual = readback;
	    printf ("Data bus stuck low test fail: expected 0x%08lx, actual 0x%08lx/n", *expected, *actual);
	    return 1;
    }

    /* shorten test */
    for(lineindex = 0, val = 1; val != 0; val <<= 1, lineindex++)
	{
        /* walking 1 */
        *addr  = val;
        readback = *addr;

        if(readback != val)
		{
	        *expected = val;
	        *actual = readback;
	        *errline = lineindex;
	        printf ("Shorted at data line %d: expected 0x%08lx, actual 0x%08lx/n", lineindex, val, readback);
	        return 1;
        }

        /* walking 0 */       
        *addr  = ~val;
        readback = *addr;
        if(readback != ~val)
		{
	        *expected = val;
	        *actual = readback;
	        *errline = lineindex;
	        printf ("Shorted at data line %d: expected 0x%08lx, actual 0x%08lx/n", lineindex, val, readback);
	        return 1;
        }
    }
}

/**********************************************************************
 *
 * Function:    TestAddressBus()
 *
 * Description: Test the address bus wiring in a memory region by
 *              performing a walking 1's test on the relevant bits
 *              of the address and checking for aliasing. This test
 *              will find single-bit address failures such as stuck
 *              -high, stuck-low, and shorted pins.
 *
 * Notes:       For best results, the selected base address should
 *              have enough LSB 0's to guarantee single address bit
 *              changes.  For example, to test a 64-Kbyte region,
 *              select a base address on a 64-Kbyte boundary.  Also,
 *              select the region size as a power-of-two--if at all
 *              possible.
 *
 * Inputs:      
 * Outputs:     test pattern, actual value and error lines and address
 *
 * Returns:     0 if the test succeeds. 
 *                  1 if the test fails.
 *
 * ## NOTE ##    Be sure to specify start and end
 *              addresses such that addr_mask has
 *              lots of bits set. For example an
 *              address range of 01000000 02000000 is
 *              bad while a range of 01000000
 *              01ffffff is perfect.
 **********************************************************************/

int TestAddressBus (u32 *erraddr,unsigned int *errline, u32 *expected, u32 *actual)
{
    vu32     *start, *end;
    vu32     addr_mask;
    vu32     offset;
    vu32     test_offset;
    vu32     pattern;
    vu32     temp;
    vu32     anti_pattern;
    unsigned int lineindex;


    start = (u32 *)(CFG_SDRAM_BASE + (SDRAM_MAX_SIZE >> 1));
    end = (u32 *)(CFG_SDRAM_BASE + SDRAM_MAX_SIZE - 1);

    printf ("Testing addr range: 0x%.8lx ... 0x%.8lx:/n", start, end);

    addr_mask = ((unsigned int)end - (unsigned int)start)/sizeof(vu32 );
    pattern = (vu32 ) 0xaaaaaaaa;
    anti_pattern = (vu32 ) 0x55555555;

    printf("addr mask = 0x%.8lx/n", addr_mask);

    /* Write the default pattern at each of the  logical power-of-two offsets.*/
    for (offset = 1; (offset & addr_mask) != 0; offset <<= 1) {
        start[offset] = pattern;
    }

    /* Check for address bits stuck high or shorted if 0 and 1 gets 0.*/
    test_offset = 0;
    start[test_offset] = anti_pattern;
    lineindex = 2;
    for (offset = 1; (offset & addr_mask) != 0; offset <<= 1, lineindex++) {
        temp = start[offset];
        if (temp != pattern) {
            printf ("FAILURE at address 0x%08lx, bit %d: expected 0x%08lx, actual 0x%08lx/n", &start[offset], lineindex, pattern, temp);
            *expected = pattern;
            *actual = temp;
            *errline = lineindex;
            *erraddr = &start[offset];
            return 1;
        }
    }

    start[test_offset] = pattern;
    /* Now pattern at all logical power-of-two offsets and base */

    /* Check for addr bits stuck low or shorted.*/
    for (test_offset = 1; (test_offset & addr_mask) != 0; test_offset <<= 1) {
        start[test_offset] = anti_pattern;

        lineindex = 2;
        /* Check for addr bits stuck low or shorted if 0 and 1 gets 0.*/
        temp = start[0];
        if (temp != pattern) {
            printf ("FAILURE at address 0x%08lx, bit %d: expected 0x%08lx, actual 0x%08lx/n", &start[offset], lineindex, pattern, temp);
            *expected = pattern;
            *actual = temp;
            *errline = lineindex;
            *erraddr = &start[offset];
            return 1;
        }

        /* Check for addr bits shorted no matter what 0 and 1 gets when connected.*/
        for (offset = 1; (offset & addr_mask) != 0; offset <<= 1, lineindex++) {
            temp = start[offset];
            if ((temp != pattern) && (offset != test_offset)) {
                printf ("FAILURE at address 0x%08lx, bit %d: expected 0x%08lx, actual 0x%08lx/n", &start[offset], lineindex, pattern, temp);
                *expected = pattern;
                *actual = temp;
                *errline = lineindex;
                *erraddr = &start[offset];
                return 1;
            }
        }

        /* restore pattern at all logical power-of-two offsets */
        start[test_offset] = pattern;
    }

    return 0;

}

/**********************************************************************
 *
 * Function:    TestIntegrity()
 *
 * Description: Test the integrity of a physical memory device by
 *              performing an increment/decrement test over the
 *              entire region.  In the process every storage bit
 *              in the device is tested as a zero and a one.  The
 *              base address and the size of the region are
 *              selected by the caller.
 *
 * Notes:      
 *
 * Inputs:      start addr and end addr
 * Outputs:     test pattern, actual value, error address
 *
 * Returns:     0 if the test succeeds. 
 *                  1 if the test fails.
 *
 **********************************************************************/
int TestIntegrity (unsigned int *erraddr, unsigned int *expected, unsigned int *actual, vu32  *start, vu32  *end)
{
    vu32     offset;
    vu32     pattern;
    vu32     temp;
    vu32     anti_pattern;
    u32     num_words;

    printf ("Testing integrity: 0x%08x ... 0x%08x:/n", start, end);

    num_words = ((unsigned int)end - (unsigned int)start)/sizeof(u32) + 1;

    /* Fill memory with a known pattern.*/
    for (pattern = 1, offset = 0; offset < num_words; pattern++, offset++) {
        start[offset] = pattern;
    }

    /* Check each location and invert it for the second pass. */
    for (pattern = 1, offset = 0; offset < num_words; pattern++, offset++)
	{
        temp = start[offset];
        if (temp != pattern) 
		{
            printf ("FAILURE at address 0x%08lx: expected 0x%08lx, actual 0x%08lx/n", &start[offset], pattern, temp);
            *expected = pattern;
            *actual = temp;
            *erraddr = &start[offset];
            return 1;
        }

        anti_pattern = ~pattern;
        start[offset] = anti_pattern;
    }


    /* Check each location for the inverted pattern and zero it.*/
    for (pattern = 1, offset = 0; offset < num_words; pattern++, offset++) 
	{
        anti_pattern = ~pattern;
        temp = start[offset];
        if (temp != anti_pattern)
		{
            printf ("FAILURE at address 0x%08lx: expected 0x%08lx, actual 0x%08lx/n", &start[offset], anti_pattern, temp);
            *expected = anti_pattern;
            *actual = temp;
            *erraddr = &start[offset];
            return 1;
        }

        start[offset] = 0;
    }

    return 0;

}

