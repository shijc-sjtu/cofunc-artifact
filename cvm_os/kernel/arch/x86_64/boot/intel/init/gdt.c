/*
 * Copyright (c) 2023 Institute of Parallel And Distributed Systems (IPADS), Shanghai Jiao Tong University (SJTU)
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <seg.h>

struct segdesc __attribute__((aligned(16))) bootgdt[GDT_ENTRIES] = {
	[GDT_NULL] = SEGDESC(0,	/* base */
			     0,	/* base */
			     0	/* bits */
	    ),
	[GDT_CS_32] = SEGDESC(0,	/* base */
			      0xfffff,	/* limit */
			      SEG_R | SEG_CODE | SEG_S | SEG_DPL(0) | SEG_P | SEG_D | SEG_G	/* bits */
	    ),
	[GDT_CS_64] = SEGDESC(0,	/* base */
			      0,	/* limit */
			      SEG_R | SEG_CODE | SEG_S | SEG_DPL(0) | SEG_P | SEG_L | SEG_G	/* bits */
	    ),
	[GDT_DS] = SEGDESC(0,		/* base */
			   0xfffff,	/* limit */
			   SEG_W | SEG_S | SEG_DPL(0) | SEG_P | SEG_D | SEG_G	/* bits */
	    ),
	[GDT_FS] = SEGDESC(0,		/* base */
			   0xfffff,	/* limit */
			   SEG_W | SEG_S | SEG_DPL(0) | SEG_P | SEG_D | SEG_G	/* bits */
	    ),
	[GDT_GS] = SEGDESC(0,		/* base */
			   0xfffff,	/* limit */
			   SEG_W | SEG_S | SEG_DPL(0) | SEG_P | SEG_D | SEG_G	/* bits */
	    ),
	[GDT_UD] = SEGDESC(0,		/* base */
			   0xfffff,	/* limit */
			   SEG_W | SEG_S | SEG_DPL(3) | SEG_P | SEG_D | SEG_G	/* bits */
	    ),
	[GDT_UC] = SEGDESC(0,		/* base */
			   0,		/* limit */
			   SEG_R | SEG_CODE | SEG_S | SEG_DPL(3) | SEG_P | SEG_L | SEG_G	/* bits */
	    ),

	/* set GDT_TSS in kernel main */
};
