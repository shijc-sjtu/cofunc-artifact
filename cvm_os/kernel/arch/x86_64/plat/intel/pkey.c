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

/*
 * This file is used for configuring Intel MPK memory domains.
 */

#include <arch/mm/page_table.h>
#include <mm/mm.h>
#include <mm/vmspace.h>
#include <mm/kmalloc.h>
#include <common/kprint.h>
#include <common/macro.h>
#include <common/types.h>
#include <common/errno.h>

/*
 * Pkey only takes effect on the last level page table page (pte)
 * which points to some physical page.
 *
 */
static void pte_set_domain(pte_t *entry, int domid)
{
	/* the pkey in pte_2M or pte_1G are same with pte_4K */
	entry->pte_4K.pkey = domid;
}

#ifdef CHCORE

//#define PCID_RMASK (0xfffUL)
//#define remove_pcid(x) (void *)(((u64)pgtbl) & (~PCID_RMASK))
//#define get_pcid(x) (((u64)pgtbl) & (PCID_RMASK))

/*
 * Function pkey_protect will modify page table entries.
 * However, it does not flush tlb.
 * The caller should flush tlb by using the most efficient way
 * (e.g., single flush or batch flush).
 */
int pkey_protect(struct vmspace *vmspace, vaddr_t va, size_t len, int domain_id)
{
	void *pgtbl;

	s64 total_page_cnt;
	ptp_t *l0_ptp, *l1_ptp, *l2_ptp, *l3_ptp;
	pte_t *pte;
	pte_t *entry;
	int ret;
	int pte_index; /* the index of pte in the last level page table */
	int i;

	/* va should be page aligned: which is done in vmspace_map_range */
	BUG_ON(va % PAGE_SIZE);

	/* root page table page must exist */
	pgtbl = vmspace->pgtbl;
	BUG_ON(pgtbl == NULL);
	l0_ptp = (ptp_t *)remove_pcid(pgtbl);
	l1_ptp = NULL;
	l2_ptp = NULL;
	l3_ptp = NULL;

	total_page_cnt = len / PAGE_SIZE + (((len % PAGE_SIZE) > 0) ? 1 : 0);

	while (total_page_cnt > 0) {
		// l0
		ret = get_next_ptp(l0_ptp, 0, va, &l1_ptp, &pte, false, NULL);
		if (ret != 0) printk("ret: %d\n", ret);
		BUG_ON(ret != 0);

		// l1
		ret = get_next_ptp(l1_ptp, 1, va, &l2_ptp, &pte, false, NULL);
		if (ret != 0) printk("ret: %d\n", ret);
		BUG_ON(ret != 0);

		// l2
		ret = get_next_ptp(l2_ptp, 2, va, &l3_ptp, &pte, false, NULL);
		BUG_ON(ret != 0);

		// l3
		// step-1: get the index of pte
		pte_index = GET_L3_INDEX(va);
		for (i = pte_index; i < PTP_ENTRIES; ++i) {

			entry = &(l3_ptp->ent[i]);
			/* set domain id (pkey) */
			pte_set_domain(entry, domain_id);

			va += PAGE_SIZE;
			total_page_cnt -= 1;
			if (total_page_cnt == 0)
				break;
		}

	}

	return 0;
}

#endif
