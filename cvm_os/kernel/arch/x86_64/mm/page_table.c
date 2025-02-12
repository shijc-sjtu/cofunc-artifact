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

#include <mm/mm.h>
#include <mm/vmspace.h>
#include <mm/kmalloc.h>
#include <mm/common_pte.h>
#include <common/kprint.h>
#include <common/macro.h>
#include <common/types.h>
#include <common/errno.h>
#ifdef CHCORE_PLAT_AMD_SEV
#include <common/bitops.h>
#endif /* CHCORE_PLAT_AMD_SEV */

#include <arch/mm/page_table.h>
#include <arch/mmu.h>
#include <arch/machine/smp.h>

/*
 * Important:
 * We do not flush any TLB when adding new mappings in map_range_in_pgtbl.
 * This is because TLB will not cache empty mappings.
 * Prerequisite: ChCore does not directly change mappings (without unmap).
 */

/*
 * Inst/data cache on x86_64 are consistent.
 */
void flush_idcache(void)
{
	/* empty */
}

#ifdef CHCORE_PLAT_AMD_SEV
unsigned long flush_tlb_bitmap[PLAT_CPU_NUM][PAGE_SIZE/BITS_PER_LONG];
#endif /* CHCORE_PLAT_AMD_SEV */
/*
 * Write cr3 is needed for context switching.
 * Function set_page_table only changes CR3 without flushing TLBs.
 *
 * Chcore enables PCID.
 * We should not rely on the following function to flush TLB.
 */
void set_page_table(paddr_t pgtbl)
{
	/* set the highest bit: do not flush TLB */
	pgtbl |= (1UL << 63);
#ifdef CHCORE_PLAT_AMD_SEV
	u32 cpuid = smp_get_cpu_id();
	if (get_bit(get_pcid(pgtbl), flush_tlb_bitmap[cpuid])) {
		pgtbl &= ~(1UL << 63);
		clear_bit(get_pcid(pgtbl), flush_tlb_bitmap[cpuid]);
	}
#endif /* CHCORE_PLAT_AMD_SEV */
	asm volatile("mov %0, %%cr3\n\t" : : "r"(pgtbl) : );
}

paddr_t get_page_table(void)
{
	paddr_t pgtbl;

	asm volatile("mov %%cr3, %0\n\t" :"=r"(pgtbl) : : );
	return pgtbl;
}

#define USER_PTE 0
#define KERNEL_PTE 1

/*
 * the 3rd arg means the kind of PTE (user or kernel PTE)
 */
static int set_pte_flags(pte_t *entry, vmr_prop_t flags, int kind)
{
	/* For enabling MPK, we set U bit everywhere */
	BUG_ON(kind != USER_PTE && kind != KERNEL_PTE);
	if (kind == USER_PTE)
		entry->pteval |= PAGE_USER;

	if (flags & VMR_WRITE)
		entry->pteval |= PAGE_RW;
		/* equals: entry->pte_4K.writeable = 1; */
	else
		entry->pteval &= (~PAGE_RW);
		/* equals: entry->pte_4K.writeable = 0; */

	if (flags & VMR_EXEC)
		entry->pteval &= (~PAGE_NX);
		/* equals: entry->pte_4K.nx = 0; */
	else
		entry->pteval |= PAGE_NX;
		/* equals: entry->pte_4K.nx = 1; */

	if (flags & VMR_NOCACHE)
		entry->pteval |= PAGE_PCD;
		/* equals: entry->pte_4K.cache_disable = 1; */
	else
		entry->pteval &= (~PAGE_PCD);
		/* equals: entry->pte_4K.cache_disable = 0; */

#ifdef CHCORE_SPLIT_CONTAINER
#ifdef CHCORE_PLAT_AMD_SEV
	if (!(flags & VMR_SC_SHM))
		entry->pteval |= PAGE_PRIVATE;
#endif /* CHCORE_PLAT_AMD_SEV */
#ifdef CHCORE_PLAT_INTEL_TDX
	if (flags & VMR_SC_SHM)
		entry->pteval |= PAGE_SHARED;
#endif /* CHCORE_PLAT_AMD_SEV */
#else
#ifdef CHCORE_PLAT_AMD_SEV
	entry->pteval |= PAGE_PRIVATE;
#endif /* CHCORE_PLAT_AMD_SEV */
#endif

	// TODO: set memory type
	return 0;
}

#define NORMAL_PTP (0)
#define BLOCK_PTP  (1) /* huge page */

/*
 * Find next page table page for the "va".
 *
 * cur_ptp: current page table page
 * level:   current ptp level
 *
 * next_ptp: returns "next_ptp"
 * pte     : returns "pte" (points to next_ptp) in "cur_ptp"
 *
 * alloc: if true, allocate a ptp when missing
 *
 */
int get_next_ptp(ptp_t *cur_ptp, u32 level, vaddr_t va,
			ptp_t **next_ptp, pte_t **pte, bool alloc, long *rss)
{
	u32 index = 0;
	pte_t *entry;

	if (cur_ptp == NULL)
		return -ENOMAPPING;

	switch (level) {
	case 0:
		index = GET_L0_INDEX(va);
		break;
	case 1:
		index = GET_L1_INDEX(va);
		break;
	case 2:
		index = GET_L2_INDEX(va);
		break;
	case 3:
		index = GET_L3_INDEX(va);
		break;
	default:
		BUG("unexpected level\n");
		return -EINVAL;
	}

	entry = &(cur_ptp->ent[index]);
	/* if not present */
	if (!(entry->pteval & PAGE_PRESENT)) {
		if (alloc == false) {
			return -ENOMAPPING;
		}
		else {
			/* alloc a new page table page */
			ptp_t *new_ptp;
			paddr_t new_ptp_paddr;
			pte_t new_pte_val;

			/* get 2^0 physical page */
			new_ptp = (ptp_t *)get_pages(0);
			BUG_ON(new_ptp == NULL);
			memset((void *)new_ptp, 0, PAGE_SIZE);
			if (rss)
				*rss += PAGE_SIZE;

			new_ptp_paddr = virt_to_phys((void *)new_ptp);

			new_pte_val.pteval = 0;
			new_pte_val.table.present = 1;
			/* For enabling MPK, set U-bit in every level page table */
			new_pte_val.table.user = 1;
			new_pte_val.table.writeable = 1;

			new_pte_val.table.next_table_addr
				= new_ptp_paddr >> PAGE_SHIFT;
			entry->pteval = new_pte_val.pteval;
		}
	}

	*next_ptp = (ptp_t *)GET_NEXT_PTP(entry);
	*pte = entry;

	/* whether it is a PTP or a page (BLOCK_PTP) */
	if ((level == 3) || (entry->table.is_page))
		return BLOCK_PTP;
	else
		return NORMAL_PTP;
}

int debug_query_in_pgtbl(void *pgtbl, vaddr_t va, paddr_t *pa, pte_t **entry)
{
	ptp_t *l0_ptp, *l1_ptp, *l2_ptp, *l3_ptp;
	ptp_t *phys_page;
	pte_t *pte;
	int ret;

	// L0 page table
	l0_ptp = (ptp_t *)remove_pcid(pgtbl);
	ret = get_next_ptp(l0_ptp, 0, va, &l1_ptp, &pte, false, NULL);
	//BUG_ON(ret < 0);
	if (ret < 0) {
		printk("[debug_query_in_pgtbl] L0 no mapping.\n");
		return ret;
	}
	printk("L0 pte is 0x%lx\n", pte->pteval);

	// L1 page table
	ret = get_next_ptp(l1_ptp, 1, va, &l2_ptp, &pte, false, NULL);
	//BUG_ON(ret < 0);
	if (ret < 0) {
		printk("[debug_query_in_pgtbl] L1 no mapping.\n");
		return ret;
	}
	printk("L1 pte is 0x%lx\n", pte->pteval);

	// L2 page table
	ret = get_next_ptp(l2_ptp, 2, va, &l3_ptp, &pte, false, NULL);
	//BUG_ON(ret < 0);
	if (ret < 0) {
		printk("[debug_query_in_pgtbl] L2 no mapping.\n");
		return ret;
	}
	printk("L2 pte is 0x%lx\n", pte->pteval);

	// L3 page table
	ret = get_next_ptp(l3_ptp, 3, va, &phys_page, &pte, false, NULL);
	//BUG_ON(ret < 0);
	if (ret < 0) {
		printk("[debug_query_in_pgtbl] L3 no mapping.\n");
		return ret;
	}
	printk("L3 pte is 0x%lx\n", pte->pteval);

	*pa = virt_to_phys((void *)phys_page) + GET_VA_OFFSET_L3(va);
	*entry = pte;
	return 0;
}

int query_in_pgtbl(void *pgtbl, vaddr_t va, paddr_t *pa, pte_t **entry)
{
	/*
	 * On x86_64, pml4 is the highest level page table.
	 *
	 * To make the code similar with that in aarch64,
	 * we use l0_ptp to represent the high level page table.
	 *
	 */
	ptp_t *l0_ptp, *l1_ptp, *l2_ptp, *l3_ptp;
	ptp_t *phys_page;
	pte_t *pte;
	int ret;

	/* L0 page table / pml4 */
	l0_ptp = (ptp_t *)remove_pcid(pgtbl);
	ret = get_next_ptp(l0_ptp, 0, va, &l1_ptp, &pte, false, NULL);
	if (ret < 0)
		return ret;

	/* L1 page table / pdpte */
	ret = get_next_ptp(l1_ptp, 1, va, &l2_ptp, &pte, false, NULL);
	if (ret < 0)
		return ret;
	else if (ret == BLOCK_PTP) { /* 1G huge page */
		*pa = virt_to_phys((void *)l2_ptp) +
			GET_VA_OFFSET_L1(va);

		if (entry)
			*entry = pte;

		return 0;
	}

	/* L2 page table / pde */
	ret = get_next_ptp(l2_ptp, 2, va, &l3_ptp, &pte, false, NULL);
	if (ret < 0)
		return ret;
	else if (ret == BLOCK_PTP) { /* 2M huge page */
		*pa = virt_to_phys((void *)l3_ptp) +
			GET_VA_OFFSET_L2(va);

		if (entry)
			*entry = pte;

		return 0;
	}

	/* L3 page table / pte */
	ret = get_next_ptp(l3_ptp, 3, va, &phys_page, &pte, false, NULL);
	if (ret < 0)
		return ret;

	*pa = virt_to_phys((void *)phys_page) + GET_VA_OFFSET_L3(va);
	if (entry)
		*entry = pte;
	return 0;
}

#define IS_PTE_INVALID(pteval) (!(pteval & PAGE_PRESENT))

/* TODO: no support for huge page */
#ifdef CHCORE
void free_page_table(void *pgtbl)
{
	ptp_t *l0_ptp, *l1_ptp, *l2_ptp, *l3_ptp;
	pte_t *l0_pte, *l1_pte, *l2_pte;
	int i, j, k;

	if (pgtbl == NULL) {
		kwarn("%s: input arg is NULL.\n", __func__);
		return;
	}

	/* L0 page table */
	l0_ptp = (ptp_t *)remove_pcid(pgtbl);

	/*
	 * Interate each entry in the l0 page table.
	 * Note: on x86_64, the last two entry of l0 ptp points to
	 * kernel page table.
	 * We use the last three entries of l0 ptp all 
	 * point to kernel page table pages to mapping
	 * kernel stack, it also doesn't need to be free
	 */
	for (i = 0; i < PTP_ENTRIES - 2; ++i) {
		l0_pte = &l0_ptp->ent[i];
		if (IS_PTE_INVALID(l0_pte->pteval)) continue;
		l1_ptp = (ptp_t *)GET_NEXT_PTP(l0_pte);

		/* Interate each entry in the l1 page table*/
		for (j = 0; j < PTP_ENTRIES; ++j) {
			l1_pte = &l1_ptp->ent[j];
			if (IS_PTE_INVALID(l1_pte->pteval)) continue;
			l2_ptp = (ptp_t *)GET_NEXT_PTP(l1_pte);

			/* Interate each entry in the l2 page table*/
			for (k = 0; k < PTP_ENTRIES; ++k) {
				l2_pte = &l2_ptp->ent[k];
				if (IS_PTE_INVALID(l2_pte->pteval)) continue;
				l3_ptp = (ptp_t *)GET_NEXT_PTP(l2_pte);
				/* Free the l3 page table page */
				BUG_ON((vaddr_t)l3_ptp % PAGE_SIZE != 0);
				kfree(l3_ptp);
			}

			/* Free the l2 page table page */
			BUG_ON((vaddr_t)l2_ptp % PAGE_SIZE != 0);
			kfree(l2_ptp);
		}

		/* Free the l1 page table page */
		BUG_ON((vaddr_t)l1_ptp % PAGE_SIZE != 0);
		kfree(l1_ptp);

	}

	/* Free the l0 page table page */
	BUG_ON((vaddr_t)l0_ptp % PAGE_SIZE != 0);
	kfree(l0_ptp);
}
#endif

static int map_range_in_pgtbl_common(void *pgtbl, vaddr_t va, paddr_t pa,
		       size_t len, vmr_prop_t flags, int kind, long *rss)
{
	s64 total_page_cnt;
	ptp_t *l0_ptp, *l1_ptp, *l2_ptp, *l3_ptp;
	pte_t *pte;
	int ret;
	/* the index of pte in the last level page table */
	int pte_index;
	int i;

	/* root page table page must exist */
	BUG_ON(pgtbl == NULL);
	/* va should be page aligned. */
	BUG_ON(va % PAGE_SIZE);
	total_page_cnt = len / PAGE_SIZE + (((len % PAGE_SIZE) > 0) ? 1 : 0);

	l0_ptp = (ptp_t *)remove_pcid(pgtbl);

	l1_ptp = NULL;
	l2_ptp = NULL;
	l3_ptp = NULL;

	while (total_page_cnt > 0) {
		// l0
		ret = get_next_ptp(l0_ptp, 0, va, &l1_ptp, &pte, true, rss);
		if (ret != 0) printk("ret: %d\n", ret);
		BUG_ON(ret != 0);

		// l1
		ret = get_next_ptp(l1_ptp, 1, va, &l2_ptp, &pte, true, rss);
		if (ret != 0) printk("ret: %d\n", ret);
		BUG_ON(ret != 0);

		// l2
		ret = get_next_ptp(l2_ptp, 2, va, &l3_ptp, &pte, true, rss);
		BUG_ON(ret != 0);

		// l3
		// step-1: get the index of pte
		pte_index = GET_L3_INDEX(va);
		for (i = pte_index; i < PTP_ENTRIES; ++i) {
			pte_t new_pte_val;

			new_pte_val.pteval = 0;

			new_pte_val.pte_4K.present = 1;
			new_pte_val.pte_4K.pfn = pa >> PAGE_SHIFT;

			set_pte_flags(&new_pte_val, flags, kind);
			l3_ptp->ent[i].pteval = new_pte_val.pteval;

			va += PAGE_SIZE;
			pa += PAGE_SIZE;
			if (rss)
				*rss += PAGE_SIZE;
			total_page_cnt -= 1;
			if (total_page_cnt == 0)
				break;
		}
	}

	/* No need to flush TLB when adding mappings */
	return 0;
}

/* Map vm range in kernel */
int map_range_in_pgtbl_kernel(void *pgtbl, vaddr_t va, paddr_t pa,
		       size_t len, vmr_prop_t flags)
{
	return map_range_in_pgtbl_common(pgtbl, va, pa, len, flags, 1, NULL);
}

/* Map vm range in user */
int map_range_in_pgtbl(void *pgtbl, vaddr_t va, paddr_t pa,
		       size_t len, vmr_prop_t flags, long *rss)
{
	return map_range_in_pgtbl_common(pgtbl, va, pa, len, flags, 0, rss);
}

/*
 * Try to relase a lower level page table page (low_ptp).
 * @high_ptp: the higher level page table page
 * @low_ptp: the next level page table page
 * @index: the index of low_ptp in high ptp entries
 * @return:
 * 	- zero if lower page table page is not all empty
 * 	- nonzero otherwise
 */
static int try_release_ptp(ptp_t *high_ptp, ptp_t *low_ptp,
				  int index, long *rss)
{
	int i;

	for (i = 0; i < PTP_ENTRIES; i++) {
		if (!IS_PTE_INVALID(low_ptp->ent[i].pteval)) {
			return 0;
		}
	}

	BUG_ON(index < 0 || index >= PTP_ENTRIES);
	high_ptp->ent[index].pteval = 0;
	kfree(low_ptp);
	if (rss)
		*rss -= PAGE_SIZE;

	return 1;
}

static void recycle_pgtable_entry(ptp_t *l0_ptp, ptp_t *l1_ptp, ptp_t *l2_ptp,
			   ptp_t *l3_ptp, vaddr_t va, long *rss)
{
	if (!try_release_ptp(l2_ptp, l3_ptp, GET_L2_INDEX(va), rss))
		return;

	if (!try_release_ptp(l1_ptp, l2_ptp, GET_L1_INDEX(va), rss))
		return;

	try_release_ptp(l0_ptp, l1_ptp, GET_L0_INDEX(va), rss);
}

int unmap_range_in_pgtbl(void *pgtbl, vaddr_t va, size_t len, long *rss)
{
	s64 total_page_cnt; // must be signed
	s64 left_page_cnt_in_current_level;
	ptp_t *l0_ptp, *l1_ptp, *l2_ptp, *l3_ptp;
	pte_t *pte;
	int ret;
	int pte_index; // the index of pte in the last level page table
	int i;
	vaddr_t old_va;

	BUG_ON(pgtbl == NULL);
	BUG_ON(va % PAGE_SIZE);

	l0_ptp = (ptp_t *)remove_pcid(pgtbl);

	total_page_cnt = len / PAGE_SIZE + (((len % PAGE_SIZE) > 0) ? 1 : 0);
	while (total_page_cnt > 0) {
		old_va = va;

		/* l0 */
		ret = get_next_ptp(l0_ptp, 0, va, &l1_ptp, &pte, false, NULL);
		if (ret == -ENOMAPPING) {
			left_page_cnt_in_current_level = (L0_PER_ENTRY_PAGES - GET_L1_INDEX(va) * L1_PER_ENTRY_PAGES);
			total_page_cnt -= (left_page_cnt_in_current_level > total_page_cnt ? total_page_cnt : left_page_cnt_in_current_level);
			va += left_page_cnt_in_current_level * PAGE_SIZE;
			continue;
		}

		/* l1 */
		ret = get_next_ptp(l1_ptp, 1, va, &l2_ptp, &pte, false, NULL);
		if (ret == -ENOMAPPING) {
			left_page_cnt_in_current_level = (L1_PER_ENTRY_PAGES - GET_L2_INDEX(va) * L2_PER_ENTRY_PAGES);
			total_page_cnt -= (left_page_cnt_in_current_level > total_page_cnt ? total_page_cnt : left_page_cnt_in_current_level);
			va += left_page_cnt_in_current_level * PAGE_SIZE;
			continue;
		}

		/* l2 */
		ret = get_next_ptp(l2_ptp, 2, va, &l3_ptp, &pte, false, NULL);
		if (ret == -ENOMAPPING) {
			left_page_cnt_in_current_level = (L2_PER_ENTRY_PAGES - GET_L3_INDEX(va) * L3_PER_ENTRY_PAGES);
			total_page_cnt -= (left_page_cnt_in_current_level > total_page_cnt ? total_page_cnt : left_page_cnt_in_current_level);
			va += left_page_cnt_in_current_level * PAGE_SIZE;
			continue;
		}

		/* l3 */
		/* get the index of pte */
		pte_index = GET_L3_INDEX(va);
		for (i = pte_index; i < PTP_ENTRIES; ++i) {
			if (l3_ptp->ent[i].pte_4K.present && rss)
				*rss -= PAGE_SIZE;

			/* clear the pte */
			l3_ptp->ent[i].pteval = 0;
			va += PAGE_SIZE;
			total_page_cnt -= 1;
			if (total_page_cnt == 0)
				break;
		}
		recycle_pgtable_entry(l0_ptp, l1_ptp, l2_ptp, l3_ptp, old_va, rss);
	}

	return 0;
}

/*
 * Foring supportting mprotect:
 *	- scan the page table and modify the PTEs if they exist
 */
int mprotect_in_pgtbl(void *pgtbl, vaddr_t va, size_t len, vmr_prop_t flags)
{
	s64 total_page_cnt; // must be signed
	ptp_t *l0_ptp, *l1_ptp, *l2_ptp, *l3_ptp;
	pte_t *pte;
	int ret;
	int pte_index; // the index of pte in the last level page table
	int i;

	BUG_ON(pgtbl == NULL);
	BUG_ON(va % PAGE_SIZE);

	l0_ptp = (ptp_t *)remove_pcid(pgtbl);

	total_page_cnt = len / PAGE_SIZE + (((len % PAGE_SIZE) > 0) ? 1 : 0);
	while (total_page_cnt > 0) {
		/* l0 */
		ret = get_next_ptp(l0_ptp, 0, va, &l1_ptp, &pte, false, NULL);
		if (ret == -ENOMAPPING) {
			total_page_cnt -= L0_PER_ENTRY_PAGES;
			va += L0_PER_ENTRY_PAGES * PAGE_SIZE;
			continue;
		}

		/* l1 */
		ret = get_next_ptp(l1_ptp, 1, va, &l2_ptp, &pte, false, NULL);
		if (ret == -ENOMAPPING) {
			total_page_cnt -= L1_PER_ENTRY_PAGES;
			va += L1_PER_ENTRY_PAGES * PAGE_SIZE;
			continue;
		}

		/* l2 */
		ret = get_next_ptp(l2_ptp, 2, va, &l3_ptp, &pte, false, NULL);
		if (ret == -ENOMAPPING) {
			total_page_cnt -= L2_PER_ENTRY_PAGES;
			va += L2_PER_ENTRY_PAGES * PAGE_SIZE;
			continue;
		}

		/* l3 */
		/* get the index of pte */
		pte_index = GET_L3_INDEX(va);
		for (i = pte_index; i < PTP_ENTRIES; ++i) {

			/*
			 * Modify the permission in the pte if it exists.
			 * Usually, some ptes exist, so flush tlb is necessary.
			 */
			if (l3_ptp->ent[i].pteval & PAGE_PRESENT)
				set_pte_flags(&(l3_ptp->ent[i]), flags, USER_PTE);

			va += PAGE_SIZE;
			total_page_cnt -= 1;
			if (total_page_cnt == 0)
				break;
		}
	}

	return 0;
}

void parse_pte_to_common(pte_t* pte, unsigned int level, struct common_pte_t* ret)
{
	switch (level) {
	case 3:
		ret->valid = pte->pte_4K.present;
		ret->access = pte->pte_4K.accessed;
		ret->dirty = pte->pte_4K.dirty;

		ret->ppn = pte->pte_4K.pfn;
		ret->perm = 0;
		if (!pte->pte_4K.nx) {
			ret->perm |= VMR_EXEC;
		}

		if (pte->pte_4K.writeable) {
			ret->perm |= (VMR_READ | VMR_WRITE);
		} else {
			ret->perm |= VMR_READ;
		}
		break;
	default:
		BUG_ON(1);
	}
}

void update_pte(pte_t* dest, unsigned int level, struct common_pte_t* src) 
{
	switch (3) {
	case 3:
		dest->pte_4K.present = src->valid;
		dest->pte_4K.accessed = src->access;
		dest->pte_4K.dirty = src->dirty;

		dest->pte_4K.pfn = src->ppn;

		set_pte_flags(dest, src->perm, USER_PTE);
		break;
	default:
		BUG_ON(1);
	}
}
