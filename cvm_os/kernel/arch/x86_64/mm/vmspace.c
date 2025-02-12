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

#include <common/types.h>
#include <common/kprint.h>
#include <common/lock.h>
#include <mm/mm.h>
#include <mm/vmspace.h>
#include <mm/kmalloc.h>

#include <arch/mm/page_table.h>
#include <arch/tools.h>
#include <arch/mmu.h>

/*
static void pte_set_user_bit(pte_t *entry)
{
	entry->pteval |= PAGE_USER;
}
*/

static void pte_clear_user_bit(pte_t *entry)
{
	entry->pteval &= ~PAGE_USER;
}

static void __arch_vmspace_init(struct vmspace *vmspace)
{
	ptp_t *ptp_k;
	ptp_t *ptp_u;
	pte_t *entry_k;
	pte_t *entry_u;
	int index;

	/*
	 * We map the kernel space in the user pgtbl
	 * but mark them as Supervisor (user cannot access).
	 *
	 * We use 1G huge page for the kernel address mapping.
	 */

	/* Kernel root page table page */
	ptp_k = (ptp_t *)CHCORE_PGD;
	/* User process root page table page */
	ptp_u = (ptp_t *)vmspace->pgtbl;

	/* Map the kernel code part in the user page table */
	index = GET_L0_INDEX(KCODE);
	BUG_ON(index != 511);
	/* The page table entry for the kernel code mapping */
	entry_k = &(ptp_k->ent[index]);
	/* The corresponding entry in the user page table */
	entry_u = &(ptp_u->ent[index]);
	/* Set the mapping in the user page table */
	entry_u->pteval = entry_k->pteval;
	/* Protect kernel form user */
	pte_clear_user_bit(entry_u);

	/* Map the kernel direct mapping part in the user page table */
	index = GET_L0_INDEX(KBASE);
	BUG_ON(index != 510);
	/* The page table entry for the kernel code mapping */
	entry_k = &(ptp_k->ent[index]);
	/* The corresponding entry in the user page table */
	entry_u = &(ptp_u->ent[index]);
	/* Setup the mappings in the user page table */
	entry_u->pteval = entry_k->pteval;
	/* Protect kernel form user */
	pte_clear_user_bit(entry_u);
}

/* Initialize the top page table page for a user-level process */
void arch_vmspace_init(struct vmspace *vmspace)
{
	u64 pcid;

	__arch_vmspace_init(vmspace);

	/* CR3: the lower 12-bit represent PCID */
	pcid = vmspace->pcid;
	vmspace->pgtbl = (void *)((u64)(vmspace->pgtbl) | pcid);
}

struct vmspace *create_idle_vmspace(void)
{
	struct vmspace *idle_vmspace;

	idle_vmspace = kzalloc(sizeof(*idle_vmspace));
	/* Cannot use the CHCORE_PGD directly because its addr < IMG_END */
	idle_vmspace->pgtbl = get_pages(0);
	BUG_ON(idle_vmspace->pgtbl == NULL);
	memset(idle_vmspace->pgtbl, 0, PAGE_SIZE);

	__arch_vmspace_init(idle_vmspace);

	return idle_vmspace;
}

/* Change vmspace to the target one */
void switch_vmspace_to(struct vmspace *vmspace)
{
	set_page_table(virt_to_phys(vmspace->pgtbl));
}