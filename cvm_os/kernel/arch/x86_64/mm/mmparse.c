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

#include <arch/boot.h>
#include <arch/machine/smp.h>
#include <arch/tools.h>
#include <arch/mmu.h>
#include <common/types.h>
#include <common/kprint.h>
#include <common/macro.h>
#include <mm/mm.h>
#include <arch/drivers/multiboot2.h>

#define SIZE_1G (1UL << 30)

#define PRESENT  (1 << 0)
#define WRITABLE (1 << 1)
#define HUGE_1G  (1 << 7)
#define GLOBAL   (1 << 8)
#define NX       (1UL << 63)
#define PRIVATE  (1UL << 51)
#define SHARED   (1UL << 51)

static void refill_kernel_page_table(long max_mem)
{
        u64 idx = 0;
        u64 *direct_mapping;

        /*
         * We do not remove the booting mapping in the boot page table
         * because it will not be copied to apps' page tables.
         * Besides, the boot page table will not be used after booting.
         */

        /* Re-setup the direct mapping for all the physical memory */
        direct_mapping = (u64 *)CHCORE_PUD_Direct_Mapping;

        /*
         * Since we bindly mapping 0-4G in header.S,
         * here clear it first while leave the first 1GB.
         */
        for (idx = 1; idx < 4; ++idx) {
                *(direct_mapping + idx) = 0;
        }

        /* We map the available physical memory here. 0~1G has been mapped. */
        idx = 0;
        while (max_mem > SIZE_1G) {
                direct_mapping += 1;
                idx += 1;

                /* Add mapping for 1G, 2G, 3G ... */
#ifdef CHCORE_PLAT_AMD_SEV
                *direct_mapping = (idx << 30) + PRESENT + WRITABLE + HUGE_1G
                        + GLOBAL + NX + PRIVATE;
#else /* CHCORE_PLAT_AMD_SEV */
                *direct_mapping = (idx << 30) + PRESENT + WRITABLE + HUGE_1G
                        + GLOBAL + NX;
#endif /* CHCORE_PLAT_AMD_SEV */
                max_mem -= SIZE_1G;
        }

        /* Flush TLB: SMP is not enabled for now. */
        flush_boot_tlb();
}

void parse_mem_map(void *info)
{
        struct multiboot_tag_mmap *tag;
        multiboot_memory_map_t *mmap = NULL, *second_mmap = NULL, *temp = NULL;
        paddr_t p_end;
        u64 mlength = 0;
        u64 second_mlength = 0;
        u64 max_paddr = 0;

        tag = (struct multiboot_tag_mmap *)info;
        p_end = (u64)((void *)img_end - KCODE);

#ifndef CHCORE_PLAT_INTEL_TDX
        /*
         * According to multiboot2 specification,
         * type 1 indicates available memory,
         * type 2 indicates reserved memory,
         * type 3 indicates usable memory holding ACPI information,
         * type 4 indicates reserved memory which needs to be preserved on hibernation,
         * type 5 indicates memory which is occupied by defective RAM modules,
         * All other types indicate reserved memory.
         */
        for (temp = tag->entries; (u64)temp < (u64)tag + tag->size;
                        temp = (multiboot_memory_map_t *)((u64)temp + tag->entry_size)) {
                kinfo("start_addr = 0x%lx, end_addr = 0x%lx, type = 0x%x\n",
                                temp->addr,
                                temp->addr + temp->len,
                                temp->type);

                if (temp->type == MULTIBOOT_MEMORY_AVAILABLE) {
                        u64 temp_end = temp->addr + temp->len;
                        if (temp_end <= p_end) continue;

                        if (temp->len > mlength) {
                                if (mmap != NULL) {
                                        /* Previously largest one become the second. */
                                        second_mmap = mmap;
                                        second_mlength = mmap->len;
                                }
                                mmap = temp; /* Record the current largest entry */
                                mlength = temp->len;

                                if (temp_end > max_paddr)
                                        max_paddr = temp_end;

                        } else if (temp->len > second_mlength) {
                                /* Record the second largest entry */
                                second_mmap = temp;
                                second_mlength = temp->len;

                                if (temp_end > max_paddr)
                                        max_paddr = temp_end;
                        }
                }
        }
#else /* CHCORE_PLAT_INTEL_TDX */
        /* Fake parsing */
        multiboot_memory_map_t __mmap, __second_mmap;

        (void)tag;
        (void)temp;

        __mmap.addr = 0x100000000UL;
        __mmap.len = 0x80000000UL;
        __mmap.type = MULTIBOOT_MEMORY_AVAILABLE;
        mmap = &__mmap;
        mlength = __mmap.len;
        

        __second_mmap.addr = 0x20000000UL;
        __second_mmap.len = 0x60000000UL;
        __second_mmap.type = MULTIBOOT_MEMORY_AVAILABLE;
        second_mmap = &__second_mmap;
        second_mlength = __second_mmap.len;

        max_paddr = 0x180000000UL;
#endif /* CHCORE_PLAT_INTEL_TDX */

#ifdef CHCORE_SPLIT_CONTAINER
        max_paddr = 0x7D00000000; // 500G
#endif /* CHCORE_SPLIT_CONTAINER */

        /* Failed to detect memory using multiboot2 */
        BUG_ON(mlength == 0);
        BUG_ON(mmap == NULL);
        BUG_ON(mmap->type != MULTIBOOT_MEMORY_AVAILABLE);

        if (second_mlength == 0)
                physmem_map_num = 1;
        else
                physmem_map_num = 2;

        /* remove kernel image part [0, img_end) */
        if (mmap->addr < p_end)
                physmem_map[0][0] = p_end;
        else
                physmem_map[0][0] = mmap->addr;

        physmem_map[0][1] = mmap->addr + mmap->len;

        if (second_mmap->addr < p_end)
                physmem_map[1][0] = p_end;
        else
                physmem_map[1][0] = second_mmap->addr;

        physmem_map[1][1] = second_mmap->addr + second_mmap->len;


        for (int i = 0; i < physmem_map_num; ++i) {
                kinfo("Kernel uses memory: 0x%lx - 0x%lx\n",
                                physmem_map[i][0],
                                physmem_map[i][1]);
        }

        refill_kernel_page_table((long)max_paddr);
}
