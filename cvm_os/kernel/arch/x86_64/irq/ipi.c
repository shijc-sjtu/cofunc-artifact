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

#include <arch/mmu.h>
#include <irq/irq.h>
#include <irq/ipi.h>

void x2apic_send_ipi_single(u32, u32);

void arch_send_ipi(u32 cpu, u32 ipi)
{
	plat_send_ipi(cpu, ipi);
}

/*
 * IPI receiver side:
 * Based on IPI_tx interfaces, ChCore uses the following TLB shootdown
 * protocol between different CPU cores.
 */
void handle_ipi_on_tlb_shootdown(void)
{
	int cpuid;
	u64 start_va;
	u64 page_cnt;
	u64 pcid;
	u64 vmspace;

	cpuid = smp_get_cpu_id();

	start_va = get_ipi_tx_arg(0);
	page_cnt = get_ipi_tx_arg(1);
	pcid     = get_ipi_tx_arg(2);
	vmspace  = get_ipi_tx_arg(3);

	flush_local_tlb_opt(start_va, page_cnt, pcid);

	/*
	 * If the vmspace is running on the current CPU,
	 * we should clear the history_cpu records because
	 * the vmspace will continue to run after this IPI.
	 */
	if (((u64)(current_thread->vmspace) != vmspace)
	    && (vmspace != 0))
		clear_history_cpu((struct vmspace *)vmspace, cpuid);
}

void arch_handle_ipi(u32 ipi_vector)
{
	switch (ipi_vector) {
	case IPI_TLB_SHOOTDOWN:
		handle_ipi_on_tlb_shootdown();
		break;
	case IPI_RESCHED:
		add_pending_resched(smp_get_cpu_id());
		break;
	default:
		BUG("Unsupported IPI vector %u\n", ipi_vector);
		break;
	}
}
