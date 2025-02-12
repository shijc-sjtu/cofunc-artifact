#include <sev.h>
#include <machine.h>
#include <arch/machine/smp.h>
#include <arch/mmu.h>
#include <arch/time.h>
#include <common/bitops.h>
#include <common/macro.h>
#include <common/util.h>
#include <mm/uaccess.h>
#include <mm/kmalloc.h>
#ifdef CHCORE_SPLIT_CONTAINER
#include <split-container/split_container.h>
#endif /* CHCORE_SPLIT_CONTAINER */

static struct ghcb __ghcbs[PLAT_CPU_NUM] ALIGN(PAGE_SIZE);
static struct ghcb *ghcbs[PLAT_CPU_NUM];

static inline void vmgexit(void)
{
        asm volatile("rep; vmmcall");
}

static int pvalidate(vaddr_t vaddr, bool rmp_psize, bool validate)
{
        bool no_rmpupdate;
        int rc;

        /* "pvalidate" mnemonic support in binutils 2.36 and newer */
        asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFF\n\t"
                     CC_SET(c)
                     : CC_OUT(c) (no_rmpupdate), "=a"(rc)
                     : "a"(vaddr), "c"(rmp_psize), "d"(validate)
                     : "memory", "cc");

        if (no_rmpupdate)
                return PVALIDATE_FAIL_NOUPDATE;

        return rc;
}

static inline int rmpadjust(unsigned long vaddr, bool rmp_psize, unsigned long attrs)
{
        int rc;

        /* "rmpadjust" mnemonic support in binutils 2.36 and newer */
        asm volatile(".byte 0xF3,0x0F,0x01,0xFE\n\t"
                     : "=a"(rc)
                     : "a"(vaddr), "c"(rmp_psize), "d"(attrs)
                     : "memory", "cc");

        return rc;
}

static void early_set_page_state(unsigned long paddr, enum psc_op op)
{
        u64 val;

        /*
         * Use the MSR protocol because this function can be called before
         * the GHCB is established.
         */
        __wrmsr(MSR_GHCB, GHCB_MSR_PSC_REQ_GFN(paddr >> PAGE_SHIFT, op));
        vmgexit();

        val = __rdmsr(MSR_GHCB);

        BUG_ON(GHCB_RESP_CODE(val) != GHCB_MSR_PSC_RESP);
        BUG_ON(GHCB_MSR_PSC_RESP_VAL(val));
}

static void early_set_page_shared(unsigned long vaddr, unsigned long paddr)
{
        /* Invalidate the memory pages before they are marked shared in the RMP table. */        
        BUG_ON(pvalidate(vaddr, RMP_PG_SIZE_4K, false));

        /* Ask hypervisor to mark the memory pages shared in the RMP table. */
        early_set_page_state(paddr, SNP_PAGE_STATE_SHARED);
}

static void register_ghcb(unsigned long paddr)
{
        unsigned long pfn = paddr >> PAGE_SHIFT;
        u64 val;

        __wrmsr(MSR_GHCB, GHCB_MSR_REG_GPA_REQ_VAL(pfn));
        vmgexit();

        val = __rdmsr(MSR_GHCB);

        /* If the response GPA is not ours then abort the guest */
        BUG_ON(GHCB_RESP_CODE(val) != GHCB_MSR_REG_GPA_RESP);
        BUG_ON(GHCB_MSR_REG_GPA_RESP_VAL(val) != pfn);
}

void sev_snp_init_per_cpu_ghcb(u32 cpuid)
{
        struct ghcb *ghcb;
        paddr_t paddr;
        vaddr_t vaddr;

        /* Setup cpuid in per_cpu_info */
        extern struct per_cpu_info cpu_info[];
        cpu_info[cpuid].cpu_id = cpuid;
	__wrmsr(MSR_GSBASE, (u64)&cpu_info[cpuid]);
	asm volatile ("swapgs");

        vaddr = (vaddr_t)&__ghcbs[cpuid];
        paddr = (paddr_t)&__ghcbs[cpuid] - KCODE;

        early_set_page_shared(vaddr, paddr);
        register_ghcb(paddr);

        /*
         * SEV-ES GHCBs are shared between the guest and the hypervisor.
         * ghcb and &__ghcbs[cpuid] are mapped to the same physical address, 
         * but ghcb is mapped without SEV C-bit.
         * See also kernel/arch/x86_64/boot/init/header.S.
         */
        ghcbs[cpuid] = ghcb = (void *)&__ghcbs[cpuid] - KCODE + KGHCB;

        ghcb->protocol_version = 2;
        ghcb->ghcb_usage = 0;
        ghcb->sw_exitcode = 0;
        memset(ghcb->valid_bitmap, 0, sizeof(ghcb->valid_bitmap));
}

#define GHCB_BITMAP_INDEX(field) (offsetof(struct ghcb, field) / sizeof(u64))
#define DEFINE_GHCB_ACCESSORS(field)                                            \
        static void ghcb_set_##field(struct ghcb *ghcb, u64 value)              \
        {                                                                       \
                set_bit(GHCB_BITMAP_INDEX(field),                               \
                        (unsigned long *)ghcb->valid_bitmap);                   \
                ghcb->field = value;                                            \
        }
DEFINE_GHCB_ACCESSORS(rax)
DEFINE_GHCB_ACCESSORS(rbx)
DEFINE_GHCB_ACCESSORS(rcx)
DEFINE_GHCB_ACCESSORS(rdx)
DEFINE_GHCB_ACCESSORS(cpl)
// DEFINE_GHCB_ACCESSORS(sw_scratch)
DEFINE_GHCB_ACCESSORS(sw_exitcode)
DEFINE_GHCB_ACCESSORS(sw_exitinfo1)
DEFINE_GHCB_ACCESSORS(sw_exitinfo2)

static void ghcb_invalidate(struct ghcb *ghcb)
{
        ghcb->sw_exitcode = 0;
        memset(ghcb->valid_bitmap, 0, sizeof(ghcb->valid_bitmap));
}

static int call_vmm_with_ghcb(struct ghcb *ghcb)
{	
        __wrmsr(MSR_GHCB, (u64)ghcb - KGHCB);

        vmgexit();

        return ghcb->sw_exitinfo1 & 0xffffffff;
}

void sev_snp_do_wbinvd(void)
{
        struct ghcb *ghcb = ghcbs[smp_get_cpu_id()];

        ghcb_set_sw_exitcode(ghcb, VM_EXIT_WBINVD);
        ghcb_set_sw_exitinfo1(ghcb, 0);
        ghcb_set_sw_exitinfo2(ghcb, 0);

        BUG_ON(call_vmm_with_ghcb(ghcb));

        ghcb_invalidate(ghcb);
}

u32 sev_snp_do_in(u16 addr, int data_width)
{
        u32 data;
        u64 sw_exitinfo1;
        struct ghcb *ghcb = ghcbs[smp_get_cpu_id()];

        sw_exitinfo1 = IOIO_TYPE_IN | IOIO_ADDR_16 | data_width;
        sw_exitinfo1 |= (u64)addr << 16;

        ghcb_set_sw_exitcode(ghcb, VM_EXIT_IOIO);
        ghcb_set_sw_exitinfo1(ghcb, sw_exitinfo1);
        ghcb_set_sw_exitinfo2(ghcb, 0);

        BUG_ON(call_vmm_with_ghcb(ghcb));

        data = ghcb->rax;

        ghcb_invalidate(ghcb);
        return data;
}

void sev_snp_do_out(u16 addr, u32 data, int data_width)
{
        u64 sw_exitinfo1;
        struct ghcb *ghcb = ghcbs[smp_get_cpu_id()];

        sw_exitinfo1 = IOIO_TYPE_OUT | IOIO_ADDR_16 | data_width;
        sw_exitinfo1 |= (u64)addr << 16;

        ghcb_set_sw_exitcode(ghcb, VM_EXIT_IOIO);
        ghcb_set_sw_exitinfo1(ghcb, sw_exitinfo1);
        ghcb_set_sw_exitinfo2(ghcb, 0);

        ghcb_set_rax(ghcb, data);

        BUG_ON(call_vmm_with_ghcb(ghcb));

        ghcb_invalidate(ghcb);
}

/* Fake implementation */
void sev_snp_do_cpuid(u32 *eax, u32 *ebx, u32 *ecx, u32 *edx)
{
        if (*eax == 0x1 && *ecx == 0) {
                *ecx |= FEATURE_ECX_X2APIC;
        } else {
                BUG_ON(1);
        }
}

bool msr_need_vmgexit(u64 msr)
{
        switch (msr) {
        case MSR_GHCB:
        case MSR_GSBASE:
        case MSR_STAR:
        case MSR_LSTAR:
        case MSR_SFMASK:
                return false;
        }

        return true;
}

u64 sev_snp_do_rdmsr(u64 msr)
{
        struct ghcb *ghcb = ghcbs[smp_get_cpu_id()];
        u64 val;

        if (!msr_need_vmgexit(msr)) {
                return __rdmsr(msr);
        }

        ghcb_set_sw_exitcode(ghcb, VM_EXIT_MSR);
        ghcb_set_sw_exitinfo1(ghcb, MSR_TYPE_READ);
        ghcb_set_sw_exitinfo2(ghcb, 0);

        ghcb_set_rcx(ghcb, msr);

        BUG_ON(call_vmm_with_ghcb(ghcb));

        val = (ghcb->rdx << 32) + (ghcb->rax & 0xffffffffUL);

        ghcb_invalidate(ghcb);

        return val;
}

void sev_snp_do_wrmsr(u64 msr, u64 val)
{
        struct ghcb *ghcb = ghcbs[smp_get_cpu_id()];

        if (!msr_need_vmgexit(msr)) {
                __wrmsr(msr, val);
                return;
        }

        ghcb_set_sw_exitcode(ghcb, VM_EXIT_MSR);
        ghcb_set_sw_exitinfo1(ghcb, MSR_TYPE_WRITE);
        ghcb_set_sw_exitinfo2(ghcb, 0);

        ghcb_set_rcx(ghcb, msr);
        ghcb_set_rax(ghcb, val & 0xffffffffUL);
        ghcb_set_rdx(ghcb, val >> 32);

        BUG_ON(call_vmm_with_ghcb(ghcb));

        ghcb_invalidate(ghcb);
}

static int set_vmsa(void *va, bool vmsa)
{
        u64 attrs;

        /*
         * Running at VMPL0 allows the kernel to change the VMSA bit for a page
         * using the RMPADJUST instruction. However, for the instruction to
         * succeed it must target the permissions of a lesser privileged
         * (higher numbered) VMPL level, so use VMPL1 (refer to the RMPADJUST
         * instruction in the AMD64 APM Volume 3).
         */
        attrs = 1;
        if (vmsa)
                attrs |= RMPADJUST_VMSA_PAGE_BIT;

        return rmpadjust((unsigned long)va, RMP_PG_SIZE_4K, attrs);
}

void sev_snp_wakeup_cpu(u32 apic_id, u64 start_ip)
{
        struct sev_es_save_area *vmsa;
        struct ghcb *ghcb;
        u8 sipi_vector;
        u64 cr4;

        vmsa = get_pages(1);
        // vmsa = (void *)vmsas[apic_id];
        BUG_ON(!vmsa);
        vmsa = (void *)vmsa + PAGE_SIZE;
        memset(vmsa, 0, PAGE_SIZE);

        /* CR4 should maintain the MCE value */
        asm volatile("mov %%cr4, %0" : "=r"(cr4) ::);
        cr4 &= X86_CR4_MCE;

        /* Set the CS value based on the start_ip converted to a SIPI vector */
        sipi_vector		= start_ip >> 12;
        vmsa->cs.base		= sipi_vector << 12;
        vmsa->cs.limit		= AP_INIT_CS_LIMIT;
        vmsa->cs.attrib		= INIT_CS_ATTRIBS;
        vmsa->cs.selector	= sipi_vector << 8;

        /* Set the RIP value based on start_ip */
        vmsa->rip		= start_ip & 0xfff;

        /* Set AP INIT defaults as documented in the APM */
        vmsa->ds.limit		= AP_INIT_DS_LIMIT;
        vmsa->ds.attrib		= INIT_DS_ATTRIBS;
        vmsa->es		= vmsa->ds;
        vmsa->fs		= vmsa->ds;
        vmsa->gs		= vmsa->ds;
        vmsa->ss		= vmsa->ds;

        vmsa->gdtr.limit	= AP_INIT_GDTR_LIMIT;
        vmsa->ldtr.limit	= AP_INIT_LDTR_LIMIT;
        vmsa->ldtr.attrib	= INIT_LDTR_ATTRIBS;
        vmsa->idtr.limit	= AP_INIT_IDTR_LIMIT;
        vmsa->tr.limit		= AP_INIT_TR_LIMIT;
        vmsa->tr.attrib		= INIT_TR_ATTRIBS;

        vmsa->cr4		= cr4;
        vmsa->cr0		= AP_INIT_CR0_DEFAULT;
        vmsa->dr7		= DR7_RESET_VALUE;
        vmsa->dr6		= AP_INIT_DR6_DEFAULT;
        vmsa->rflags		= AP_INIT_RFLAGS_DEFAULT;
        vmsa->g_pat		= AP_INIT_GPAT_DEFAULT;
        vmsa->xcr0		= AP_INIT_XCR0_DEFAULT;
        vmsa->mxcsr		= AP_INIT_MXCSR_DEFAULT;
        vmsa->x87_ftw		= AP_INIT_X87_FTW_DEFAULT;
        vmsa->x87_fcw		= AP_INIT_X87_FCW_DEFAULT;

        /* SVME must be set. */
        vmsa->efer		= EFER_SVME;
        
        /*
         * Set the SNP-specific fields for this VMSA:
         *   VMPL level
         *   SEV_FEATURES (matches the SEV STATUS MSR right shifted 2 bits)
         */
        vmsa->vmpl		= 0;
        vmsa->sev_features	= __rdmsr(MSR_AMD64_SEV) >> 2;
        
        /* Switch the page over to a VMSA page now that it is initialized */
        BUG_ON(set_vmsa(vmsa, true));

        /* Issue VMGEXIT AP Creation NAE event */
        ghcb = ghcbs[smp_get_cpu_id()];

        ghcb_set_rax(ghcb, vmsa->sev_features);
        ghcb_set_sw_exitcode(ghcb, SVM_VMGEXIT_AP_CREATION);
        ghcb_set_sw_exitinfo1(ghcb, ((u64)apic_id << 32) | SVM_VMGEXIT_AP_CREATE);
        ghcb_set_sw_exitinfo2(ghcb, virt_to_phys(vmsa));

        BUG_ON(call_vmm_with_ghcb(ghcb));

        ghcb_invalidate(ghcb);
}

long sev_snp_do_hypercall(unsigned int nr, unsigned long p1, unsigned long p2, unsigned long p3)
{
	long ret;
	struct ghcb *ghcb = ghcbs[smp_get_cpu_id()];

	ghcb_set_sw_exitcode(ghcb, VM_EXIT_VMMCALL);
	ghcb_set_sw_exitinfo1(ghcb, 0);
	ghcb_set_sw_exitinfo2(ghcb, 0);

	ghcb_set_cpl(ghcb, 0);
	ghcb_set_rax(ghcb, nr);
	ghcb_set_rbx(ghcb, p1);
        ghcb_set_rcx(ghcb, p2);
        ghcb_set_rdx(ghcb, p3);

	BUG_ON(call_vmm_with_ghcb(ghcb));

	ret = ghcb->rax;

	ghcb_invalidate(ghcb);
	return ret;
}

#ifdef CHCORE_SPLIT_CONTAINER
static unsigned long try_accept_one(paddr_t start, unsigned long len,
				    int rmp_psize)
{
	unsigned long accept_size = rmp_psize ? 0x200000 : 0x1000;

	if (!IS_ALIGNED(start, accept_size))
		return 0;

	if (len < accept_size)
		return 0;

	if (pvalidate(phys_to_virt(start), rmp_psize, true)) {
                if (rmp_psize == RMP_PG_SIZE_2M)
                        kwarn("2M pvalidate failed\n");
		return 0;
        }

	return accept_size;
}

bool sev_snp_enc_status_changed_phys(paddr_t start, paddr_t end, bool enc)
{

        size_t size = end - start;

#ifdef CHCORE_SPLIT_CONTAINER
        split_container_request(
                SC_REQ_MAP_GPA, enc ? start | BIT(51) : start, size);
#else /* CHCORE_SPLIT_CONTAINER */
#error Not implemented
#endif /* CHCORE_SPLIT_CONTAINER */

	if (!enc)
		return true;

	while (start < end) {
		unsigned long len = end - start;
                unsigned long accept_size;

		accept_size = try_accept_one(start, len, RMP_PG_SIZE_2M);
		if (!accept_size)
			accept_size = try_accept_one(start, len, RMP_PG_SIZE_4K);
		if (!accept_size)
			return false;
		start += accept_size;
	}

	return true;
}
#endif

static void handle_cpuid_vc(struct arch_exec_context *ec)
{
        switch (ec->reg[RAX])
        {
        case 0x0:
                ec->reg[RAX] = 0xd;
                ec->reg[RBX] = 0x68747541;
                ec->reg[RCX] = 0x444d4163;
                ec->reg[RDX] = 0x69746e65;
                break;
        case 0x1:
                ec->reg[RAX] = 0x800f12;
                ec->reg[RBX] = 0x100800;
                ec->reg[RCX] = 0xfef83203;
                ec->reg[RDX] = 0x178bfbff;
                break;
        case 0x7:
                ec->reg[RAX] = 0x0;
                ec->reg[RBX] = 0x0;
                ec->reg[RCX] = 0x0;
                ec->reg[RDX] = 0x0;
                break;
        case 0x80000000:
                ec->reg[RAX] = 0x8000001f;
                // ec->reg[RBX] = 0x68747541;
                // ec->reg[RCX] = 0x444d4163;
                // ec->reg[RDX] = 0x69746e65;
                break;
        case 0x80000001:
                ec->reg[RAX] = 0x800f12;
                ec->reg[RBX] = 0x0;
                ec->reg[RCX] = 0xc003f3;
                ec->reg[RDX] = 0x2fd3fbff;
                break;
        case 0x80000006:
                ec->reg[RAX] = 0x0;
                ec->reg[RBX] = 0x42004200;
                ec->reg[RCX] = 0x2006140;
                // ec->reg[RDX] = 0x2fd3fbff;
                break;
        default:
                break;
        }

        ec->reg[RIP] += 2;
}

void sev_snp_handle_vc(struct arch_exec_context *ec)
{
        int errorcode;

        errorcode = ec->reg[EC];

        switch (errorcode) {
        case VM_EXIT_CPUID:
                handle_cpuid_vc(ec);
                break;
        default:
                BUG_ON(1);
                break;
        }
}
