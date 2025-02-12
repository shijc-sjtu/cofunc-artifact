#pragma once

#include <common/types.h>
#include <arch/sched/arch_sched.h>
#include <common/bitops.h>

#define VM_EXIT_CPUID    0x072
#define VM_EXIT_IOIO     0x07b
#define VM_EXIT_MSR      0x07c
#define VM_EXIT_VMMCALL  0x081
#define VM_EXIT_WBINVD   0x089

/* SEV-ES software-defined VMGEXIT events */
#define SVM_VMGEXIT_MMIO_READ			0x80000001
#define SVM_VMGEXIT_MMIO_WRITE			0x80000002
#define SVM_VMGEXIT_NMI_COMPLETE		0x80000003
#define SVM_VMGEXIT_AP_HLT_LOOP			0x80000004
#define SVM_VMGEXIT_AP_JUMP_TABLE		0x80000005
#define SVM_VMGEXIT_SET_AP_JUMP_TABLE		0
#define SVM_VMGEXIT_GET_AP_JUMP_TABLE		1
#define SVM_VMGEXIT_PSC				0x80000010
#define SVM_VMGEXIT_GUEST_REQUEST		0x80000011
#define SVM_VMGEXIT_EXT_GUEST_REQUEST		0x80000012
#define SVM_VMGEXIT_AP_CREATION			0x80000013
#define SVM_VMGEXIT_AP_CREATE_ON_INIT		0
#define SVM_VMGEXIT_AP_CREATE			1
#define SVM_VMGEXIT_AP_DESTROY			2
#define SVM_VMGEXIT_HV_FEATURES			0x8000fffd
#define SVM_VMGEXIT_UNSUPPORTED_EVENT		0x8000ffff

#define IOIO_TYPE_IN   1
#define IOIO_TYPE_OUT  0
#define IOIO_ADDR_64   BIT(9)
#define IOIO_ADDR_32   BIT(8)
#define IOIO_ADDR_16   BIT(7)
#define IOIO_DATA_32   BIT(6)
#define IOIO_DATA_16   BIT(5)
#define IOIO_DATA_8    BIT(4)

#define MSR_TYPE_READ   0
#define MSR_TYPE_WRITE  1

#define AP_JUMP_TABLE_SET  0
#define AP_JUMP_TABLE_GET  1

#define GHCB_MSR_RUNE_REQ  0x200

/* Software defined (when rFlags.CF = 1) */
#define PVALIDATE_FAIL_NOUPDATE		255

/* RMP page size */
#define RMP_PG_SIZE_4K			0
#define RMP_PG_SIZE_2M			1

#define GHCB_MSR_PSC_REQ		0x014
#define GHCB_MSR_PSC_GFN_POS		12
#define GHCB_MSR_PSC_GFN_MASK		GENMASK_ULL(39, 0)
#define GHCB_MSR_PSC_OP_POS		52
#define GHCB_MSR_PSC_OP_MASK		0xf
#define GHCB_MSR_PSC_REQ_GFN(gfn, op)			\
        /* GHCBData[55:52] */				\
        (((u64)((op) & 0xf) << 52) |			\
        /* GHCBData[51:12] */				\
        ((u64)((gfn) & GENMASK_ULL(39, 0)) << 12) |	\
        /* GHCBData[11:0] */				\
        GHCB_MSR_PSC_REQ)

#define GHCB_MSR_PSC_RESP		0x015
#define GHCB_MSR_PSC_ERROR_POS		32
#define GHCB_MSR_PSC_ERROR_MASK		GENMASK_ULL(31, 0)
#define GHCB_MSR_PSC_ERROR		GENMASK_ULL(31, 0)
#define GHCB_MSR_PSC_RSVD_POS		12
#define GHCB_MSR_PSC_RSVD_MASK		GENMASK_ULL(19, 0)
#define GHCB_MSR_PSC_RESP_VAL(val)			\
        /* GHCBData[63:32] */				\
        (((u64)(val) & GENMASK_ULL(63, 32)) >> 32)

#define GHCB_MSR_INFO_POS		0
#define GHCB_DATA_LOW			12
#define GHCB_MSR_INFO_MASK		((1ULL << GHCB_DATA_LOW) - 1)

#define GHCB_RESP_CODE(v)		((v) & GHCB_MSR_INFO_MASK)

/* GHCB GPA Register */
#define GHCB_MSR_REG_GPA_REQ		0x012
#define GHCB_MSR_REG_GPA_REQ_VAL(v)			\
        /* GHCBData[63:12] */				\
        (((u64)((v) & GENMASK_ULL(51, 0)) << 12) |	\
        /* GHCBData[11:0] */				\
        GHCB_MSR_REG_GPA_REQ)

#define GHCB_MSR_REG_GPA_RESP		0x013
#define GHCB_MSR_REG_GPA_RESP_VAL(v)			\
        /* GHCBData[63:12] */				\
        (((u64)(v) & GENMASK_ULL(63, 12)) >> 12)

/* AP INIT values as documented in the APM2  section "Processor Initialization State" */
#define AP_INIT_CS_LIMIT		0xffff
#define AP_INIT_DS_LIMIT		0xffff
#define AP_INIT_LDTR_LIMIT		0xffff
#define AP_INIT_GDTR_LIMIT		0xffff
#define AP_INIT_IDTR_LIMIT		0xffff
#define AP_INIT_TR_LIMIT		0xffff
#define AP_INIT_RFLAGS_DEFAULT		0x2
#define AP_INIT_DR6_DEFAULT		0xffff0ff0
#define AP_INIT_GPAT_DEFAULT		0x0007040600070406ULL
#define AP_INIT_XCR0_DEFAULT		0x1
#define AP_INIT_X87_FTW_DEFAULT		0x5555
#define AP_INIT_X87_FCW_DEFAULT		0x0040
#define AP_INIT_CR0_DEFAULT		0x60000010
#define AP_INIT_MXCSR_DEFAULT		0x1f80

#define SVM_SELECTOR_S_SHIFT 4
#define SVM_SELECTOR_DPL_SHIFT 5
#define SVM_SELECTOR_P_SHIFT 7
#define SVM_SELECTOR_AVL_SHIFT 8
#define SVM_SELECTOR_L_SHIFT 9
#define SVM_SELECTOR_DB_SHIFT 10
#define SVM_SELECTOR_G_SHIFT 11

#define SVM_SELECTOR_TYPE_MASK (0xf)
#define SVM_SELECTOR_S_MASK (1 << SVM_SELECTOR_S_SHIFT)
#define SVM_SELECTOR_DPL_MASK (3 << SVM_SELECTOR_DPL_SHIFT)
#define SVM_SELECTOR_P_MASK (1 << SVM_SELECTOR_P_SHIFT)
#define SVM_SELECTOR_AVL_MASK (1 << SVM_SELECTOR_AVL_SHIFT)
#define SVM_SELECTOR_L_MASK (1 << SVM_SELECTOR_L_SHIFT)
#define SVM_SELECTOR_DB_MASK (1 << SVM_SELECTOR_DB_SHIFT)
#define SVM_SELECTOR_G_MASK (1 << SVM_SELECTOR_G_SHIFT)

#define SVM_SELECTOR_WRITE_MASK (1 << 1)
#define SVM_SELECTOR_READ_MASK SVM_SELECTOR_WRITE_MASK
#define SVM_SELECTOR_CODE_MASK (1 << 3)

#define INIT_LDTR_ATTRIBS	(SVM_SELECTOR_P_MASK | 2)
#define INIT_TR_ATTRIBS		(SVM_SELECTOR_P_MASK | 3)

#define __ATTR_BASE		(SVM_SELECTOR_P_MASK | SVM_SELECTOR_S_MASK)
#define INIT_CS_ATTRIBS		(__ATTR_BASE | SVM_SELECTOR_READ_MASK | SVM_SELECTOR_CODE_MASK)
#define INIT_DS_ATTRIBS		(__ATTR_BASE | SVM_SELECTOR_WRITE_MASK)

#define DR7_RESET_VALUE        0x400

/* EFER bits: */
#define _EFER_SCE		0  /* SYSCALL/SYSRET */
#define _EFER_LME		8  /* Long mode enable */
#define _EFER_LMA		10 /* Long mode active (read-only) */
#define _EFER_NX		11 /* No execute enable */
#define _EFER_SVME		12 /* Enable virtualization */
#define _EFER_LMSLE		13 /* Long Mode Segment Limit Enable */
#define _EFER_FFXSR		14 /* Enable Fast FXSAVE/FXRSTOR */

#define EFER_SCE		(1<<_EFER_SCE)
#define EFER_LME		(1<<_EFER_LME)
#define EFER_LMA		(1<<_EFER_LMA)
#define EFER_NX			(1<<_EFER_NX)
#define EFER_SVME		(1<<_EFER_SVME)
#define EFER_LMSLE		(1<<_EFER_LMSLE)
#define EFER_FFXSR		(1<<_EFER_FFXSR)

#define X86_CR4_MCE_BIT		6 /* Machine check enable */
#define X86_CR4_MCE             (1UL<<X86_CR4_MCE_BIT)

#define RMPADJUST_VMSA_PAGE_BIT		BIT(16)

struct ghcb {
        u8 reserved1[0xcb];
        u8 cpl;
        u8 reserved2[0x74];
        u64 xss;
        u8 reserved3[0x18];
        u64 dr7;
        u8 reserved4[0x90];
        u64 rax;
        u8 reserved5[0x108];
        u64 rcx;
        u64 rdx;
        u64 rbx;
        u8 reserved6[0x70];
        u64 sw_exitcode;
        u64 sw_exitinfo1;
        u64 sw_exitinfo2;
        u64 sw_scratch;
        u8 reserved7[0x38];
        u64 xcr0;
        u8 valid_bitmap[0x10];
        u64 x87_state_gpa;
        u8 reserved8[0x3f8];
        u8 shared_buffer[0x7f0];
        u8 reserved9[0xa];
        u16 protocol_version;
        u32 ghcb_usage;
} __attribute__((packed, aligned(0x1000)));

struct ap_reset_addr {
        u16 ip;
        u16 cs;
} __attribute__((packed));

/*
 * SNP Page State Change Operation
 *
 * GHCBData[55:52] - Page operation:
 *   0x0001	Page assignment, Private
 *   0x0002	Page assignment, Shared
 */
enum psc_op {
        SNP_PAGE_STATE_PRIVATE = 1,
        SNP_PAGE_STATE_SHARED,
};

/* SNP Page State Change NAE event */
#define VMGEXIT_PSC_MAX_ENTRY		253

struct psc_hdr {
	u16 cur_entry;
	u16 end_entry;
	u32 reserved;
} __attribute__((packed));

struct psc_entry {
	u64	cur_page	: 12,
		gfn		: 40,
		operation	: 4,
		pagesize	: 1,
		reserved	: 7;
} __attribute__((packed));

struct snp_psc_desc {
	struct psc_hdr hdr;
	struct psc_entry entries[VMGEXIT_PSC_MAX_ENTRY];
} __attribute__((packed));

struct vmcb_seg {
	u16 selector;
	u16 attrib;
	u32 limit;
	u64 base;
} __attribute__((packed));

/* Save area definition for SEV-ES and SEV-SNP guests */
struct sev_es_save_area {
	struct vmcb_seg es;
	struct vmcb_seg cs;
	struct vmcb_seg ss;
	struct vmcb_seg ds;
	struct vmcb_seg fs;
	struct vmcb_seg gs;
	struct vmcb_seg gdtr;
	struct vmcb_seg ldtr;
	struct vmcb_seg idtr;
	struct vmcb_seg tr;
	u64 vmpl0_ssp;
	u64 vmpl1_ssp;
	u64 vmpl2_ssp;
	u64 vmpl3_ssp;
	u64 u_cet;
	u8 reserved_0xc8[2];
	u8 vmpl;
	u8 cpl;
	u8 reserved_0xcc[4];
	u64 efer;
	u8 reserved_0xd8[104];
	u64 xss;
	u64 cr4;
	u64 cr3;
	u64 cr0;
	u64 dr7;
	u64 dr6;
	u64 rflags;
	u64 rip;
	u64 dr0;
	u64 dr1;
	u64 dr2;
	u64 dr3;
	u64 dr0_addr_mask;
	u64 dr1_addr_mask;
	u64 dr2_addr_mask;
	u64 dr3_addr_mask;
	u8 reserved_0x1c0[24];
	u64 rsp;
	u64 s_cet;
	u64 ssp;
	u64 isst_addr;
	u64 rax;
	u64 star;
	u64 lstar;
	u64 cstar;
	u64 sfmask;
	u64 kernel_gs_base;
	u64 sysenter_cs;
	u64 sysenter_esp;
	u64 sysenter_eip;
	u64 cr2;
	u8 reserved_0x248[32];
	u64 g_pat;
	u64 dbgctl;
	u64 br_from;
	u64 br_to;
	u64 last_excp_from;
	u64 last_excp_to;
	u8 reserved_0x298[80];
	u32 pkru;
	u32 tsc_aux;
	u8 reserved_0x2f0[24];
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u64 reserved_0x320;	/* rsp already available at 0x01d8 */
	u64 rbp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u8 reserved_0x380[16];
	u64 guest_exit_info_1;
	u64 guest_exit_info_2;
	u64 guest_exit_int_info;
	u64 guest_nrip;
	u64 sev_features;
	u64 vintr_ctrl;
	u64 guest_exit_code;
	u64 virtual_tom;
	u64 tlb_id;
	u64 pcpu_id;
	u64 event_inj;
	u64 xcr0;
	u8 reserved_0x3f0[16];

	/* Floating point area */
	u64 x87_dp;
	u32 mxcsr;
	u16 x87_ftw;
	u16 x87_fsw;
	u16 x87_fcw;
	u16 x87_fop;
	u16 x87_ds;
	u16 x87_cs;
	u64 x87_rip;
	u8 fpreg_x87[80];
	u8 fpreg_xmm[256];
	u8 fpreg_ymm[256];
} __attribute__((packed));

void sev_snp_init_per_cpu_ghcb(u32 cpuid);
void sev_snp_do_wbinvd(void);
u32 sev_snp_do_in(u16 addr, int data_width);
void sev_snp_do_out(u16 addr, u32 data, int data_width);
void sev_snp_do_cpuid(u32 *eax, u32 *ebx, u32 *ecx, u32 *edx);
u64 sev_snp_do_rdmsr(u64 msr);
void sev_snp_do_wrmsr(u64 msr, u64 val);
void sev_snp_wakeup_cpu(u32 apic_id, u64 start_ip);
long sev_snp_do_hypercall(unsigned int nr, unsigned long p1, unsigned long p2, unsigned long p3);
bool sev_snp_enc_status_changed_phys(paddr_t start, paddr_t end, bool enc);
void sev_snp_handle_vc(struct arch_exec_context *ec);
