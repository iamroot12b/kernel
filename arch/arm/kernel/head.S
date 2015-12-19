/*
 *  linux/arch/arm/kernel/head.S
 *
 *  Copyright (C) 1994-2002 Russell King
 *  Copyright (c) 2003 ARM Limited
 *  All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  Kernel startup code for all 32-bit CPUs
 */
#include <linux/linkage.h>
#include <linux/init.h>

#include <asm/assembler.h>
#include <asm/cp15.h>
#include <asm/domain.h>
#include <asm/ptrace.h>
#include <asm/asm-offsets.h>
#include <asm/memory.h>
#include <asm/thread_info.h>
#include <asm/pgtable.h>

#if defined(CONFIG_DEBUG_LL) && !defined(CONFIG_DEBUG_SEMIHOSTING)
#include CONFIG_DEBUG_LL_INCLUDE
#endif

/*
 * swapper_pg_dir is the virtual address of the initial page table.
 * We place the page tables 16K below KERNEL_RAM_VADDR.  Therefore, we must
 * make sure that KERNEL_RAM_VADDR is correctly set.  Currently, we expect
 * the least significant 16 bits to be 0x8000, but we could probably
 * relax this restriction to KERNEL_RAM_VADDR >= PAGE_OFFSET + 0x4000.
 */
#define KERNEL_RAM_VADDR	(PAGE_OFFSET + TEXT_OFFSET)
#if (KERNEL_RAM_VADDR & 0xffff) != 0x8000
#error KERNEL_RAM_VADDR must start at 0xXXXX8000
#endif

#ifdef CONFIG_ARM_LPAE
	/* LPAE requires an additional page for the PGD */
#define PG_DIR_SIZE	0x5000
#define PMD_ORDER	3
#else
#define PG_DIR_SIZE	0x4000
#define PMD_ORDER	2
#endif

	.globl	swapper_pg_dir
	.equ	swapper_pg_dir, KERNEL_RAM_VADDR - PG_DIR_SIZE

	.macro	pgtbl, rd, phys
	add	\rd, \phys, #TEXT_OFFSET
	sub	\rd, \rd, #PG_DIR_SIZE
	.endm

/* ================================================ */
/* IAMROOT-12-B,31th(2015.11.21 15:00): Start	    */
/* ================================================ */

/*
 * Kernel startup entry point.
 * ---------------------------
 *
 * This is normally called from the decompressor code.  The requirements
 * are: MMU = off, D-cache = off, I-cache = dont care, r0 = 0,
 * r1 = machine nr, r2 = atags or dtb pointer.
 *
 * This code is mostly position independent, so if you link the kernel at
 * 0xc0008000, you call this at __pa(0xc0008000).
 * >>> IAMROOT-12-B
 * 빌드시 config 파일 확인시 CONFIG_PAGE_OFFSET=0x80000000 
 * in case of raspberry pi2, 0x80008000, root/arch/arm/include/asm -> memory.h 
 * 파일에 __pa(0xXXXXXXXX) 함수를 통해 물리주소를 구할 수 있음. 
 * <<<
 *
 * See linux/arch/arm/tools/mach-types for the complete list of machine
 * numbers for r1.
 *
 * We're trying to keep crap to a minimum; DO NOT add any machine specific
 * crap here - that's what the boot loader (or in extreme, well justified
 * circumstances, zImage) is for.
 */
	.arm
/* >>> IAMROOT-12-B
 * __HEAD : root/include/linux/init.h파일에 define되어 있음, 
 * #define __HEAD		.section	".head.text","ax", "ax"의미는 allowable section
 * compile시 section을 할당키 위해 macro로 선언되어 있음.
 * ENTRY macro함수, input된 라벨을 .global로 선언. : ENTRY(root/include/linux -> linkage.h 파일에 선언되어 있음.
 * stext의 label을 text start로 하고자 함.
 *
 * #ifndef ENTRY
 * #define ENTRY(name) \
 *  .globl name ASM_NL \											@ASM_NL -> ; (구분자)
 *  ALIGN ASM_NL \														@ALIGN -> .align 4,0x90 (2의4으로 align하고, padding되는 데이터는 0x90으로 채운다
 *																							@						[issue1] 왜 0x90으로 채울까? 0x90은 NOP
 *																							@						b/bl 명령일 것 같은 경우, pipeline을 비우지만 compressed head.s에서 kernel head.s jump시
 *																							@						pipeline이 깨졌을 것이라 추정되기 때문에 align 통해 padding된 데이터 처리시 pipeline을 
 *																							@						비울 것이라 추정됨.
 *																							@						[Issue2] : mov pc, r0 연산으로 통해 pc변경시 pipeline 처리가 어떻게 되는지 확인필요?
 *  name:
 * #endif
 * <<<
 *
*/
	__HEAD
ENTRY(stext)

 /* >>> IAMROOT-12-B
  * if set config big endian type 빅엔디안일 경우면 셋엔디안을 빅에디안으로 바꾸어라. 
  * <<<
  */
 ARM_BE8(setend	be )			@ ensure we are in BE8 mode

/* >>> IAMROOT-12-B
 * THUMB -> thumb 모드 일때 수행되는 코드
 * <<<
*/
 THUMB(	adr	r9, BSYM(1f)	)	@ Kernel is always entered in ARM.
 THUMB(	bx	r9		)	@ If this is a Thumb-2 kernel,
 THUMB(	.thumb			)	@ switch to Thumb now.
 THUMB(1:			)

#ifdef CONFIG_ARM_VIRT_EXT
	bl	__hyp_stub_install							@IAMROOT-12-B : root/arch/arm/kernel -> hyp-stub.s : mode값을 특정 위치에 저장하여 backup처리
#endif
	@ ensure svc mode and all interrupts masked
	safe_svcmode_maskall r9						@IAMROOT-12-B : interrup masking 처리, svcmode로 설정 처리

/* ================================================ */
/* IAMROOT-12-B,33th(2015.12.05 15:30)              */
/* ================================================ */
/* Coprocessor로부터 processor ID 정보를 r9로 읽어온 후,
 * __lookup_processor_type 라벨로 분기하여,
 * 커널이 해당 processor를 지원하는지를 확인한 후,
 * 지원한다면, 해당 processor ID 정보를 담고있는 
 * 구조체 배열의 해당 index의 주소 값을 r5에 저장하고,
 * 지원하지 않는다면, r5에는 '0'값을 저장한 후,
 * 복귀하여, r5의 값이 유효한지를 판단하여,
 * 0이면 __error_p로 분기한다.
 */
	mrc	p15, 0, r9, c0, c0		@ get processor id	@IAMROOT-12-B : r9 = cpu info 정보, DDI0406C_b_armV7_AR_architecture_reference_manual.pdf page 1648
	bl	__lookup_processor_type		@ r5=procinfo r9=cpuid
	movs	r10, r5				@ invalid processor (r5=0)?				@IAMROOT-12-B : r5 = processor info address
 THUMB( it	eq )		@ force fixup-able long branch encoding
	beq	__error_p			@ yes, error 'p'										@IAMROOT-12-B : r10 = 0x00 이면 error 처리

/* ================================================ */
/* IAMROOT-12-B,33th(2015.12.05 15:30)              */
/* ================================================ */
/* 커널이 64bit 주소 변환 기능(LPAE)을 사용하겠다고
 * 설정한 상태에서,
 * 실제로 해당 processor가 64bit 주소 변환 기능(LPAE)을
 * 지원하는지를 CP15의 ID_MMFR0(c0-0,c1-4) 레지스터의 
 * 하위 [0:3] bit의 VMSA Support를 보고 판단하는데,
 * 값이 5인 경우는 지원하고 0~4는 LPAE를 지원하지 않으며,
 * 0~4인 경우는 __error_lpae로 분기한다.
 */
#ifdef CONFIG_ARM_LPAE
	mrc	p15, 0, r3, c0, c1, 4		@ read ID_MMFR0
	and	r3, r3, #0xf			@ extract VMSA support
	cmp	r3, #5				@ long-descriptor translation table format?
 THUMB( it	lo )				@ force fixup-able long branch encoding
	blo	__error_lpae			@ only classic page table format
#endif

/* ================================================ */
/* IAMROOT-12-B,33th(2015.12.05 15:30)              */
/* ================================================ */
/*
 * CONFIG_XIP_KERNEL is not set in Rpi-2
 * PC 기준 2f 라벨의 주소 값을 r3에 저장하고,
 * 커널의 가상 주소에서 r3를 빼 실제 2f 라벨의
 * 물리 주소에 해당하는 offset 값을 구한다.
 */
#ifndef CONFIG_XIP_KERNEL
	adr	r3, 2f
	ldmia	r3, {r4, r8}																	@IAMROOT-12-B : r3 = 0x8080, r4 = 0x80008080, r8 = 0x80000000
	sub	r4, r3, r4			@ (PHYS_OFFSET - PAGE_OFFSET)
	add	r8, r8, r4			@ PHYS_OFFSET										@IAMROOT-12-B : r4 = 0x80000000, r8 = 0x80000000, final r8 = 0x00
#else
	ldr	r8, =PLAT_PHYS_OFFSET		@ always constant in this case
#endif

	/*
	 * r1 = machine no, r2 = atags or dtb,
	 * r8 = phys_offset, r9 = cpuid, r10 = procinfo
	 */
	bl	__vet_atags																			@IAMROOT-12-B : atag, dtb관련 내용은 이후 소스 분석시 상세 분석 필요
#ifdef CONFIG_SMP_ON_UP
	bl	__fixup_smp
#endif
#ifdef CONFIG_ARM_PATCH_PHYS_VIRT
	bl	__fixup_a_pv_table				@IAMROOT-12-B : http://stackcanary.com/?p=616
#endif
	bl	__create_page_tables

	/*
	 * The following calls CPU specific code in a position independent
	 * manner.  See arch/arm/mm/proc-*.S for details.  r10 = base of
	 * xxx_proc_info structure selected by __lookup_processor_type
	 * above.  On return, the CPU will be ready for the MMU to be
	 * turned on, and r0 will hold the CPU control register value.
	 */
	ldr	r13, =__mmap_switched		@ address to jump to after
						@ mmu has been enabled
	adr	lr, BSYM(1f)			@ return (PIC) address
	mov	r8, r4				@ set TTBR1 to swapper_pg_dir
 ARM(	add	pc, r10, #PROCINFO_INITFUNC	)
 THUMB(	add	r12, r10, #PROCINFO_INITFUNC	)
 THUMB(	ret	r12				)
1:	b	__enable_mmu
ENDPROC(stext)
	.ltorg
#ifndef CONFIG_XIP_KERNEL
2:	.long	.
	.long	PAGE_OFFSET
#endif

/*
 * Setup the initial page tables.  We only setup the barest
 * amount which are required to get the kernel running, which
 * generally means mapping in the kernel code.
 *
 * r8 = phys_offset, r9 = cpuid, r10 = procinfo
 *
 * Returns:
 *  r0, r3, r5-r7 corrupted
 *  r4 = page table (see ARCH_PGD_SHIFT in asm/memory.h)
 */
__create_page_tables:
	pgtbl	r4, r8				@ page table address

	/*
	 * Clear the swapper page table
	 */
	mov	r0, r4
	mov	r3, #0
	add	r6, r0, #PG_DIR_SIZE
1:	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
	teq	r0, r6
	bne	1b

#ifdef CONFIG_ARM_LPAE
	/*
	 * Build the PGD table (first level) to point to the PMD table. A PGD
	 * entry is 64-bit wide.
	 */
	mov	r0, r4
	add	r3, r4, #0x1000			@ first PMD table address
	orr	r3, r3, #3			@ PGD block type
	mov	r6, #4				@ PTRS_PER_PGD
	mov	r7, #1 << (55 - 32)		@ L_PGD_SWAPPER
1:
#ifdef CONFIG_CPU_ENDIAN_BE8
	str	r7, [r0], #4			@ set top PGD entry bits
	str	r3, [r0], #4			@ set bottom PGD entry bits
#else
	str	r3, [r0], #4			@ set bottom PGD entry bits
	str	r7, [r0], #4			@ set top PGD entry bits
#endif
	add	r3, r3, #0x1000			@ next PMD table
	subs	r6, r6, #1
	bne	1b

	add	r4, r4, #0x1000			@ point to the PMD tables
#ifdef CONFIG_CPU_ENDIAN_BE8
	add	r4, r4, #4			@ we only write the bottom word
#endif
#endif

	ldr	r7, [r10, #PROCINFO_MM_MMUFLAGS] @ mm_mmuflags

	/*
	 * Create identity mapping to cater for __enable_mmu.
	 * This identity mapping will be removed by paging_init().
	 */
	adr	r0, __turn_mmu_on_loc
	ldmia	r0, {r3, r5, r6}
	sub	r0, r0, r3			@ virt->phys offset
	add	r5, r5, r0			@ phys __turn_mmu_on
	add	r6, r6, r0			@ phys __turn_mmu_on_end
	mov	r5, r5, lsr #SECTION_SHIFT
	mov	r6, r6, lsr #SECTION_SHIFT

1:	orr	r3, r7, r5, lsl #SECTION_SHIFT	@ flags + kernel base
	str	r3, [r4, r5, lsl #PMD_ORDER]	@ identity mapping
	cmp	r5, r6
	addlo	r5, r5, #1			@ next section
	blo	1b

	/*
	 * Map our RAM from the start to the end of the kernel .bss section.
	 */
	add	r0, r4, #PAGE_OFFSET >> (SECTION_SHIFT - PMD_ORDER)
	ldr	r6, =(_end - 1)
	orr	r3, r8, r7
	add	r6, r4, r6, lsr #(SECTION_SHIFT - PMD_ORDER)
1:	str	r3, [r0], #1 << PMD_ORDER
	add	r3, r3, #1 << SECTION_SHIFT
	cmp	r0, r6
	bls	1b

#ifdef CONFIG_XIP_KERNEL
	/*
	 * Map the kernel image separately as it is not located in RAM.
	 */
#define XIP_START XIP_VIRT_ADDR(CONFIG_XIP_PHYS_ADDR)
	mov	r3, pc
	mov	r3, r3, lsr #SECTION_SHIFT
	orr	r3, r7, r3, lsl #SECTION_SHIFT
	add	r0, r4,  #(XIP_START & 0xff000000) >> (SECTION_SHIFT - PMD_ORDER)
	str	r3, [r0, #((XIP_START & 0x00f00000) >> SECTION_SHIFT) << PMD_ORDER]!
	ldr	r6, =(_edata_loc - 1)
	add	r0, r0, #1 << PMD_ORDER
	add	r6, r4, r6, lsr #(SECTION_SHIFT - PMD_ORDER)
1:	cmp	r0, r6
	add	r3, r3, #1 << SECTION_SHIFT
	strls	r3, [r0], #1 << PMD_ORDER
	bls	1b
#endif

	/*
	 * Then map boot params address in r2 if specified.
	 * We map 2 sections in case the ATAGs/DTB crosses a section boundary.
	 */
	mov	r0, r2, lsr #SECTION_SHIFT
	movs	r0, r0, lsl #SECTION_SHIFT
	subne	r3, r0, r8
	addne	r3, r3, #PAGE_OFFSET
	addne	r3, r4, r3, lsr #(SECTION_SHIFT - PMD_ORDER)
	orrne	r6, r7, r0
	strne	r6, [r3], #1 << PMD_ORDER
	addne	r6, r6, #1 << SECTION_SHIFT
	strne	r6, [r3]

#if defined(CONFIG_ARM_LPAE) && defined(CONFIG_CPU_ENDIAN_BE8)
	sub	r4, r4, #4			@ Fixup page table pointer
						@ for 64-bit descriptors
#endif

#ifdef CONFIG_DEBUG_LL
#if !defined(CONFIG_DEBUG_ICEDCC) && !defined(CONFIG_DEBUG_SEMIHOSTING)
	/*
	 * Map in IO space for serial debugging.
	 * This allows debug messages to be output
	 * via a serial console before paging_init.
	 */
	addruart r7, r3, r0

	mov	r3, r3, lsr #SECTION_SHIFT
	mov	r3, r3, lsl #PMD_ORDER

	add	r0, r4, r3
	mov	r3, r7, lsr #SECTION_SHIFT
	ldr	r7, [r10, #PROCINFO_IO_MMUFLAGS] @ io_mmuflags
	orr	r3, r7, r3, lsl #SECTION_SHIFT
#ifdef CONFIG_ARM_LPAE
	mov	r7, #1 << (54 - 32)		@ XN
#ifdef CONFIG_CPU_ENDIAN_BE8
	str	r7, [r0], #4
	str	r3, [r0], #4
#else
	str	r3, [r0], #4
	str	r7, [r0], #4
#endif
#else
	orr	r3, r3, #PMD_SECT_XN
	str	r3, [r0], #4
#endif

#else /* CONFIG_DEBUG_ICEDCC || CONFIG_DEBUG_SEMIHOSTING */
	/* we don't need any serial debugging mappings */
	ldr	r7, [r10, #PROCINFO_IO_MMUFLAGS] @ io_mmuflags
#endif

#if defined(CONFIG_ARCH_NETWINDER) || defined(CONFIG_ARCH_CATS)
	/*
	 * If we're using the NetWinder or CATS, we also need to map
	 * in the 16550-type serial port for the debug messages
	 */
	add	r0, r4, #0xff000000 >> (SECTION_SHIFT - PMD_ORDER)
	orr	r3, r7, #0x7c000000
	str	r3, [r0]
#endif
#ifdef CONFIG_ARCH_RPC
	/*
	 * Map in screen at 0x02000000 & SCREEN2_BASE
	 * Similar reasons here - for debug.  This is
	 * only for Acorn RiscPC architectures.
	 */
	add	r0, r4, #0x02000000 >> (SECTION_SHIFT - PMD_ORDER)
	orr	r3, r7, #0x02000000
	str	r3, [r0]
	add	r0, r4, #0xd8000000 >> (SECTION_SHIFT - PMD_ORDER)
	str	r3, [r0]
#endif
#endif
#ifdef CONFIG_ARM_LPAE
	sub	r4, r4, #0x1000		@ point to the PGD table
	mov	r4, r4, lsr #ARCH_PGD_SHIFT
#endif
	ret	lr
ENDPROC(__create_page_tables)
	.ltorg
	.align
__turn_mmu_on_loc:
	.long	.
	.long	__turn_mmu_on
	.long	__turn_mmu_on_end

#if defined(CONFIG_SMP)
	.text
ENTRY(secondary_startup_arm)
	.arm
 THUMB(	adr	r9, BSYM(1f)	)	@ Kernel is entered in ARM.
 THUMB(	bx	r9		)	@ If this is a Thumb-2 kernel,
 THUMB(	.thumb			)	@ switch to Thumb now.
 THUMB(1:			)
ENTRY(secondary_startup)
	/*
	 * Common entry point for secondary CPUs.
	 *
	 * Ensure that we're in SVC mode, and IRQs are disabled.  Lookup
	 * the processor type - there is no need to check the machine type
	 * as it has already been validated by the primary processor.
	 */

 ARM_BE8(setend	be)				@ ensure we are in BE8 mode

#ifdef CONFIG_ARM_VIRT_EXT
	bl	__hyp_stub_install_secondary
#endif
	safe_svcmode_maskall r9

	mrc	p15, 0, r9, c0, c0		@ get processor id
	bl	__lookup_processor_type
	movs	r10, r5				@ invalid processor?
	moveq	r0, #'p'			@ yes, error 'p'
 THUMB( it	eq )		@ force fixup-able long branch encoding
	beq	__error_p

	/*
	 * Use the page tables supplied from  __cpu_up.
	 */
	adr	r4, __secondary_data
	ldmia	r4, {r5, r7, r12}		@ address to jump to after
	sub	lr, r4, r5			@ mmu has been enabled
	ldr	r4, [r7, lr]			@ get secondary_data.pgdir
	add	r7, r7, #4
	ldr	r8, [r7, lr]			@ get secondary_data.swapper_pg_dir
	adr	lr, BSYM(__enable_mmu)		@ return address
	mov	r13, r12			@ __secondary_switched address
 ARM(	add	pc, r10, #PROCINFO_INITFUNC	) @ initialise processor
						  @ (return control reg)
 THUMB(	add	r12, r10, #PROCINFO_INITFUNC	)
 THUMB(	ret	r12				)
ENDPROC(secondary_startup)
ENDPROC(secondary_startup_arm)

	/*
	 * r6  = &secondary_data
	 */
ENTRY(__secondary_switched)
	ldr	sp, [r7, #4]			@ get secondary_data.stack
	mov	fp, #0
	b	secondary_start_kernel
ENDPROC(__secondary_switched)

	.align

	.type	__secondary_data, %object
__secondary_data:
	.long	.
	.long	secondary_data
	.long	__secondary_switched
#endif /* defined(CONFIG_SMP) */



/*
 * Setup common bits before finally enabling the MMU.  Essentially
 * this is just loading the page table pointer and domain access
 * registers.
 *
 *  r0  = cp#15 control register
 *  r1  = machine ID
 *  r2  = atags or dtb pointer
 *  r4  = page table (see ARCH_PGD_SHIFT in asm/memory.h)
 *  r9  = processor ID
 *  r13 = *virtual* address to jump to upon completion
 */
__enable_mmu:
#if defined(CONFIG_ALIGNMENT_TRAP) && __LINUX_ARM_ARCH__ < 6
	orr	r0, r0, #CR_A
#else
	bic	r0, r0, #CR_A
#endif
#ifdef CONFIG_CPU_DCACHE_DISABLE
	bic	r0, r0, #CR_C
#endif
#ifdef CONFIG_CPU_BPREDICT_DISABLE
	bic	r0, r0, #CR_Z
#endif
#ifdef CONFIG_CPU_ICACHE_DISABLE
	bic	r0, r0, #CR_I
#endif
#ifndef CONFIG_ARM_LPAE
	mov	r5, #(domain_val(DOMAIN_USER, DOMAIN_MANAGER) | \
		      domain_val(DOMAIN_KERNEL, DOMAIN_MANAGER) | \
		      domain_val(DOMAIN_TABLE, DOMAIN_MANAGER) | \
		      domain_val(DOMAIN_IO, DOMAIN_CLIENT))
	mcr	p15, 0, r5, c3, c0, 0		@ load domain access register
	mcr	p15, 0, r4, c2, c0, 0		@ load page table pointer
#endif
	b	__turn_mmu_on
ENDPROC(__enable_mmu)

/*
 * Enable the MMU.  This completely changes the structure of the visible
 * memory space.  You will not be able to trace execution through this.
 * If you have an enquiry about this, *please* check the linux-arm-kernel
 * mailing list archives BEFORE sending another post to the list.
 *
 *  r0  = cp#15 control register
 *  r1  = machine ID
 *  r2  = atags or dtb pointer
 *  r9  = processor ID
 *  r13 = *virtual* address to jump to upon completion
 *
 * other registers depend on the function called upon completion
 */
	.align	5
	.pushsection	.idmap.text, "ax"
ENTRY(__turn_mmu_on)
	mov	r0, r0
	instr_sync
	mcr	p15, 0, r0, c1, c0, 0		@ write control reg
	mrc	p15, 0, r3, c0, c0, 0		@ read id reg
	instr_sync
	mov	r3, r3
	mov	r3, r13
	ret	r3
__turn_mmu_on_end:
ENDPROC(__turn_mmu_on)
	.popsection


#ifdef CONFIG_SMP_ON_UP															@IAMROOT-12-B : 
	__HEAD
__fixup_smp:
	and	r3, r9, #0x000f0000	@ architecture version		@IAMROOT-12-B : r9 = processor id, 
	teq	r3, #0x000f0000		@ CPU ID supported?
	bne	__fixup_smp_on_up	@ no, assume UP							@IAMROOT-12-B : arm v7 arch 이전 버전일 경우에 대해 __fixup_smp_on_up 수행
																										@IAMROOT-12-B : arm v7 arch은 uni-core가 아닌 multi core
																										@IAMROOT-12-B : uniprocessor상에서 수행되지 않는 명령을 가능하기 위해 설정처리
	@IAMROOT-12-B : 아래는 kconfig 내용을 발췌
	/*
	 * config SMP_ON_UP
	 * bool "Allow booting SMP kernel on uniprocessor systems (EXPERIMENTAL)"
	 * depends on SMP && !XIP_KERNEL && MMU
	 * default y
	 * help
	 *   SMP kernels contain instructions which fail on non-SMP processors.
	 *   Enabling this option allows the kernel to modify itself to make
	 *   these instructions safe.  Disabling it allows about 1K of space
	 *   savings.
   * 
	 *   If you don't know what to do here, say Y.
	 */

	bic	r3, r9, #0x00ff0000														@IAMROOT-12-B : r3 = 0x4100xxxx
	bic	r3, r3, #0x0000000f	@ mask 0xff00fff0					@IAMROOT-12-B : r3 = 0x4100xxx0
	mov	r4, #0x41000000																@IAMROOT-12-B : r4 = 0x41000000
	orr	r4, r4, #0x0000b000														@IAMROOT-12-B : 왜 한번에 하면 되지, 세번으로 할까? 32bit processor에서 명령어,데이터를 모두 32bit에 담을 수 없으니
																										@IAMROOT-12-B : 세번을 나누어서 사용하지 않았을까... (추정)
	orr	r4, r4, #0x00000020	@ val 0x4100b020					@IAMROOT-12-B : r4 = 0x4100b020
	teq	r3, r4			@ ARM 11MPCore?										@IAMROOT-12-B : Use the TEQ instruction to test if two values are equal, without affecting the V or C flags (as CMP does).
	reteq	lr			@ yes, assume SMP										@IAMROOT-12-B : zero flag set이면 11MP core면 리턴 처리

	mrc	p15, 0, r0, c0, c0, 5	@ read MPIDR												@IAMROOT-12-B : MPIDR(Multiprocessor Affinity Register)
	and	r0, r0, #0xc0000000	@ multiprocessing extensions and		
	teq	r0, #0x80000000		@ not part of a uniprocessor system?		@IAMROOT-12-B : [31 bit] : RAO (read as one), [30 bit] : 1 (uniprocessor) 0 (multi-processor)
	bne    __fixup_smp_on_up	@ no, assume UP											@IAMROOT-12-B : uni-processor면 수행, multi면 skip

	@ Core indicates it is SMP. Check for Aegis SOC where a single
	@ Cortex-A9 CPU is present but SMP operations fault.
	mov	r4, #0x41000000
	orr	r4, r4, #0x0000c000
	orr	r4, r4, #0x00000090
	teq	r3, r4			@ Check for ARM Cortex-A9											@IAMROOT-12-B : ARM Cortex-A9일 경우, 결과값은 0
	retne	lr			@ Not ARM Cortex-A9,

	@ If a future SoC *does* use 0x0 as the PERIPH_BASE, then the @IAMROOT-12-B : Aegis SOC 예외 처리 코드되는 것으로 추정
	@ below address check will need to be #ifdef'd or equivalent
	@ for the Aegis platform.
	mrc	p15, 4, r0, c15, c0	@ get SCU base address
	teq	r0, #0x0		@ '0' on actual UP A9 hardware
	beq	__fixup_smp_on_up	@ So its an A9 UP
	ldr	r0, [r0, #4]		@ read SCU Config
ARM_BE8(rev	r0, r0)			@ byteswap if big endian
	and	r0, r0, #0x3		@ number of CPUs
	teq	r0, #0x0		@ is 1?
	retne	lr

__fixup_smp_on_up:														@IAMROOT-12-B : uni-processor인 경우에 처리하는 함수
	adr	r0, 1f
	ldmia	r0, {r3 - r5}												@IAMROOT-12-B : save real address
	sub	r3, r0, r3
	add	r4, r4, r3
	add	r5, r5, r3
	b	__do_fixup_smp_on_up
ENDPROC(__fixup_smp)

	.align
1:	.word	.
	.word	__smpalt_begin
	.word	__smpalt_end

	.pushsection .data
	.globl	smp_on_up

	/* SMP 면 1 리턴, UP 면 0 리턴으로 판단됨 */
smp_on_up:
	ALT_SMP(.long	1)
	ALT_UP(.long	0)
	.popsection
#endif

/* ================================================ */
/* IAMROOT-12-B,35th(2015.12.19 18:00)              */
/* ================================================ */
/*
 *  ALT_SMP()와 ALT_UP()는 항상 페어로 존재함.
 *  현재 SMP 모드로 실행될 경우 ALT_SMP가 실행되거나 적용됨
 *  UP 모드인 경우에는 아래 __do_fixup_smp_on_up 을 수행한 결과가 실행이 되기 때문에 UP 명령어가 실행됨
 *  .pushsection name 은 현재 섹션은 섹션 스택에 잠시 넣어놓고 name에 해당하는 섹션으로 current section을 변경
 *  .popsection은 센션 스택의 가장 위에 있는 섹션을 current section으로 만듦 
 *  
 *  arch/arm/include/asm/smp_plat.h:17 is_smp 함수에서 보면 smp_on_up을 사용하는데 smp_on_up은 현재 모드(SMP or UP)에 따른 리턴값으로 판단됨
 */

	.text
__do_fixup_smp_on_up:
	cmp	r4, r5									@IAMROOT-12-B : __smpalt_begin ~ __smpalt_end까지 loop돌면서 처리
	reths	lr
	ldmia	r4!, {r0, r6}
 ARM(	str	r6, [r0, r3]	)
 THUMB(	add	r0, r0, r3	)
#ifdef __ARMEB__
 THUMB(	mov	r6, r6, ror #16	)	@ Convert word order for big-endian.
#endif
 THUMB(	strh	r6, [r0], #2	)	@ For Thumb-2, store as two halfwords
 THUMB(	mov	r6, r6, lsr #16	)	@ to be robust against misaligned r3.
 THUMB(	strh	r6, [r0]	)
	b	__do_fixup_smp_on_up
ENDPROC(__do_fixup_smp_on_up)

ENTRY(fixup_smp)
	stmfd	sp!, {r4 - r6, lr}
	mov	r4, r0
	add	r5, r0, r1
	mov	r3, #0
	bl	__do_fixup_smp_on_up
	ldmfd	sp!, {r4 - r6, pc}
ENDPROC(fixup_smp)

#ifdef __ARMEB__
#define LOW_OFFSET	0x4
#define HIGH_OFFSET	0x0
#else
#define LOW_OFFSET	0x0
#define HIGH_OFFSET	0x4
#endif

#ifdef CONFIG_ARM_PATCH_PHYS_VIRT

/* __fixup_pv_table - patch the stub instructions with the delta between
 * PHYS_OFFSET and PAGE_OFFSET, which is assumed to be 16MiB aligned and
 * can be expressed by an immediate shifter operand. The stub instruction
 * has a form of '(add|sub) rd, rn, #imm'.
 */

 /* ================================================ */
 /* IAMROOT-12-B,35th(2015.12.19 22:00) : 종료        */
 /* ================================================ */

	__HEAD
__fixup_pv_table:
	adr	r0, 1f
	ldmia	r0, {r3-r7}
	mvn	ip, #0
	subs	r3, r0, r3	@ PHYS_OFFSET - PAGE_OFFSET
	add	r4, r4, r3	@ adjust table start address
	add	r5, r5, r3	@ adjust table end address
	add	r6, r6, r3	@ adjust __pv_phys_pfn_offset address
	add	r7, r7, r3	@ adjust __pv_offset address
	mov	r0, r8, lsr #PAGE_SHIFT	@ convert to PFN
	str	r0, [r6]	@ save computed PHYS_OFFSET to __pv_phys_pfn_offset
	strcc	ip, [r7, #HIGH_OFFSET]	@ save to __pv_offset high bits
	mov	r6, r3, lsr #24	@ constant for add/sub instructions
	teq	r3, r6, lsl #24 @ must be 16MiB aligned
THUMB(	it	ne		@ cross section branch )
	bne	__error
	str	r3, [r7, #LOW_OFFSET]	@ save to __pv_offset low bits
	b	__fixup_a_pv_table
ENDPROC(__fixup_pv_table)

	.align
1:	.long	.
	.long	__pv_table_begin
	.long	__pv_table_end
2:	.long	__pv_phys_pfn_offset
	.long	__pv_offset

	.text
__fixup_a_pv_table:
	adr	r0, 3f
	ldr	r6, [r0]
	add	r6, r6, r3
	ldr	r0, [r6, #HIGH_OFFSET]	@ pv_offset high word
	ldr	r6, [r6, #LOW_OFFSET]	@ pv_offset low word
	mov	r6, r6, lsr #24
	cmn	r0, #1
#ifdef CONFIG_THUMB2_KERNEL
	moveq	r0, #0x200000	@ set bit 21, mov to mvn instruction
	lsls	r6, #24
	beq	2f
	clz	r7, r6
	lsr	r6, #24
	lsl	r6, r7
	bic	r6, #0x0080
	lsrs	r7, #1
	orrcs	r6, #0x0080
	orr	r6, r6, r7, lsl #12
	orr	r6, #0x4000
	b	2f
1:	add     r7, r3
	ldrh	ip, [r7, #2]
ARM_BE8(rev16	ip, ip)
	tst	ip, #0x4000
	and	ip, #0x8f00
	orrne	ip, r6	@ mask in offset bits 31-24
	orreq	ip, r0	@ mask in offset bits 7-0
ARM_BE8(rev16	ip, ip)
	strh	ip, [r7, #2]
	bne	2f
	ldrh	ip, [r7]
ARM_BE8(rev16	ip, ip)
	bic	ip, #0x20
	orr	ip, ip, r0, lsr #16
ARM_BE8(rev16	ip, ip)
	strh	ip, [r7]
2:	cmp	r4, r5
	ldrcc	r7, [r4], #4	@ use branch for delay slot
	bcc	1b
	bx	lr
#else
#ifdef CONFIG_CPU_ENDIAN_BE8
	moveq	r0, #0x00004000	@ set bit 22, mov to mvn instruction
#else
	moveq	r0, #0x400000	@ set bit 22, mov to mvn instruction
#endif
	b	2f
1:	ldr	ip, [r7, r3]
#ifdef CONFIG_CPU_ENDIAN_BE8
	@ in BE8, we load data in BE, but instructions still in LE
	bic	ip, ip, #0xff000000
	tst	ip, #0x000f0000	@ check the rotation field
	orrne	ip, ip, r6, lsl #24 @ mask in offset bits 31-24
	biceq	ip, ip, #0x00004000 @ clear bit 22
	orreq	ip, ip, r0      @ mask in offset bits 7-0
#else
	bic	ip, ip, #0x000000ff
	tst	ip, #0xf00	@ check the rotation field
	orrne	ip, ip, r6	@ mask in offset bits 31-24
	biceq	ip, ip, #0x400000	@ clear bit 22
	orreq	ip, ip, r0	@ mask in offset bits 7-0
#endif
	str	ip, [r7, r3]
2:	cmp	r4, r5
	ldrcc	r7, [r4], #4	@ use branch for delay slot
	bcc	1b
	ret	lr
#endif
ENDPROC(__fixup_a_pv_table)

	.align
3:	.long __pv_offset

ENTRY(fixup_pv_table)
	stmfd	sp!, {r4 - r7, lr}
	mov	r3, #0			@ no offset
	mov	r4, r0			@ r0 = table start
	add	r5, r0, r1		@ r1 = table size
	bl	__fixup_a_pv_table
	ldmfd	sp!, {r4 - r7, pc}
ENDPROC(fixup_pv_table)

	.data
	.globl	__pv_phys_pfn_offset
	.type	__pv_phys_pfn_offset, %object
__pv_phys_pfn_offset:
	.word	0
	.size	__pv_phys_pfn_offset, . -__pv_phys_pfn_offset

	.globl	__pv_offset
	.type	__pv_offset, %object
__pv_offset:
	.quad	0
	.size	__pv_offset, . -__pv_offset
#endif

#include "head-common.S"
