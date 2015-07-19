/*
 *  arch/arm/include/asm/assembler.h
 *
 *  Copyright (C) 1996-2000 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  This file contains arm architecture specific defines
 *  for the different processors.
 *
 *  Do not include any C declarations in this file - it is included by
 *  assembler source.
 */
#ifndef __ASM_ASSEMBLER_H__
#define __ASM_ASSEMBLER_H__

#ifndef __ASSEMBLY__
#error "Only include this from assembly code"
#endif

#include <asm/ptrace.h>
#include <asm/domain.h>
#include <asm/opcodes-virt.h>
#include <asm/asm-offsets.h>
#include <asm/page.h>
#include <asm/thread_info.h>

#define IOMEM(x)	(x)

/*
 * Endian independent macros for shifting bytes within registers.
 */
#ifndef __ARMEB__
#define lspull          lsr
#define lspush          lsl
#define get_byte_0      lsl #0
#define get_byte_1	lsr #8
#define get_byte_2	lsr #16
#define get_byte_3	lsr #24
#define put_byte_0      lsl #0
#define put_byte_1	lsl #8
#define put_byte_2	lsl #16
#define put_byte_3	lsl #24
#else
#define lspull          lsl
#define lspush          lsr
#define get_byte_0	lsr #24
#define get_byte_1	lsr #16
#define get_byte_2	lsr #8
#define get_byte_3      lsl #0
#define put_byte_0	lsl #24
#define put_byte_1	lsl #16
#define put_byte_2	lsl #8
#define put_byte_3      lsl #0
#endif

/* Select code for any configuration running in BE8 mode */
#ifdef CONFIG_CPU_ENDIAN_BE8
#define ARM_BE8(code...) code
#else
#define ARM_BE8(code...)
#endif

/*
 * Data preload for architectures that support it
 */
#if __LINUX_ARM_ARCH__ >= 5
#define PLD(code...)	code
#else
#define PLD(code...)
#endif

/*
 * This can be used to enable code to cacheline align the destination
 * pointer when bulk writing to memory.  Experiments on StrongARM and
 * XScale didn't show this a worthwhile thing to do when the cache is not
 * set to write-allocate (this would need further testing on XScale when WA
 * is used).
 *
 * On Feroceon there is much to gain however, regardless of cache mode.
 */
#ifdef CONFIG_CPU_FEROCEON
#define CALGN(code...) code
#else
#define CALGN(code...)
#endif

/*
 * Enable and disable interrupts
 */
#if __LINUX_ARM_ARCH__ >= 6
	.macro	disable_irq_notrace
	cpsid	i
	.endm

	.macro	enable_irq_notrace
	cpsie	i
	.endm
#else
	.macro	disable_irq_notrace
	msr	cpsr_c, #PSR_I_BIT | SVC_MODE
	.endm

	.macro	enable_irq_notrace
	msr	cpsr_c, #SVC_MODE
	.endm
#endif

	.macro asm_trace_hardirqs_off
#if defined(CONFIG_TRACE_IRQFLAGS)
	stmdb   sp!, {r0-r3, ip, lr}
	bl	trace_hardirqs_off
	ldmia	sp!, {r0-r3, ip, lr}
#endif
	.endm

	.macro asm_trace_hardirqs_on_cond, cond
#if defined(CONFIG_TRACE_IRQFLAGS)
	/*
	 * actually the registers should be pushed and pop'd conditionally, but
	 * after bl the flags are certainly clobbered
	 */
	stmdb   sp!, {r0-r3, ip, lr}
	bl\cond	trace_hardirqs_on
	ldmia	sp!, {r0-r3, ip, lr}
#endif
	.endm

	.macro asm_trace_hardirqs_on
	asm_trace_hardirqs_on_cond al
	.endm

	.macro disable_irq
	disable_irq_notrace
	asm_trace_hardirqs_off
	.endm

	.macro enable_irq
	asm_trace_hardirqs_on
	enable_irq_notrace
	.endm
/*
 * Save the current IRQ state and disable IRQs.  Note that this macro
 * assumes FIQs are enabled, and that the processor is in SVC mode.
 */
	.macro	save_and_disable_irqs, oldcpsr
#ifdef CONFIG_CPU_V7M
	mrs	\oldcpsr, primask
#else
	mrs	\oldcpsr, cpsr
#endif
	disable_irq
	.endm

	.macro	save_and_disable_irqs_notrace, oldcpsr
	mrs	\oldcpsr, cpsr
	disable_irq_notrace
	.endm

/*
 * Restore interrupt state previously stored in a register.  We don't
 * guarantee that this will preserve the flags.
 */
	.macro	restore_irqs_notrace, oldcpsr
#ifdef CONFIG_CPU_V7M
	msr	primask, \oldcpsr
#else
	msr	cpsr_c, \oldcpsr
#endif
	.endm

	.macro restore_irqs, oldcpsr
	tst	\oldcpsr, #PSR_I_BIT
	asm_trace_hardirqs_on_cond eq
	restore_irqs_notrace \oldcpsr
	.endm

/*
 * Get current thread_info.
 */
	.macro	get_thread_info, rd
 ARM(	mov	\rd, sp, lsr #THREAD_SIZE_ORDER + PAGE_SHIFT	)
 THUMB(	mov	\rd, sp			)
 THUMB(	lsr	\rd, \rd, #THREAD_SIZE_ORDER + PAGE_SHIFT	)
	mov	\rd, \rd, lsl #THREAD_SIZE_ORDER + PAGE_SHIFT
	.endm

/*
 * Increment/decrement the preempt count.
 */
#ifdef CONFIG_PREEMPT_COUNT
	.macro	inc_preempt_count, ti, tmp
	ldr	\tmp, [\ti, #TI_PREEMPT]	@ get preempt count
	add	\tmp, \tmp, #1			@ increment it
	str	\tmp, [\ti, #TI_PREEMPT]
	.endm

	.macro	dec_preempt_count, ti, tmp
	ldr	\tmp, [\ti, #TI_PREEMPT]	@ get preempt count
	sub	\tmp, \tmp, #1			@ decrement it
	str	\tmp, [\ti, #TI_PREEMPT]
	.endm

	.macro	dec_preempt_count_ti, ti, tmp
	get_thread_info \ti
	dec_preempt_count \ti, \tmp
	.endm
#else
	.macro	inc_preempt_count, ti, tmp
	.endm

	.macro	dec_preempt_count, ti, tmp
	.endm

	.macro	dec_preempt_count_ti, ti, tmp
	.endm
#endif

#define USER(x...)				\
9999:	x;					\
	.pushsection __ex_table,"a";		\
	.align	3;				\
	.long	9999b,9001f;			\
	.popsection

#ifdef CONFIG_SMP
#define ALT_SMP(instr...)					\
9998:	instr
/*
 * Note: if you get assembler errors from ALT_UP() when building with
 * CONFIG_THUMB2_KERNEL, you almost certainly need to use
 * ALT_SMP( W(instr) ... )
 */
#define ALT_UP(instr...)					\
	.pushsection ".alt.smp.init", "a"			;\
	.long	9998b						;\
9997:	instr							;\
	.if . - 9997b != 4					;\
		.error "ALT_UP() content must assemble to exactly 4 bytes";\
	.endif							;\
	.popsection
#define ALT_UP_B(label)					\
	.equ	up_b_offset, label - 9998b			;\
	.pushsection ".alt.smp.init", "a"			;\
	.long	9998b						;\
	W(b)	. + up_b_offset					;\
	.popsection
#else
#define ALT_SMP(instr...)
#define ALT_UP(instr...) instr
#define ALT_UP_B(label) b label
#endif

/*
 * Instruction barrier
 */
	.macro	instr_sync
#if __LINUX_ARM_ARCH__ >= 7
	isb
#elif __LINUX_ARM_ARCH__ == 6
	mcr	p15, 0, r0, c7, c5, 4
#endif
	.endm

/*
 * SMP data memory barrier
 */
	.macro	smp_dmb mode
#ifdef CONFIG_SMP
#if __LINUX_ARM_ARCH__ >= 7
	.ifeqs "\mode","arm"
	ALT_SMP(dmb	ish)
	.else
	ALT_SMP(W(dmb)	ish)
	.endif
#elif __LINUX_ARM_ARCH__ == 6
	ALT_SMP(mcr	p15, 0, r0, c7, c10, 5)	@ dmb
#else
#error Incompatible SMP platform
#endif
	.ifeqs "\mode","arm"
	ALT_UP(nop)
	.else
	ALT_UP(W(nop))
	.endif
#endif
	.endm

#if defined(CONFIG_CPU_V7M)
	/*
	 * setmode is used to assert to be in svc mode during boot. For v7-M
	 * this is done in __v7m_setup, so setmode can be empty here.
	 */
	.macro	setmode, mode, reg
	.endm
#elif defined(CONFIG_THUMB2_KERNEL)
	.macro	setmode, mode, reg
	mov	\reg, #\mode
	msr	cpsr_c, \reg
	.endm
#else
	.macro	setmode, mode, reg
	msr	cpsr_c, #\mode
	.endm
#endif

/*
 * Helper macro to enter SVC mode cleanly and mask interrupts. reg is
 * a scratch register for the macro to overwrite.
 *
 * This macro is intended for forcing the CPU into SVC mode at boot time.
 * you cannot return to the original mode.
 */
<<<<<<< HEAD
 /**
  * @[charles.hyunchul-JO]:2015.07.06
  check define value as below -> root/arch/arm/include/asm/ptrace.h
	#define PSR_F_BIT	0x00000040
	#define PSR_I_BIT	0x00000080
	#define PSR_A_BIT	0x00000100 //V6 arch?̻? ????, ??????��?? V7/M ??????, Abot bit??.
	#define PSR_E_BIT	0x00000200
	#define PSR_J_BIT	0x01000000
	#define PSR_Q_BIT	0x08000000
	#define PSR_V_BIT	0x10000000
	#define PSR_C_BIT	0x20000000
	#define PSR_Z_BIT	0x40000000
	#define PSR_N_BIT	0x80000000
=======
/*
 * 공통 : 7월4일 미완료 차주 자료 추가해서 논의
>>>>>>> 4de9132293dfebfbf6fb663600918a3c8632e15b
 */
.macro safe_svcmode_maskall reg:req
    /*
     * raspberry pi 2는 LINUX_ARM_ARCH 7이고 CONFIG_CPU_V7이므로
     * 아래의 #if directive는 true
     */
#if __LINUX_ARM_ARCH__ >= 6 && !defined(CONFIG_CPU_V7M)
    /*
     * instruction descriptions
     *
     * xor : XOR 논리 연산을 이용한 비교 명령어
     * tst : AND 논리 연산을 이용한 비교 명령어
     * bic : 특정 비트값을 0으로 클리어
     * orr : 32bit or 논리 연산
     * adr : 주소값을 레지스터에 저장하는 의사 명령어
     *       pc 상대 덧셈 뺄셈을 이용하여 주어진 label의 주소를 레지스터에 저장
     * msr : psr 레지스터 전용 mov 명령어(쓰기)
     * bne : branch instruction B with the condition mnemonic NE (not equal)
     *       if the previous compare instruction sets the condition flags
     *       to not equal, the branch instruction is executed.
     */
/*
 * 공통 : HYP_MODE => cprs 에서 설정된 모드, 책에 나오지 않은 신규 모드 ...
 * SVC 모드 보다 높은 모드 확인 필요 ~!!!!!
 * 가상화관련 
 */

    /*
     * cpsr을 읽어 현재 mode가 HYP_MODE인지 검사
     * eor로 현재 HYP_MODE인 경우에만 MODE_MASK에 해당하는 bits가 모두 0이 됨
     * tst로 HYP_MODE인 경우에만 Zero flag가 1로 설정 됨(Z)
     */
	mrs	\reg , cpsr
	eor	\reg, \reg, #HYP_MODE
	tst	\reg, #MODE_MASK

    /*
     * MODE_MASK(0x0000001F)에 해당 하는 bit를 0으로 초기화
     * SVC_MODE를 만들기 위한 선행 작업
     * IRQ, FIQ를 막고, SVC_MODE를 설정
     * THUMB일때는 Thumb 비트를 turn on
     */
	bic	\reg , \reg , #MODE_MASK
	orr	\reg , \reg , #PSR_I_BIT | PSR_F_BIT | SVC_MODE
THUMB(	orr	\reg , \reg , #PSR_T_BIT	)

    /*
     * 이전의 tst 비교연산에서 HYP_MODE에서만 Zero flag가 1로 설정(Z) 되었기 때문에
     * Zero flag가 0일때(z)만 jump하는 bne는 HYP_MODE에서는 false가 되어 실행하지 않는다.
     * 즉, HYP_MODE가 아닌경우에 1f로 jump
     */
	bne	1f

    /*
     * arch/arm/include/asm/unidifed.h
     * #idfed CONFIG_THUMB2_KERNEL
     * #define BSYM(sym)    sym + 1
     * #else
     * #define BSYM(sym)    sym ()
     * #endif
     *
     * adr  lr, 2f + 1
     * lr = pc relative 2f + 1
     * lr = 2f address + 1
     *
     * kernel disassemble 결과
     * 6c: 1a000004    bne 84 <not_angel+0x2c>
     * 70: e3800c01    orr r0, r0, #256    ; 0x100
     * 74: e28fe00c    add lr, pc, #12
     * 78: e16ff000    msr SPSR_fsxc, r0
     * 7c: e12ef30e    msr ELR_hyp, lr
     * 80: e160006e    eret
     * 84: e121f000    msr CPSR_c, r0
     * 88: e16ff009    msr SPSR_fsxc, r9
     */

    /*
     * abort bit(PSR_A_BIT)를 세워서 abort mode로 넘어가는 것을 막음
     * 이후 operations에서 아마 data abort exception이 발생할 수도 있기 때문인 듯
     * lr에는 2: label의 주소를 PC 상대 주소를 이용해 저장
     * __MSR_ELR_HYP를 수행하고나서 돌아왔을때 1: label을 건너뛰고 2: label로 가기 위해 하는 것으로 생각 됨
     * BSYM은 THUMB2_KERNEL 인지에 따라 주소 지정 방식이 달라서 2f + 1해주느냐 아니냐의 차이
     * spsr의 c(control), x(extension), s(status), f(flag)에 reg 값을 저장
     */
	orr	\reg, \reg, #PSR_A_BIT
	adr	lr, BSYM(2f)
	msr	spsr_cxsf, \reg

    /*
     * 2015/07/11 스터디 종료
     * TODO: __MSR_ELR_HYP(14),__ERET 각자 조사
     */

    /*
     * __MSR_ELR_HYP(0xE12EF300)
     * __ERET(0xE160006E)
     *
     * ELR_hyp : hyp mode does not provide its own banked copy of lr. Instead, on taking
     *           an exception to hyp mode, the preferred return address is stored in
     *           ELR_hyp, a 32-bit special register implemented for this purpose.
     *           ELR_hyp can be accessed explicitly only by executing mrs(banked register),
     *           msr(banked register).
     *           The ERET instruction uses the value in ELR_hyp as the return address for
     *           the exception.
     *
     * ERET : When executed in hyp mode, exception return loads the pc
     *        from ELR_hyp and loads the cpsr from spsr_hyp
     */

    /*
     * __MSR_ELR_HYP(14)는 msr (banked register) instruction으로 인코딩 됨
     * 14는 r14(link register)를 나타내고 이를 HYP MODE에만 있는 ELR_hyp에 저장
     * __ERET는 exception return instruction으로 인코딩 되고, HYP_MODE에서 실행될 때
     * pc 값을 ELR_hyp로 설정하고, spsr_hyp 값을 cpsr에 설정함
     *
     * 즉, 위에서 lr에 2: label 주소를 저장하고, spsr에 SVC_MODE로 미리 준비해둔 상태에서
     * __MSR_ELR_HYP를 통해 ELR_hyp에 2: label주소를 저장하고,
     * __ERET를 통해 pc값을 2: label주소로 설정후, cpsr에 spsr값을 설정함으로써
     * HYP_MODE에서 SVC_MODE로 전환 함
     */
	__MSR_ELR_HYP(14)
	__ERET

    /*
     * HYP_MODE가 아닌 경우 1: label로 jump해서 SVC_MODE로 bit 설정해둔
     * reg를 cpsr_c(control)에 저장
     * 즉, 현재 mode를 SVC_MODE로 변경
     */
1:	msr	cpsr_c, \reg
2:
#else
/*
 * workaround for possibly broken pre-v6 hardware
 * (akita, Sharp Zaurus C-1000, PXA270-based)
 */
	setmode	PSR_F_BIT | PSR_I_BIT | SVC_MODE, \reg
#endif
.endm

/*
 * STRT/LDRT access macros with ARM and Thumb-2 variants
 */
#ifdef CONFIG_THUMB2_KERNEL

	.macro	usraccoff, instr, reg, ptr, inc, off, cond, abort, t=TUSER()
9999:
	.if	\inc == 1
	\instr\cond\()b\()\t\().w \reg, [\ptr, #\off]
	.elseif	\inc == 4
	\instr\cond\()\t\().w \reg, [\ptr, #\off]
	.else
	.error	"Unsupported inc macro argument"
	.endif

	.pushsection __ex_table,"a"
	.align	3
	.long	9999b, \abort
	.popsection
	.endm

	.macro	usracc, instr, reg, ptr, inc, cond, rept, abort
	@ explicit IT instruction needed because of the label
	@ introduced by the USER macro
	.ifnc	\cond,al
	.if	\rept == 1
	itt	\cond
	.elseif	\rept == 2
	ittt	\cond
	.else
	.error	"Unsupported rept macro argument"
	.endif
	.endif

	@ Slightly optimised to avoid incrementing the pointer twice
	usraccoff \instr, \reg, \ptr, \inc, 0, \cond, \abort
	.if	\rept == 2
	usraccoff \instr, \reg, \ptr, \inc, \inc, \cond, \abort
	.endif

	add\cond \ptr, #\rept * \inc
	.endm

#else	/* !CONFIG_THUMB2_KERNEL */

	.macro	usracc, instr, reg, ptr, inc, cond, rept, abort, t=TUSER()
	.rept	\rept
9999:
	.if	\inc == 1
	\instr\cond\()b\()\t \reg, [\ptr], #\inc
	.elseif	\inc == 4
	\instr\cond\()\t \reg, [\ptr], #\inc
	.else
	.error	"Unsupported inc macro argument"
	.endif

	.pushsection __ex_table,"a"
	.align	3
	.long	9999b, \abort
	.popsection
	.endr
	.endm

#endif	/* CONFIG_THUMB2_KERNEL */

	.macro	strusr, reg, ptr, inc, cond=al, rept=1, abort=9001f
	usracc	str, \reg, \ptr, \inc, \cond, \rept, \abort
	.endm

	.macro	ldrusr, reg, ptr, inc, cond=al, rept=1, abort=9001f
	usracc	ldr, \reg, \ptr, \inc, \cond, \rept, \abort
	.endm

/* Utility macro for declaring string literals */
	.macro	string name:req, string
	.type \name , #object
\name:
	.asciz "\string"
	.size \name , . - \name
	.endm

	.macro check_uaccess, addr:req, size:req, limit:req, tmp:req, bad:req
#ifndef CONFIG_CPU_USE_DOMAINS
	adds	\tmp, \addr, #\size - 1
	sbcccs	\tmp, \tmp, \limit
	bcs	\bad
#endif
	.endm

	.irp	c,,eq,ne,cs,cc,mi,pl,vs,vc,hi,ls,ge,lt,gt,le,hs,lo
	.macro	ret\c, reg
#if __LINUX_ARM_ARCH__ < 6
	mov\c	pc, \reg
#else
	.ifeqs	"\reg", "lr"
	bx\c	\reg
	.else
	mov\c	pc, \reg
	.endif
#endif
	.endm
	.endr

	.macro	ret.w, reg
	ret	\reg
#ifdef CONFIG_THUMB2_KERNEL
	nop
#endif
	.endm

#endif /* __ASM_ASSEMBLER_H__ */
