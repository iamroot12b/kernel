/*
 * IAMROOT Kernel 12차-B팀 (http://www.iamroot.org)
 * ===================================================
 * 
 */

/*
 *  linux/arch/arm/boot/compressed/head.S
 *
 *  Copyright (C) 1996-2002 Russell King
 *  Copyright (C) 2004 Hyok S. Choi (MPU support)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/linkage.h>
#include <asm/assembler.h>

	.arch	armv7-a
/*
 * Debugging stuff
 *
 * Note that these macros must not contain any code which is not
 * 100% relocatable.  Any attempt to do so will result in a crash.
 * Please select one of the following when turning on debugging.
 */
#ifdef DEBUG

#if defined(CONFIG_DEBUG_ICEDCC)

#if defined(CONFIG_CPU_V6) || defined(CONFIG_CPU_V6K) || defined(CONFIG_CPU_V7)
		.macro	loadsp, rb, tmp
		.endm
		.macro	writeb, ch, rb
		mcr	p14, 0, \ch, c0, c5, 0
		.endm
#elif defined(CONFIG_CPU_XSCALE)
		.macro	loadsp, rb, tmp
		.endm
		.macro	writeb, ch, rb
		mcr	p14, 0, \ch, c8, c0, 0
		.endm
#else
		.macro	loadsp, rb, tmp
		.endm
		.macro	writeb, ch, rb
		mcr	p14, 0, \ch, c1, c0, 0
		.endm
#endif

#else

#include CONFIG_DEBUG_LL_INCLUDE

		.macro	writeb,	ch, rb
		senduart \ch, \rb
		.endm

#if defined(CONFIG_ARCH_SA1100)
		.macro	loadsp, rb, tmp
		mov	\rb, #0x80000000	@ physical base address
#ifdef CONFIG_DEBUG_LL_SER3
		add	\rb, \rb, #0x00050000	@ Ser3
#else
		add	\rb, \rb, #0x00010000	@ Ser1
#endif
		.endm
#else
		.macro	loadsp,	rb, tmp
		addruart \rb, \tmp
		.endm
#endif
#endif
#endif

		.macro	kputc,val
		mov	r0, \val
		bl	putc
		.endm

		.macro	kphex,val,len
		mov	r0, \val
		mov	r1, #\len
		bl	phex
		.endm

		.macro	debug_reloc_start
#ifdef DEBUG
		kputc	#'\n'
		kphex	r6, 8		/* processor id */
		kputc	#':'
		kphex	r7, 8		/* architecture id */
#ifdef CONFIG_CPU_CP15
		kputc	#':'
		mrc	p15, 0, r0, c1, c0
		kphex	r0, 8		/* control reg */
#endif
		kputc	#'\n'
		kphex	r5, 8		/* decompressed kernel start */
		kputc	#'-'
		kphex	r9, 8		/* decompressed kernel end  */
		kputc	#'>'
		kphex	r4, 8		/* kernel execution address */
		kputc	#'\n'
#endif
		.endm

		.macro	debug_reloc_end
#ifdef DEBUG
		kphex	r5, 8		/* end of kernel */
		kputc	#'\n'
		mov	r0, r4
		bl	memdump		/* dump 256 bytes at start of kernel */
#endif
		.endm

		.section ".start", #alloc, #execinstr
/*
 * sort out different calling conventions
 */
 

/* IAMROOT-12-B: Start analysis. Fighting!
 * ---------------------------------------
 * ref : http://www.iamroot.org/lxr/http/source/arch/arm/boot/compressed/head.S#L133
 */
 
		.align
		.arm				@ Always enter in ARM state
start:

/* ================================================ */
/* IAMROOT-12-B,10th(2015.06.27 18:00): Start       */
/* ================================================ */
	   /* -------------------------------------------------------------------
		* 스타트라는 레이블을 펑션으로 정의하겠다.
		* 같은 파일 내에서만 점프 가능?
		* 이게 없으면 어떻게 되는가?
		* 파일 외부에서 호출하려면 이렇게 정의해야 한다.
		* 인텔에서 .global과 비슷한 것 같다는 의견이 나왔음
		* #function은 그냥 상수는 아닌것 같고 어디에 정의 되어 있나?
		* #function은 어디에 정의 되어있나?
		* ex) add r1, #2
		* ------------------------------------------------------------------- */	
		.type	start,#function

	   /* -------------------------------------------------------------------
		* 가스랑 인스트럭션 문서 2개를 봐야한다.
		* .rept ~ .endr 사이를 7번 반복한다.
		* 의미는 단지 딜레이를 주려는 의도만 있는 것은 아닌것 같다.
		* 얼핏 보기에는 어떤 지저분한 부트로드에서 이렇게 하지 않으면 안됐었다는 이야기가 있었는데....
		* 다른 의견 ) 엔젤 부트로더 등 여러가지 부트로더가 있었음 근데 월드 부트로더?
		* 메직 시그니쳐 이미지쪽에 시그니쳐가 있다는 이야기....가 나왔음
		* 파이프라인 클리어를 위한 용도도 이야기가 나왔음...
		* 매직 시그니쳐??
		* 부트로더랑 제트이미지 사이에 고유의 유니크한 값이 있는 곳이 있다고 함.
		* 7번인데 무브 알제로 알제로 까지 포함하면 총 8번
		* 4바이트 떨어진 위치에 시그니쳐가 있다고 함
		* 그냥 4바이트씩 어드레싱 된다고 함. 시프트?
		* r0 에는 0이 들어있음...
		* 이렇게 이동한 이유가 히스토리를 보니 여러가지 부트로드 보았더니 호환성을 위해 이렇게 이동했다는 의견
		* 무브는 4바이트 이동
 		* 암/썸 모드 암괄호는 썸모드에서 실행안됨, 역도 성립
		* ------------------------------------------------------------------- */	
		.rept	7

		mov	r0, r0
		.endr

   /* -----------------------------------------------------------------------
	* 밑에 암모드랑 썸모드 명령어 내용이 똑같다고 함
	* 예전 소스에 콜링 컨벤션 정렬? -> 링크 부탁드립니다.
	* ftp://ftp.u-aizu.ac.jp/pub/os/ 나중에 완성...
	* ------------------------------------------------------------------- */	
	ARM(		mov	r0, r0		)
	
   /* -----------------------------------------------------------------------
	* 암모드일경우 일에프로 이동하고 썸모드인경우
	* ------------------------------------------------------------------- */	
	ARM(		b	1f		)

   /* -----------------------------------------------------------------------
	* 암모드에서 점프하면 밑에 워드는 읽히는 타이밍이 없는것 같은데....
	* 1에프를 주소를 읽어 알12에 넣고
	* 알12로 감
	* 비에스와이엠 -> 썸일때 마지막 1비트가 1이어야하는데 그거 세팅하는것 같다는 의견이 있었음
	* ------------------------------------------------------------------- */	
	THUMB(		adr	r12, BSYM(1f)	)
	THUMB(		bx	r12		)

	   /* -------------------------------------------------------------------
		* 덤프뜨면 헥사로 24 28 .... 링크 스크립트에 정의 되어  있다고 함.
		* 소스 파일에 루트/아키텍처/암/부트/컴프레스드/vmlinux.lds.s : defined 되어있음
		* 점워드는 4바이트, 변수 선언이라고 생각하면 됨
		* 24, 28 ....  위치에 4바이트 씩 시그니처가 것이 중요한 내용
		* ------------------------------------------------------------------- */	
		.word	_magic_sig	@ Magic numbers to help the loader
		.word	_magic_start	@ absolute load/run zImage address
		.word	_magic_end	@ zImage end address
		.word	0x04030201	@ endianness flag

   /* -----------------------------------------------------------------------
	* 이건 어셈블리 지시자라 실행되는게 아님
	* 루트 밑에 설정.. 루트/ 바로 밑에 .config (menuconfig output file)
	* 어셀블러가 썸으로 해석하도록 하는 지시어.
	* ------------------------------------------------------------------- */	
 	THUMB(		.thumb			)
1:

   /* -----------------------------------------------------------------------
	* 빅엔디안일 경우면 셋에디안을 빅에디안으로 바꾸어라.
	* setEndian, cpu mode를 지원하기 위해서...
	* 암책 678쪽에 있음. 630쪽에도 있음 645~ 암모드 썸모드 명령어가 사전처럼 나와있음.
	* ------------------------------------------------------------------- */	
	ARM_BE8(	setend	be )			@ go BE8 if compiled for BE8

	   /* -------------------------------------------------------------------
		* cpsr 을 읽어서 서 알9에 읽음. 일반적으로 무브를 쓰는데 씨피에스알은 특이하게 엠알에스로 처리함....
		* 책에 그렇게 나와 있다고 함. 스페셜 레지스터는 별도 명령어로 처리함....
		* 그럼 일반 유저는 cpsr을 못 읽는데 왜 mov랑 구분해서 명령어가 있을까??? 숙제
		* 데이터/레지스터 처리 명령어가 구분되어 있다는 의견이 있었음.
		* ------------------------------------------------------------------- */	
		mrs	r9, cpsr
		
   /* ----------------------------------------------------------------------
 	* 커널이 가상화 설정이 되어 있으면....
	* 비엘이 점프해서 함수 실행하고 다시 여기로 돌아옴
	* 알14에 돌아올 주소 저장해 놓고 실행했다가 다시 돌아옴
	* 비는 그냥 고, 비엘은 고빽
	* ------------------------------------------------------------------- */	
#ifdef CONFIG_ARM_VIRT_EXT
	bl	__hyp_stub_install	@ get into SVC mode, reversibly
#endif

	   /* ------------------------------------------------------------------
		* mach-arm/header.h
		* root/arch/arm/tools/mach-types 에 아키텍처 아이디 목록이 정의되어 있음
		* ------------------------------------------------------------------- */	
		mov	r7, r1			@ save architecture ID

	   /* ------------------------------------------------------------------
		* document/device/tree/booting-without-of.txt 디바이스 트리 
		* 환경변수 
		* 요즘 추세는 디티브로 설정한다고 함.
		* 에이테그는 환경변수 설정을 가지고 있는 데이터 모음
		* soc 칩 마다 환경변수 모음을 에이테그라는 이름으로 가지고 있다함.
		* todo : atags pointer 목록을 찾아보기 : 숙제
		* 지디 정보에 에이테그 정보들이 있다고 함...
		* 에이테그 -> 디티비
		* root/arch/arm/boot/dts/* dts & dti files
		* ------------------------------------------------------------------- */	
		mov	r8, r2			@ save atags pointer

/* --------------------------------------------------------------------------
 * 예전에 엔젤 부트로더가 있었다고 함.
 * -------------------------------------------------------------------------- */
/* ================================================ */
/* IAMROOT-12-B,10th(2015.06.27 22:00): End       */
/* ================================================ */

		/*
		 * Booting from Angel - need to enter SVC mode and disable
		 * FIQs/IRQs (numeric definitions from angel arm.h source).
		 * We only do this if we were in user mode on entry.
		 */

/* ================================================ */
/* IAMROOT-12-B,12th(2015.07.11 18:00): Start       */
/* ================================================ */
/* --------------------------------------------------------------------------
 * arch/arm/include/uapi/asm/ptrace.h에 보면 아래와 같이 정의하는데
 * CONFIG_CPU_V7M이 아닌 경우 USR_MODE는 0x00000010이 되어 아래의 tst에서
 * Zero bit가 z(0)이 되어 user mode임에도 :not_angel로 jump 하는것은 아닌지?
 *
 * answer : USR_MODE가 0x00000010이라 할지라도 하위 2비트가 00인것은 동일함.
 *
 * #if defined(__KERNEL__) && defined(CONFIG_CPU_V7M)
 * #define USR_MODE 0x00000000
 * #define SVC_MODE 0x00000000
 * #else
 * #define USR_MODE 0x00000010
 * #define SVC_MODE 0x00000013
 * #endif
 * -------------------------------------------------------------------------- */
	   /* -------------------------------------------------------------------
 		* USR_MODE(0x00000000 or 0x00000010)인 경우에만 하위 비트가 00
 		* 따라서, user mode에서만 tst 검사로 Zero bit가 Z(1)이 되어
 		* :not_angel로 jump하지 않고 다음 instruction(mov r0, #0x17)을 실행함.
 		* ------------------------------------------------------------------- */
		mrs	r2, cpsr		@ get current mode
		tst	r2, #3			@ not user?
		
	   /* -------------------------------------------------------------------
		* Usr mode 인지를 체크(test). Usr mode 일 경우에만 하위 비트가 00 임
		* ------------------------------------------------------------------- */
		bne	not_angel

	   /* -------------------------------------------------------------------
		* 특권 모드에서는 not_angel 로 분기
		* arm debugginh mode란  host debugger 와 JTAG 를 이용한 debugging 용도로 사용됨
		* http://www.iamroot.org/xe/Kernel_8_ARM/57324 */
		* ------------------------------------------------------------------- */
		mov	r0, #0x17		@ angel_SWIreason_EnterSVC
 ARM(		swi	0x123456	)	@ angel_SWI_ARM
 THUMB(		svc	0xab		)	@ angel_SWI_THUMB

/* --------------------------------------------------------------------------
 * ARM(  swi 0x123456 ) @ angel_SWI_ARM
 * The SWI number is different for ARM state and Thumb state. 
 * By default, the SWI numbers used are: ARM state 0x123456, Thumb state 0xab 
 * service_routine 에 넘겨주는 값 
 * 0xff000000 : opcode, 0x00ffffff operand. Jump이기 때문에 r0,r1,r2 는 갱신하지 않음 
 * -------------------------------------------------------------------------- */
/* ================================================ */
/* IAMROOT-12-B,11th(2015.07.04 22:00): End         */
/* ================================================ */


/* ================================================ */
/* IAMROOT-12-B,12th(2015.07.11 18:00): Start       */
/* ================================================ */
not_angel:
	   /* -------------------------------------------------------------------
		* cpsr을 SVC mode로 설정하기 위한 macro
		* arch/arm/include/asm/assembler.h에 정의
		* macro에서 임시 저장소로 사용할 수 있도록 r0 제공
		* ------------------------------------------------------------------- */
		safe_svcmode_maskall r0

/* --------------------------------------------------------------------------
 * r9는 앞에서 cpsr(SVC_MODE로 변경전 CPU mode)값을 저장해둔 레지스터로
 * safe_svcmode_makeall 매크로에서 CPU mode를 SVC_MODE로
 * 강제 변경했으므로, 여기서 이전의 CPU mode를 spsr_cxsf에 저장해 둠
 * safe_svcmode_makeall macro 이후에 spsr에 저장한다는 의미는
 * SVC_MODE에 banked되어 있는 spsr에 이전 CPU mode를 저장하기 위한 목적
 * -------------------------------------------------------------------------- */
         
/* ================================================ */
/* IAMROOT-12-B,13th(2015.07.18 18:00)              */
/* ================================================ */
/* --------------------------------------------------------------------------
 *  arm core power on -> bootloader가 -> svc mode or hyp mode로 셋팅하고 -> head.S 실행 -> svc mode로 복귀
 * -------------------------------------------------------------------------- */
 
	msr	spsr_cxsf, r9		@ Save the CPU boot mode in
					@ SPSR
	/*
	 * Note that some cache flushing and other stuff may
	 * be needed here - is there an Angel SWI call for this?
	 */

	/*
	 * some architecture specific code can be inserted
	 * by the linker here, but it should preserve r7, r8, and r9.
	 */

	   /* -------------------------------------------------------------------
		* text section start. 링크스크립트에서 파일포맷 위치 지정하니까 여기로 지정
		* 근데 왜 여기에? 링커스크립트: kernel/arch/arm/boot/compressed/vmlinux.lds.S
		* 링크 단계에서 링커가 스크립트 참고해서 바이너리의 섹션배치함
		* root/.config 
		* 리눅스 툴체인 설치?해서 테스트 가능 컴파일하고 디어셈블 해보기 vmlinux.elf
		* ------------------------------------------------------------------- */
		.text

/* --------------------------------------------------------------------------
 * CONFIG_AUTO_ZRELADDR 압축된 zimage를 어디에 해제할것인지 zimage reload address
 * -------------------------------------------------------------------------- */
#ifdef CONFIG_AUTO_ZRELADDR

	   /* -------------------------------------------------------------------
		* 로드할 물리주소(부트로더에서 정한값) 자동으로 얻어옴
		* current_PC&0xf800_0000 +0x8000
		* ------------------------------------------------------------------- */
		@ determine final kernel image address
		mov	r4, pc

/* --------------------------------------------------------------------------
 * zimage가  첫128MB 차지하니까 클리어해서 뛰어넘으려고 주소껑충껑충
 * 0xf8000000로 & masking하면 하위비트 0으로 클리어
 * kernel/arch/arm/boot/dts/omap3-beagle.dts:line23
 * 마스킹하면 128M 단위로 정렬됨? 왜정렬함? homework?
 * 다른버전 주석에 kernel image가 128M보다 작은위치에 로드되있다?고 써있음?
 * 0x f    8    0.. ( 0x08000000 = 2^7 M =  128M )
 *    1111 1000 0000..
 * -------------------------------------------------------------------------- */

	   /* -------------------------------------------------------------------
		* comment from linux-4.1.2 version
		*
		* Find the start of physical memory.  As we are executing
		* without the MMU on, we are in the physical address space.
		* We just need to get rid of any offset by aligning the
		* address.
		*
		* This alignment is a balance between the requirements of
		* different platforms - we have chosen 128MB to allow
		* platforms which align the start of their physical memory
		* to 128MB to use this feature, while allowing the zImage
		* to be placed within the first 128MB of memory on other
		* platforms.  Increasing the alignment means we place
		* stricter alignment requirements on the start of physical
		* memory, but relaxing it means that we break people who
		* are already placing their zImage in (eg) the top 64MB
		* of this range.
		* ------------------------------------------------------------------- */
		and	r4, r4, #0xf8000000

	   /* -------------------------------------------------------------------
		* 칩 벤더마다 zimage 올릴위치 달라. 예로 삼성칩은 이렇게 설정함
		* kernel/arch/arm/mach-s3c24xx/include/mach/map.h:line135
		* physical addresses of all the chip-select areas
		* #define S3C2410_CS6 (0x30000000)
		* #define S3C2410_SDRAM_PA    (S3C2410_CS6)
		*	
		* kernel/arch/arm/Makefile:line129
		* # Text offset. This list is sorted numerically by address in order to
		* # provide a means to avoid/resolve conflicts in multi-arch kernels.
		* textofs-y	:= 0x00008000
		*		
		* #이면 상수. 
		* makefile에서 정한 환경변수 불러옴 어떻게 불러옴? 어떻게 넘어옴? 파라미터 넘기듯이 받음?
		* 어셈도 그렇게 받나? 파라미터 넘길때는 스택에 저장이라도 하는데 이건 걍#으로 띡
		* 의사명령어인가? 상수값로드: arm developer's guide 87page
		* kernel/arch/arm/kernel/Makefile 에서 d옵션으로 넘기면 받음
		* ------------------------------------------------------------------- */
		add	r4, r4, #TEXT_OFFSET
		
/* --------------------------------------------------------------------------
 * 로드한 pc 에서 128MiB단위로 정렬해 현재 실행중인 물리주소의 베이스 주소(r4)를 계산. 그리고 r4에 커널이 풀릴 위치를 저장 */
 * -------------------------------------------------------------------------- */

#else
		ldr	r4, =zreladdr
#endif
/* ================================================ */
/* IAMROOT-12-B,13th(2015.07.18 18:00): End
/* ================================================ */


/* ================================================ */
/* IAMROOT-12-B,14th(2015.07.25 18:00): Start       */
/* ================================================ */
/* 2015/07/25 스터디 시작(주석의 내용은 모두 추정. 확신할 수 없음) */

		/*
		 * Set up a page table only if it won't overwrite ourself.
		 * That means r4 < pc || r4 - 16k page directory > &_end.
		 * Given that r4 > &_end is most unfrequent, we add a rough
		 * additional 1MB of room for a possible appended DTB.
		 */
		mov	r0, pc
		cmp	r0, r4		/* == zreladdr */
		
	   /* --------------------------------------------------------------------------
		* r4의 zreladdr 주소가 현재 실행중인 pc보다 큰 경우(덮어쓸 경우) 아래 코드를 실행 
		*
		* LC0+32 == _end - restart + 16384 + 1024*1024
		* _end = .bss 섹션의 마지막. 즉, 이미지의 끝
		* 16384 = 16k 페이지 디렉토리 크기
		* 1024*1024 = 확보할 공간 크기.
		* 결국 이미지 끝에서부터 16k+1MB 공간을 확보하는 것 같은데 `_end - restart`를 하는 이유는?
		* 아래 코드에서 다시 pc를 더해주므로 불필요한 연산 같은데?
 		* -------------------------------------------------------------------------- */
 		ldrcc	r0, LC0+32
		addcc	r0, r0, pc
		cmpcc	r4, r0
		orrcc	r4, r4, #1		@ remember we skipped cache_on
/* ================================================ */
/* IAMROOT-12-B,14th(2015.07.25 22:00): End         */
/* ================================================ */
/* ================================================ */
/* IAMROOT-12-B,15th(2015.08.01 19:30 ): Start      */
/* ================================================ */
 		blcs	cache_on /* 위에 코드가 수행되었다면 skip, 아니면 해당 구문으로 이동 
 						  * bl : link register(lr) 에 복귀 주소 저장 cache_on 이후에 오는 위치
 						  */
/* ================================================ */
/* IAMROOT-12-B,15th(2015.08.01 22:05): End         */
/* ================================================ */

restart:	adr	r0, LC0
		ldmia	r0, {r1, r2, r3, r6, r10, r11, r12}
		ldr	sp, [r0, #28]

		/*
		 * We might be running at a different address.  We need
		 * to fix up various pointers.
		 */
		sub	r0, r0, r1		@ calculate the delta offset
		add	r6, r6, r0		@ _edata
		add	r10, r10, r0		@ inflated kernel size location

		/*
		 * The kernel build system appends the size of the
		 * decompressed kernel at the end of the compressed data
		 * in little-endian form.
		 */
		ldrb	r9, [r10, #0]
		ldrb	lr, [r10, #1]
		orr	r9, r9, lr, lsl #8
		ldrb	lr, [r10, #2]
		ldrb	r10, [r10, #3]
		orr	r9, r9, lr, lsl #16
		orr	r9, r9, r10, lsl #24

#ifndef CONFIG_ZBOOT_ROM
		/* malloc space is above the relocated stack (64k max) */
		add	sp, sp, r0
		add	r10, sp, #0x10000
#else
		/*
		 * With ZBOOT_ROM the bss/stack is non relocatable,
		 * but someone could still run this code from RAM,
		 * in which case our reference is _edata.
		 */
		mov	r10, r6
#endif

		mov	r5, #0			@ init dtb size to 0
#ifdef CONFIG_ARM_APPENDED_DTB
/*
 *   r0  = delta
 *   r2  = BSS start
 *   r3  = BSS end
 *   r4  = final kernel address (possibly with LSB set)
 *   r5  = appended dtb size (still unknown)
 *   r6  = _edata
 *   r7  = architecture ID
 *   r8  = atags/device tree pointer
 *   r9  = size of decompressed image
 *   r10 = end of this image, including  bss/stack/malloc space if non XIP
 *   r11 = GOT start
 *   r12 = GOT end
 *   sp  = stack pointer
 *
 * if there are device trees (dtb) appended to zImage, advance r10 so that the
 * dtb data will get relocated along with the kernel if necessary.
 */

		ldr	lr, [r6, #0]
#ifndef __ARMEB__
		ldr	r1, =0xedfe0dd0		@ sig is 0xd00dfeed big endian
#else
		ldr	r1, =0xd00dfeed
#endif
		cmp	lr, r1
		bne	dtb_check_done		@ not found

#ifdef CONFIG_ARM_ATAG_DTB_COMPAT
		/*
		 * OK... Let's do some funky business here.
		 * If we do have a DTB appended to zImage, and we do have
		 * an ATAG list around, we want the later to be translated
		 * and folded into the former here. No GOT fixup has occurred
		 * yet, but none of the code we're about to call uses any
		 * global variable.
		*/

		/* Get the initial DTB size */
		ldr	r5, [r6, #4]
#ifndef __ARMEB__
		/* convert to little endian */
		eor	r1, r5, r5, ror #16
		bic	r1, r1, #0x00ff0000
		mov	r5, r5, ror #8
		eor	r5, r5, r1, lsr #8
#endif
		/* 50% DTB growth should be good enough */
		add	r5, r5, r5, lsr #1
		/* preserve 64-bit alignment */
		add	r5, r5, #7
		bic	r5, r5, #7
		/* clamp to 32KB min and 1MB max */
		cmp	r5, #(1 << 15)
		movlo	r5, #(1 << 15)
		cmp	r5, #(1 << 20)
		movhi	r5, #(1 << 20)
		/* temporarily relocate the stack past the DTB work space */
		add	sp, sp, r5

		stmfd	sp!, {r0-r3, ip, lr}
		mov	r0, r8
		mov	r1, r6
		mov	r2, r5
		bl	atags_to_fdt

		/*
		 * If returned value is 1, there is no ATAG at the location
		 * pointed by r8.  Try the typical 0x100 offset from start
		 * of RAM and hope for the best.
		 */
		cmp	r0, #1
		sub	r0, r4, #TEXT_OFFSET
		bic	r0, r0, #1
		add	r0, r0, #0x100
		mov	r1, r6
		mov	r2, r5
		bleq	atags_to_fdt

		ldmfd	sp!, {r0-r3, ip, lr}
		sub	sp, sp, r5
#endif

		mov	r8, r6			@ use the appended device tree

		/*
		 * Make sure that the DTB doesn't end up in the final
		 * kernel's .bss area. To do so, we adjust the decompressed
		 * kernel size to compensate if that .bss size is larger
		 * than the relocated code.
		 */
		ldr	r5, =_kernel_bss_size
		adr	r1, wont_overwrite
		sub	r1, r6, r1
		subs	r1, r5, r1
		addhi	r9, r9, r1

		/* Get the current DTB size */
		ldr	r5, [r6, #4]
#ifndef __ARMEB__
		/* convert r5 (dtb size) to little endian */
		eor	r1, r5, r5, ror #16
		bic	r1, r1, #0x00ff0000
		mov	r5, r5, ror #8
		eor	r5, r5, r1, lsr #8
#endif

		/* preserve 64-bit alignment */
		add	r5, r5, #7
		bic	r5, r5, #7

		/* relocate some pointers past the appended dtb */
		add	r6, r6, r5
		add	r10, r10, r5
		add	sp, sp, r5
dtb_check_done:
#endif

/*
 * Check to see if we will overwrite ourselves.
 *   r4  = final kernel address (possibly with LSB set)
 *   r9  = size of decompressed image
 *   r10 = end of this image, including  bss/stack/malloc space if non XIP
 * We basically want:
 *   r4 - 16k page directory >= r10 -> OK
 *   r4 + image length <= address of wont_overwrite -> OK
 * Note: the possible LSB in r4 is harmless here.
 */
		add	r10, r10, #16384
		cmp	r4, r10
		bhs	wont_overwrite
		add	r10, r4, r9
		adr	r9, wont_overwrite
		cmp	r10, r9
		bls	wont_overwrite

/*
 * Relocate ourselves past the end of the decompressed kernel.
 *   r6  = _edata
 *   r10 = end of the decompressed kernel
 * Because we always copy ahead, we need to do it from the end and go
 * backward in case the source and destination overlap.
 */
		/*
		 * Bump to the next 256-byte boundary with the size of
		 * the relocation code added. This avoids overwriting
		 * ourself when the offset is small.
		 */
		add	r10, r10, #((reloc_code_end - restart + 256) & ~255)
		bic	r10, r10, #255

		/* Get start of code we want to copy and align it down. */
		adr	r5, restart
		bic	r5, r5, #31

/* Relocate the hyp vector base if necessary */
#ifdef CONFIG_ARM_VIRT_EXT
		mrs	r0, spsr
		and	r0, r0, #MODE_MASK
		cmp	r0, #HYP_MODE
		bne	1f

		bl	__hyp_get_vectors
		sub	r0, r0, r5
		add	r0, r0, r10
		bl	__hyp_set_vectors
1:
#endif

		sub	r9, r6, r5		@ size to copy
		add	r9, r9, #31		@ rounded up to a multiple
		bic	r9, r9, #31		@ ... of 32 bytes
		add	r6, r9, r5
		add	r9, r9, r10

1:		ldmdb	r6!, {r0 - r3, r10 - r12, lr}
		cmp	r6, r5
		stmdb	r9!, {r0 - r3, r10 - r12, lr}
		bhi	1b

		/* Preserve offset to relocated code. */
		sub	r6, r9, r6

#ifndef CONFIG_ZBOOT_ROM
		/* cache_clean_flush may use the stack, so relocate it */
		add	sp, sp, r6
#endif

		bl	cache_clean_flush

		adr	r0, BSYM(restart)
		add	r0, r0, r6
		mov	pc, r0

wont_overwrite:
/*
 * If delta is zero, we are running at the address we were linked at.
 *   r0  = delta
 *   r2  = BSS start
 *   r3  = BSS end
 *   r4  = kernel execution address (possibly with LSB set)
 *   r5  = appended dtb size (0 if not present)
 *   r7  = architecture ID
 *   r8  = atags pointer
 *   r11 = GOT start
 *   r12 = GOT end
 *   sp  = stack pointer
 */
		orrs	r1, r0, r5
		beq	not_relocated

		add	r11, r11, r0
		add	r12, r12, r0

#ifndef CONFIG_ZBOOT_ROM
		/*
		 * If we're running fully PIC === CONFIG_ZBOOT_ROM = n,
		 * we need to fix up pointers into the BSS region.
		 * Note that the stack pointer has already been fixed up.
		 */
		add	r2, r2, r0
		add	r3, r3, r0

		/*
		 * Relocate all entries in the GOT table.
		 * Bump bss entries to _edata + dtb size
		 */
1:		ldr	r1, [r11, #0]		@ relocate entries in the GOT
		add	r1, r1, r0		@ This fixes up C references
		cmp	r1, r2			@ if entry >= bss_start &&
		cmphs	r3, r1			@       bss_end > entry
		addhi	r1, r1, r5		@    entry += dtb size
		str	r1, [r11], #4		@ next entry
		cmp	r11, r12
		blo	1b

		/* bump our bss pointers too */
		add	r2, r2, r5
		add	r3, r3, r5

#else

		/*
		 * Relocate entries in the GOT table.  We only relocate
		 * the entries that are outside the (relocated) BSS region.
		 */
1:		ldr	r1, [r11, #0]		@ relocate entries in the GOT
		cmp	r1, r2			@ entry < bss_start ||
		cmphs	r3, r1			@ _end < entry
		addlo	r1, r1, r0		@ table.  This fixes up the
		str	r1, [r11], #4		@ C references.
		cmp	r11, r12
		blo	1b
#endif

not_relocated:	mov	r0, #0
1:		str	r0, [r2], #4		@ clear bss
		str	r0, [r2], #4
		str	r0, [r2], #4
		str	r0, [r2], #4
		cmp	r2, r3
		blo	1b

		/*
		 * Did we skip the cache setup earlier?
		 * That is indicated by the LSB in r4.
		 * Do it now if so.
		 */
		tst	r4, #1
		bic	r4, r4, #1
		blne	cache_on

/*
 * The C runtime environment should now be setup sufficiently.
 * Set up some pointers, and start decompressing.
 *   r4  = kernel execution address
 *   r7  = architecture ID
 *   r8  = atags pointer
 */
		mov	r0, r4
		mov	r1, sp			@ malloc space above stack
		add	r2, sp, #0x10000	@ 64k max
		mov	r3, r7
		bl	decompress_kernel
		bl	cache_clean_flush
		bl	cache_off
		mov	r1, r7			@ restore architecture number
		mov	r2, r8			@ restore atags pointer

#ifdef CONFIG_ARM_VIRT_EXT
		mrs	r0, spsr		@ Get saved CPU boot mode
		and	r0, r0, #MODE_MASK
		cmp	r0, #HYP_MODE		@ if not booted in HYP mode...
		bne	__enter_kernel		@ boot kernel directly

		adr	r12, .L__hyp_reentry_vectors_offset
		ldr	r0, [r12]
		add	r0, r0, r12

		bl	__hyp_set_vectors
		__HVC(0)			@ otherwise bounce to hyp mode

		b	.			@ should never be reached

		.align	2
.L__hyp_reentry_vectors_offset:	.long	__hyp_reentry_vectors - .
#else
		b	__enter_kernel
#endif

		.align	2
		.type	LC0, #object
LC0:		.word	LC0			@ r1
		.word	__bss_start		@ r2
		.word	_end			@ r3
		.word	_edata			@ r6
		.word	input_data_end - 4	@ r10 (inflated size location)
		.word	_got_start		@ r11
		.word	_got_end		@ ip
		.word	.L_user_stack_end	@ sp
		.word	_end - restart + 16384 + 1024*1024
		.size	LC0, . - LC0

#ifdef CONFIG_ARCH_RPC
		.globl	params
params:		ldr	r0, =0x10000100		@ params_phys for RPC
		mov	pc, lr
		.ltorg
		.align
#endif

/*
 * Turn on the cache.  We need to setup some page tables so that we
 * can have both the I and D caches on.
 *
 * We place the page tables 16k down from the kernel execution address,
 * and we hope that nothing else is using it.  If we're using it, we
 * will go pop!
 *
 * On entry,
 *  r4 = kernel execution address
 *  r7 = architecture number
 *  r8 = atags pointer
 * On exit,
 *  r0, r1, r2, r3, r9, r10, r12 corrupted
 * This routine must preserve:
 *  r4, r7, r8
 */

/* ================================================ */
/* IAMROOT-12-B,14th(2015.08.01 19:30 ~ 22:05)      */
/* ================================================ */
	   /* --------------------------------------------------------------------------
 		* cache_on lable의 시작 주소를 32byte 경계로 정렬된 주소로 정의한다.
 		* 이유는, cache line의 크기가 32byte이기 때문인 것(?)으로 추정한다.
 		* -------------------------------------------------------------------------- */
		.align	5	            /* .align은 주소를 바이트 단위로 정렬하겠다는 의미이고,
                                 * 그 뒤의 '5'는 32byte 단위로 정렬시키겠다는 의미이다.
                                 * 32byte 경계로 정렬시키는 이유는 cache line의 크기가 32byte이기 때문인 것으로 추정되며,
                                 * 이 cache_on lable의 시작 주소는 항상 32byte 경계로 정렬됨을 보장한다.
                                 */
cache_on:	mov	r3, #8			@ cache_on function
		b	call_cache_fn

/*
 * Initialize the highest priority protection region, PR7
 * to cover all 32bit address and cacheable and bufferable.
 */
__armv4_mpu_cache_on:
		mov	r0, #0x3f		@ 4G, the whole
		mcr	p15, 0, r0, c6, c7, 0	@ PR7 Area Setting
		mcr 	p15, 0, r0, c6, c7, 1

		mov	r0, #0x80		@ PR7
		mcr	p15, 0, r0, c2, c0, 0	@ D-cache on
		mcr	p15, 0, r0, c2, c0, 1	@ I-cache on
		mcr	p15, 0, r0, c3, c0, 0	@ write-buffer on

		mov	r0, #0xc000
		mcr	p15, 0, r0, c5, c0, 1	@ I-access permission
		mcr	p15, 0, r0, c5, c0, 0	@ D-access permission

		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c7, c5, 0	@ flush(inval) I-Cache
		mcr	p15, 0, r0, c7, c6, 0	@ flush(inval) D-Cache
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
						@ ...I .... ..D. WC.M
		orr	r0, r0, #0x002d		@ .... .... ..1. 11.1
		orr	r0, r0, #0x1000		@ ...1 .... .... ....

		mcr	p15, 0, r0, c1, c0, 0	@ write control reg

		mov	r0, #0
		mcr	p15, 0, r0, c7, c5, 0	@ flush(inval) I-Cache
		mcr	p15, 0, r0, c7, c6, 0	@ flush(inval) D-Cache
		mov	pc, lr

__armv3_mpu_cache_on:
		mov	r0, #0x3f		@ 4G, the whole
		mcr	p15, 0, r0, c6, c7, 0	@ PR7 Area Setting

		mov	r0, #0x80		@ PR7
		mcr	p15, 0, r0, c2, c0, 0	@ cache on
		mcr	p15, 0, r0, c3, c0, 0	@ write-buffer on

		mov	r0, #0xc000
		mcr	p15, 0, r0, c5, c0, 0	@ access permission

		mov	r0, #0
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		/*
		 * ?? ARMv3 MMU does not allow reading the control register,
		 * does this really work on ARMv3 MPU?
		 */
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
						@ .... .... .... WC.M
		orr	r0, r0, #0x000d		@ .... .... .... 11.1
		/* ?? this overwrites the value constructed above? */
		mov	r0, #0
		mcr	p15, 0, r0, c1, c0, 0	@ write control reg

		/* ?? invalidate for the second time? */
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

#ifdef CONFIG_CPU_DCACHE_WRITETHROUGH
#define CB_BITS 0x08
#else
#define CB_BITS 0x0c
#endif

/* *************************************************************************
 * @ brief: 
 * 
 * r3 : 결과값 - 0x4000
 * r4 : 0x8000 - zimage 풀릴위치   
 *      (ldr	r4, =zreladdr)
 * 16384(0x4000 - 16kB) : Page directory size
 * r3이 page directory start address로 추정
 * ************************************************************************* */
__setup_mmu:	sub	r3, r4, #16384		@ Page directory size

	   /* -------------------------------------------------------------------
 		* bic(and not) : 0x3fff를 0으로 - 0x4000으로 alignment 
 		* TODO: 왜 두번 instruction ?
		* ------------------------------------------------------------------- */
		bic	r3, r3, #0xff		@ Align the pointer
		bic	r3, r3, #0x3f00

	   /* -------------------------------------------------------------------
		* Initialise the page tables, turning on the cacheable and bufferable
		* bits for the RAM area only.
		* ------------------------------------------------------------------- */
		mov	r0, r3

	   /* -------------------------------------------------------------------
	    * lsr : logical shift right - barrel shift
 		*       18bit - 256k
	    * ------------------------------------------------------------------- */
		mov	r9, r0, lsr #18

	   /* ^^ ----------------------------------------------------------------
	    * lsr : logical shift right
 		*       
		* 결국 하위 18비트를 clear
 		* Physical한 start of RAM 
 		* ------------------------------------------------------------------- */		
/* ================================================ */
/* IAMROOT-12-B,16th(2015.08.08 22:05):         End */
/* ================================================ */


/* ================================================ */
/* IAMROOT-12-B,18th(2015.08.22 18:30): Start       */
/* ================================================ */
 	   /* -------------------------------------------------------------------
 	    * r9 : Start of RAM
 	    * mov	r9, r0, lsr #18
 	    * mov	r9, r9, lsl #18
 	    * r10 : end of RAM -> reasonable RAM size  256MB
 	    *  0x10000000 -> 268435456 -> 256MB
 	    * ------------------------------------------------------------------- */
		mov	r9, r9, lsl #18		@ start of RAM
		add	r10, r9, #0x10000000	@ a reasonable RAM size

	   /* -------------------------------------------------------------------
 	    * armv7-a-r-manual.pdf (p.1326) : AP[2]
 	    * Short-descriptor translation table first-level descriptor formats
 	    *  -> section
 	    * armv7-a-r-manual.pdf (p.1359) : XN
 	    *  -> B3.7.2 Execute-never restrictions on instruction fetching
 	    * armv7-a-r-manual.pdf (p.1358) :  AP[2] AP[1:0] -> FULL Access
 	    *  -> Table B3-8 VMSAv7 MMU access permissions
 	    *  r1 = 0x12
 	    *   -> r1 = 0x12 | 3*(2^10)
 	    *   -> r1 = 0x12 | 0xC00
 	    *   -> r1 = 0xC12
 	    * ------------------------------------------------------------------- */
		mov	r1, #0x12		@ XN|U + section mapping
		orr	r1, r1, #3 << 10	@ AP=11

	   /* -------------------------------------------------------------------
 	    * r3 : 0x4000 -> page directory 시작 주소
 	    * r2 = 0x4000 +  0x4000 (#16384(16KB))
 	    * r2 = 0x8000	, 압축파일이 풀릴 주소
 	    * r2 와 r4는 같음(zreladdr)
  	    * ------------------------------------------------------------------- */
		add	r2, r3, #16384 @ 0x4000 <- 16384(16KB)

	   /* -------------------------------------------------------------------
		* HS : 부호 없는 높거나 같음
		* LO : 부호 없는 낮음
		* r1 = 0xC12 , virt 주소
		* r9 = start of RAM
		* r10 = end of RAM
		* r0 =
		* r2 =
		* r6 =
		* U : 다른 ARM Architecture에선 XN과 유사 ?
		* ------------------------------------------------------------------- */
1:		cmp	r1, r9			@ if virt > start of RAM
		cmphs	r10, r1			@   && end of RAM > virt

	   /* -------------------------------------------------------------------
		* bic(bit clear) --> Rd := Rn AND NOT Operand2
		* r1이 값이 램 영역일 경우 : Set cacheable, bufferable
		* armv7-a-r-manual.pdf (p.127) : Cacheability
		*   --> Table A3-5 Memory attribute summary
		*  r1 := r1 & (1110 0011)b
		* ------------------------------------------------------------------- */
		bic	r1, r1, #0x1c		@ clear XN|U + C + B

	   /* -------------------------------------------------------------------
		* orr --> Rd := Rn OR Operand2
		* r1이 값이 램 영역이 아닐 경우 : clear cacheable, bufferable
		* r1 := r1 | (0001 0000)b
		* ------------------------------------------------------------------- */
		orrlo	r1, r1, #0x10		@ Set XN|U for non-RAM

		orrhs	r1, r1, r6		@ set RAM section settings
		str	r1, [r0], #4		@ 1:1 mapping
		add	r1, r1, #1048576

	   /* -------------------------------------------------------------------
		* teq : exclusive-OR 연산
		* r0 = 0x4000 ~ 4byte 단위로 증가
		* r2 = 0x8000
		* ------------------------------------------------------------------- */
		teq	r0, r2
		bne	1b

/*
 * If ever we are running from Flash, then we surely want the cache
 * to be enabled also for our execution instance...  We map 2MB of it
 * so there is no map overlap problem for up to 1 MB compressed kernel.
 * If the execution is in RAM then we would only be duplicating the above.
 */

/* ================================================== */
/* IAMROOT-12-B,18th(2015.08.22 22:05): End         */
/* ================================================== */

/* ================================================== */
/* IAMROOT-12-B,19th(2015.08.29 19:30): Start         */
/* ================================================== */

	   /* -------------------------------------------------------------------
		* armv7-a-r-manual.pdf (p.1326) : B(Buffer) , Section[2]
		* Short-descriptor translation table first-level descriptor formats
		*  -> section
 		* orr Rd Rn Operand2 --> Rd := Rn OR Operand2
 		* r6 = 0x0E
		* r1 = r6 | (0000 0100)b
		*  --> r1 = 0x0E
		* ------------------------------------------------------------------- */
		orr	r1, r6, #0x04		@ ensure B is set for this 
	   /* -------------------------------------------------------------------
		* r6 세팅 되어 있지만 확인 차원에 세팅
		* ------------------------------------------------------------------- */

	   /* -------------------------------------------------------------------
 		* r1 = r1 | [3 * (2^10)]
	 	* r1 = 0x0E | 0xC00
		*  --> r1 = 0xC0E
		* ------------------------------------------------------------------- */
		orr	r1, r1, #3 << 10

	   /* -------------------------------------------------------------------
		* ADD{S} Rd, Rn, <Operand2>  --> Rd := Rn + Operand2
 		* ADD Rd, Rn, #<imm12> --> Rd := Rn + imm12, imm12 range 0-4095
 		* MOV{S} Rd, <Operand2> --> Rd := Operand2
 		* str : Store Register with word
 		* r2 <- pc()
 		* r2 <- (r2 >>> 20회)
 		* r1 = r1 | (r2 <<< 20회)
 		* r0 = r3 + (r2 <<< 2회)
		* ------------------------------------------------------------------- */
		mov	r2, pc
		mov	r2, r2, lsr #20
		orr	r1, r1, r2, lsl #20
		add	r0, r3, r2, lsl #2

	   /* -------------------------------------------------------------------
 		* str X Y Z --> X가 가리키는 주소의 값을 Y+Z에 저장
 		*  -> str r0, [r2], #4
 		*  -> str r1, [r6], #4
		* ------------------------------------------------------------------- */
		str	r1, [r0], #4  @ 1:1 mapping
		add	r1, r1, #1048576 @ 1MB 단위 섹션으로 관리: 1048576 = 1024 * 1024
		str	r1, [r0]

	   /* -------------------------------------------------------------------
 		* lr은 __armv7_mmu_cache_on 레이블에서
 		* blne __setup_mmu 다음 주소를 나타냄
		* ------------------------------------------------------------------- */
		mov	pc, lr 

ENDPROC(__setup_mmu)
/* ================================================ */
/*  IAMROOT-12-B,18th(2015.08.22 22:05): End        */
/* ================================================ */


@ Enable unaligned access on v6, to allow better code generation
@ for the decompressor C code:
__armv6_mmu_cache_on:
		mrc	p15, 0, r0, c1, c0, 0	@ read SCTLR
		bic	r0, r0, #2		@ A (no unaligned access fault)
		orr	r0, r0, #1 << 22	@ U (v6 unaligned access model)
		mcr	p15, 0, r0, c1, c0, 0	@ write SCTLR
		b	__armv4_mmu_cache_on

__arm926ejs_mmu_cache_on:
#ifdef CONFIG_CPU_DCACHE_WRITETHROUGH
		mov	r0, #4			@ put dcache in WT mode
		mcr	p15, 7, r0, c15, c0, 0
#endif

__armv4_mmu_cache_on:
		mov	r12, lr
#ifdef CONFIG_MMU
		mov	r6, #CB_BITS | 0x12	@ U
		bl	__setup_mmu
		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
		orr	r0, r0, #0x5000		@ I-cache enable, RR cache replacement
		orr	r0, r0, #0x0030
 ARM_BE8(	orr	r0, r0, #1 << 25 )	@ big-endian page tables
		bl	__common_mmu_cache_on
		mov	r0, #0
		mcr	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
#endif
		mov	pc, r12

__armv7_mmu_cache_on:

/* lr : start address of restart label
 * blne	__setup_mmu - lr주소를 바꾸므로 r12 임시저장 
 */
		mov	r12, lr 
	   /* -------------------------------------------------------------------
		* restart 레이블
		* ------------------------------------------------------------------- */
#ifdef CONFIG_MMU
/* MRC - coprocessor의 값을 읽어오는 instruction 
 * Format : 
 * p15 - CP15. Coprocessor 15. Coprocessor의 register가 15개 있다는
 * 0   - op code
 * r11 - 결과값 저장 위치
 * c0  - cp15의 c0 기본 레지스터
 * c1  - c0 기본 스터의 c1 보조 레지스터
 * 4   - op code 2
 * (0 레지스터의 0번째 index의 Register) 와 (c1 레지스터의 4번째 index 레지스터랑) (어떤 계산을 해서) (r11 레지스터) 에 쓴다.
 * ID_MMFR0 레지스터 r11의 저장
 * Ref : http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0464d/BABIGAED.html
 * cp15의 c0, 0, c1, 4의 기본값은 ID_MMFR0(0x10101105).
 * 즉, r11 = 0x10101105
 */
		mrc	p15, 0, r11, c0, c1, 4	@ read ID_MMFR0

/* VMSA - Virtual Memory System Arch tecture -- Virutal memory의 특징
 * PMSA - Physcial Memory System Architecture -- Physical memory의 특징
 * Coprocessor의 메모리 특징을 읽어서 
 * VMSA[0:3] & 0xf - 뭐라도 있으면 값이 나올테니까 zflag 안스고
 * zflag 안세워지면 - Not equal
 * VMSA Support : mov실행 
 * VMSA Support X : mov 실행 x
 */
		tst	r11, #0xf		@ VMSA

/* #ifdef CONFIG_CPU_DCACHE_WRITETHROUGH
   #define CB_BITS 0x08
   #else
   #define CB_BITS 0x0c  -- 현재 우리 Configuration (Writeback)
   #endif 
 * 0x0c | 0x02 = 0x0e
 * XN : Execute Never  
 * ref : http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360f/CACHFICI.html
 * TODO: XN bit의 정확한 동작 방식 
 */
		movne	r6, #CB_BITS | 0x02	@ !XN
		blne	__setup_mmu
   /* -------------------------------------------------------------------
	* MMU 세팅이후 진행
	* ------------------------------------------------------------------- */

		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		tst	r11, #0xf		@ VMSA
		mcrne	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
   /* -------------------------------------------------------------------
	* DSB: wirte 할게 있으면 완료 이후 진행 (동기처리)
	* MMU start 전 flush 
	* ------------------------------------------------------------------- */
#endif
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
   /* -------------------------------------------------------------------
	* r0: 0x00c50878 레퍼런스 메뉴얼: 1705 p
	* ------------------------------------------------------------------- */
		bic	r0, r0, #1 << 28	@ clear SCTLR.TRE
		orr	r0, r0, #0x5000		@ I-cache enable, RR cache replacement
		orr	r0, r0, #0x003c		@ write buffer
		bic	r0, r0, #2		@ A (no unaligned access fault)
		orr	r0, r0, #1 << 22	@ U (v6 unaligned access model)
						@ (needed for ARM1176)
   /* -------------------------------------------------------------------
	* VMSA는 추상화 개념, MMU는 수행하는 장치
	* #bic     r0, r0, #1 << 28        @ clear SCTLR.TRE 
	* bit clear 한 이슈 조사
	* 15번bit reserved  
	* 레퍼런스 메뉴얼 : RR 부분 참고, 1708 p
	* trustzone 내용 조사 (이슈)
	* Bits[4:3] Reserved, RAO/SBOP.
	* VMSA에 대하 조사(이슈)
	* 아키텍쳐 버전에 따라 alignment 수행(아래줄은 호환성을 위해)
	* alignment를 arm v6는 0.1로 설정가능
	* alignment를 arm v7는 1로 설정 
	* ------------------------------------------------------------------- */
/* ================================================ */
/*  IAMROOT-12-B,19th(2015.08.29 19:30): End
/* ================================================ */ 
#ifdef CONFIG_MMU
 ARM_BE8(	orr	r0, r0, #1 << 25 )	@ big-endian page tables
		mrcne   p15, 0, r6, c2, c0, 2   @ read ttb control reg
		orrne	r0, r0, #1		@ MMU enabled
		movne	r1, #0xfffffffd		@ domain 0 = client
		bic     r6, r6, #1 << 31        @ 32-bit translation system
		bic     r6, r6, #3 << 0         @ use only ttbr0
		mcrne	p15, 0, r3, c2, c0, 0	@ load page table pointer
		mcrne	p15, 0, r1, c3, c0, 0	@ load domain access control
		mcrne   p15, 0, r6, c2, c0, 2   @ load ttb control
#endif
		mcr	p15, 0, r0, c7, c5, 4	@ ISB
		mcr	p15, 0, r0, c1, c0, 0	@ load control register
		mrc	p15, 0, r0, c1, c0, 0	@ and read it back
		mov	r0, #0
		mcr	p15, 0, r0, c7, c5, 4	@ ISB
		mov	pc, r12

__fa526_cache_on:
		mov	r12, lr
		mov	r6, #CB_BITS | 0x12	@ U
		bl	__setup_mmu
		mov	r0, #0
		mcr	p15, 0, r0, c7, c7, 0	@ Invalidate whole cache
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c8, c7, 0	@ flush UTLB
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
		orr	r0, r0, #0x1000		@ I-cache enable
		bl	__common_mmu_cache_on
		mov	r0, #0
		mcr	p15, 0, r0, c8, c7, 0	@ flush UTLB
		mov	pc, r12

__common_mmu_cache_on:
#ifndef CONFIG_THUMB2_KERNEL
#ifndef DEBUG
		orr	r0, r0, #0x000d		@ Write buffer, mmu
#endif
		mov	r1, #-1
		mcr	p15, 0, r3, c2, c0, 0	@ load page table pointer
		mcr	p15, 0, r1, c3, c0, 0	@ load domain access control
		b	1f
		.align	5			@ cache line aligned
1:		mcr	p15, 0, r0, c1, c0, 0	@ load control register
		mrc	p15, 0, r0, c1, c0, 0	@ and read it back to
		sub	pc, lr, r0, lsr #32	@ properly flush pipeline
#endif

#define PROC_ENTRY_SIZE (4*5)

/*
 * Here follow the relocatable cache support functions for the
 * various processors.  This is a generic hook for locating an
 * entry and jumping to an instruction at the specified offset
 * from the start of the block.  Please note this is all position
 * independent code.
 *
 *  r1  = corrupted
 *  r2  = corrupted
 *  r3  = block offset
 *  r9  = corrupted
 *  r12 = corrupted
 */

/* IAMROOT-12-B,14th(2015.08.01 19:30 ~ 22:05)
 * -------------------------------------------
 * 현재 리눅스 커널 버전이 해당 core processor를 지원하는지를 확인한다.
 * 분석 진행 중... (14주차 스터디 종료)
 *
 * Raspberry Pi 2
 * --------------
 * # For more information about the system control registers 'c0 ~ c15' is here
 * 		REF: Cortex-A7 MPCore Technical Reference Manual
 * 		LINK: http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0388f/CIHCBHFB.html
 *
 * # For more information about c0 registers 'MIDR' filed value is here
 *		REF: ARMv7-AR Reference Manual (Issue C)
 *      LINK: http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0406c/index.html
 *      PAGE: 1649
 */
call_cache_fn:	adr	r12, proc_types
#ifdef CONFIG_CPU_CP15                                  /* 해당 커널 설정 파일에서 CONFIG_CPU_CP15가 설정되어 있으면, */
		mrc	p15, 0, r9, c0, c0	@ get processor ID      /* c0 registers의 MIDR(Op1 0: Main ID register) 필드 값을 r9로 읽어들인다. */
#else                                                   /* 설정되어 있지 않으면, */
		ldr	r9, =CONFIG_PROCESSOR_ID                    /* 커널 설정 파일에 정의된 CONFIG_PROCESSOR_ID 값을 r9로 읽어들인다. */
#endif
1:		ldr	r1, [r12, #0]		@ get value             /* proc_types: lable의 시작 주소 + (0 ~ #PROC_ENTRY_SIZE)에서 처음 상수값 (Arch ID)을 읽어들인다. */
		ldr	r2, [r12, #4]		@ get mask              /* proc_types: lable의 시작 주소 + (0 ~ #PROC_ENTRY_SIZE)에서 두 번째 상수값 (Mask bits)을 읽어들인다. */
		eor	r1, r1, r9		@ (real ^ match)            /* 커널이 지원하는 processor ID(proc_types lable)와 c0의 MIDR 필드 값을 exclusive or 취한 값을 r1에 저장한다. */
		tst	r1, r2			@       & mask		        /* r1과 r2의 값을 비교하여 일치하면 CPSR의 'Z' flag를 '1'로, 일치하지 않으면 '0'으로 설정한다. */
 ARM(		addeq	pc, r12, r3		) @ call cache function /* CPSR의 'Z' flag가 '1'이면 해당 core processor의 cache를 on시키기 위해 지정된 function을 호출한다. */

/* ================================================ */
/* IAMROOT-12-B,14th(2015.08.01 19:30 ~ 22:05): End */
/* ================================================ */


/* ================================================== */
/* IAMROOT-12-B,15th(2015.08.08 19:30): Start         */
/* ================================================== */
/* eq == zflag on, (PC = r12(proc_types) + r3(0x8))  = __armv7_mmu_cache_on 
 */
 THUMB(		addeq	r12, r3			)
 THUMB(		moveq	pc, r12			) @ call cache function
		add	r12, r12, #PROC_ENTRY_SIZE    /* 현재 읽어들인 processor ID가 일치하지 않으면, 그 다음 processor ID를 읽어들이기 위해 offset을 20byte만큼 증가시킨다. */
		b	1b                            /* 1: lable로 다시 돌아가 c0의 MIDR 필드 값과 일치하는지 검사를 수행한다. */

/*
 * Table for cache operations.  This is basically:
 *   - CPU ID match
 *   - CPU ID mask
 *   - 'cache on' method instruction
 *   - 'cache off' method instruction
 *   - 'cache flush' method instruction
 *
 * We match an entry using: ((real_id ^ match) & mask) == 0
 *
 * Writethrough caches generally only need 'on' and 'off'
 * methods.  Writeback caches _must_ have the flush method
 * defined.
 */
		.align	2
		.type	proc_types,#object
proc_types:
		.word	0x41000000		@ old ARM ID
		.word	0xff00f000
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41007000		@ ARM7/710
		.word	0xfff8fe00
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41807200		@ ARM720T (writethrough)
		.word	0xffffff00
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41007400		@ ARM74x
		.word	0xff00ff00
		W(b)	__armv3_mpu_cache_on
		W(b)	__armv3_mpu_cache_off
		W(b)	__armv3_mpu_cache_flush
		
		.word	0x41009400		@ ARM94x
		.word	0xff00ff00
		W(b)	__armv4_mpu_cache_on
		W(b)	__armv4_mpu_cache_off
		W(b)	__armv4_mpu_cache_flush

		.word	0x41069260		@ ARM926EJ-S (v5TEJ)
		.word	0xff0ffff0
		W(b)	__arm926ejs_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x00007000		@ ARM7 IDs
		.word	0x0000f000
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		@ Everything from here on will be the new ID system.

		.word	0x4401a100		@ sa110 / sa1100
		.word	0xffffffe0
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x6901b110		@ sa1110
		.word	0xfffffff0
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x56056900
		.word	0xffffff00		@ PXA9xx
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x56158000		@ PXA168
		.word	0xfffff000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x56050000		@ Feroceon
		.word	0xff0f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

#ifdef CONFIG_CPU_FEROCEON_OLD_ID
		/* this conflicts with the standard ARMv5TE entry */
		.long	0x41009260		@ Old Feroceon
		.long	0xff00fff0
		b	__armv4_mmu_cache_on
		b	__armv4_mmu_cache_off
		b	__armv5tej_mmu_cache_flush
#endif

		.word	0x66015261		@ FA526
		.word	0xff01fff1
		W(b)	__fa526_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__fa526_cache_flush

		@ These match on the architecture ID

		.word	0x00020000		@ ARMv4T
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x00050000		@ ARMv5TE
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x00060000		@ ARMv5TEJ
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x0007b000		@ ARMv6
		.word	0x000ff000
		W(b)	__armv6_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv6_mmu_cache_flush
/* Raspberry PI 의 CPU ID */
		.word	0x000f0000		@ new CPU Id
		.word	0x000f0000
		W(b)	__armv7_mmu_cache_on
		W(b)	__armv7_mmu_cache_off
		W(b)	__armv7_mmu_cache_flush

		.word	0			@ unrecognised type
		.word	0
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.size	proc_types, . - proc_types

		/*
		 * If you get a "non-constant expression in ".if" statement"
		 * error from the assembler on this line, check that you have
		 * not accidentally written a "b" instruction where you should
		 * have written W(b).
		 */
		.if (. - proc_types) % PROC_ENTRY_SIZE != 0
		.error "The size of one or more proc_types entries is wrong."
		.endif

/*
 * Turn off the Cache and MMU.  ARMv3 does not support
 * reading the control register, but ARMv4 does.
 *
 * On exit,
 *  r0, r1, r2, r3, r9, r12 corrupted
 * This routine must preserve:
 *  r4, r7, r8
 */
		.align	5
cache_off:	mov	r3, #12			@ cache_off function
		b	call_cache_fn

__armv4_mpu_cache_off:
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0	@ turn MPU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c7, c6, 0	@ flush D-Cache
		mcr	p15, 0, r0, c7, c5, 0	@ flush I-Cache
		mov	pc, lr

__armv3_mpu_cache_off:
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0, 0	@ turn MPU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

__armv4_mmu_cache_off:
#ifdef CONFIG_MMU
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0	@ turn MMU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c7	@ invalidate whole cache v4
		mcr	p15, 0, r0, c8, c7	@ invalidate whole TLB v4
#endif
		mov	pc, lr

__armv7_mmu_cache_off:
		mrc	p15, 0, r0, c1, c0
#ifdef CONFIG_MMU
		bic	r0, r0, #0x000d
#else
		bic	r0, r0, #0x000c
#endif
		mcr	p15, 0, r0, c1, c0	@ turn MMU and cache off
		mov	r12, lr
		bl	__armv7_mmu_cache_flush
		mov	r0, #0
#ifdef CONFIG_MMU
		mcr	p15, 0, r0, c8, c7, 0	@ invalidate whole TLB
#endif
		mcr	p15, 0, r0, c7, c5, 6	@ invalidate BTC
		mcr	p15, 0, r0, c7, c10, 4	@ DSB
		mcr	p15, 0, r0, c7, c5, 4	@ ISB
		mov	pc, r12

/*
 * Clean and flush the cache to maintain consistency.
 *
 * On exit,
 *  r1, r2, r3, r9, r10, r11, r12 corrupted
 * This routine must preserve:
 *  r4, r6, r7, r8
 */
		.align	5
cache_clean_flush:
		mov	r3, #16
		b	call_cache_fn

__armv4_mpu_cache_flush:
		tst	r4, #1
		movne	pc, lr
		mov	r2, #1
		mov	r3, #0
		mcr	p15, 0, ip, c7, c6, 0	@ invalidate D cache
		mov	r1, #7 << 5		@ 8 segments
1:		orr	r3, r1, #63 << 26	@ 64 entries
2:		mcr	p15, 0, r3, c7, c14, 2	@ clean & invalidate D index
		subs	r3, r3, #1 << 26
		bcs	2b			@ entries 63 to 0
		subs 	r1, r1, #1 << 5
		bcs	1b			@ segments 7 to 0

		teq	r2, #0
		mcrne	p15, 0, ip, c7, c5, 0	@ invalidate I cache
		mcr	p15, 0, ip, c7, c10, 4	@ drain WB
		mov	pc, lr
		
__fa526_cache_flush:
		tst	r4, #1
		movne	pc, lr
		mov	r1, #0
		mcr	p15, 0, r1, c7, c14, 0	@ clean and invalidate D cache
		mcr	p15, 0, r1, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv6_mmu_cache_flush:
		mov	r1, #0
		tst	r4, #1
		mcreq	p15, 0, r1, c7, c14, 0	@ clean+invalidate D
		mcr	p15, 0, r1, c7, c5, 0	@ invalidate I+BTB
		mcreq	p15, 0, r1, c7, c15, 0	@ clean+invalidate unified
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv7_mmu_cache_flush:
		tst	r4, #1
		bne	iflush
		mrc	p15, 0, r10, c0, c1, 5	@ read ID_MMFR1
		tst	r10, #0xf << 16		@ hierarchical cache (ARMv7)
		mov	r10, #0
		beq	hierarchical
		mcr	p15, 0, r10, c7, c14, 0	@ clean+invalidate D
		b	iflush
hierarchical:
		mcr	p15, 0, r10, c7, c10, 5	@ DMB
		stmfd	sp!, {r0-r7, r9-r11}
		mrc	p15, 1, r0, c0, c0, 1	@ read clidr
		ands	r3, r0, #0x7000000	@ extract loc from clidr
		mov	r3, r3, lsr #23		@ left align loc bit field
		beq	finished		@ if loc is 0, then no need to clean
		mov	r10, #0			@ start clean at cache level 0
loop1:
		add	r2, r10, r10, lsr #1	@ work out 3x current cache level
		mov	r1, r0, lsr r2		@ extract cache type bits from clidr
		and	r1, r1, #7		@ mask of the bits for current cache only
		cmp	r1, #2			@ see what cache we have at this level
		blt	skip			@ skip if no cache, or just i-cache
		mcr	p15, 2, r10, c0, c0, 0	@ select current cache level in cssr
		mcr	p15, 0, r10, c7, c5, 4	@ isb to sych the new cssr&csidr
		mrc	p15, 1, r1, c0, c0, 0	@ read the new csidr
		and	r2, r1, #7		@ extract the length of the cache lines
		add	r2, r2, #4		@ add 4 (line length offset)
		ldr	r4, =0x3ff
		ands	r4, r4, r1, lsr #3	@ find maximum number on the way size
		clz	r5, r4			@ find bit position of way size increment
		ldr	r7, =0x7fff
		ands	r7, r7, r1, lsr #13	@ extract max number of the index size
loop2:
		mov	r9, r4			@ create working copy of max way size
loop3:
 ARM(		orr	r11, r10, r9, lsl r5	) @ factor way and cache number into r11
 ARM(		orr	r11, r11, r7, lsl r2	) @ factor index number into r11
 THUMB(		lsl	r6, r9, r5		)
 THUMB(		orr	r11, r10, r6		) @ factor way and cache number into r11
 THUMB(		lsl	r6, r7, r2		)
 THUMB(		orr	r11, r11, r6		) @ factor index number into r11
		mcr	p15, 0, r11, c7, c14, 2	@ clean & invalidate by set/way
		subs	r9, r9, #1		@ decrement the way
		bge	loop3
		subs	r7, r7, #1		@ decrement the index
		bge	loop2
skip:
		add	r10, r10, #2		@ increment cache number
		cmp	r3, r10
		bgt	loop1
finished:
		ldmfd	sp!, {r0-r7, r9-r11}
		mov	r10, #0			@ swith back to cache level 0
		mcr	p15, 2, r10, c0, c0, 0	@ select current cache level in cssr
iflush:
		mcr	p15, 0, r10, c7, c10, 4	@ DSB
		mcr	p15, 0, r10, c7, c5, 0	@ invalidate I+BTB
		mcr	p15, 0, r10, c7, c10, 4	@ DSB
		mcr	p15, 0, r10, c7, c5, 4	@ ISB
		mov	pc, lr

__armv5tej_mmu_cache_flush:
		tst	r4, #1
		movne	pc, lr
1:		mrc	p15, 0, r15, c7, c14, 3	@ test,clean,invalidate D cache
		bne	1b
		mcr	p15, 0, r0, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r0, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv4_mmu_cache_flush:
		tst	r4, #1
		movne	pc, lr
		mov	r2, #64*1024		@ default: 32K dcache size (*2)
		mov	r11, #32		@ default: 32 byte line size
		mrc	p15, 0, r3, c0, c0, 1	@ read cache type
		teq	r3, r9			@ cache ID register present?
		beq	no_cache_id
		mov	r1, r3, lsr #18
		and	r1, r1, #7
		mov	r2, #1024
		mov	r2, r2, lsl r1		@ base dcache size *2
		tst	r3, #1 << 14		@ test M bit
		addne	r2, r2, r2, lsr #1	@ +1/2 size if M == 1
		mov	r3, r3, lsr #12
		and	r3, r3, #3
		mov	r11, #8
		mov	r11, r11, lsl r3	@ cache line size in bytes
no_cache_id:
		mov	r1, pc
		bic	r1, r1, #63		@ align to longest cache line
		add	r2, r1, r2
1:
 ARM(		ldr	r3, [r1], r11		) @ s/w flush D cache
 THUMB(		ldr     r3, [r1]		) @ s/w flush D cache
 THUMB(		add     r1, r1, r11		)
		teq	r1, r2
		bne	1b

		mcr	p15, 0, r1, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r1, c7, c6, 0	@ flush D cache
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv3_mmu_cache_flush:
__armv3_mpu_cache_flush:
		tst	r4, #1
		movne	pc, lr
		mov	r1, #0
		mcr	p15, 0, r1, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

/*
 * Various debugging routines for printing hex characters and
 * memory, which again must be relocatable.
 */
#ifdef DEBUG
		.align	2
		.type	phexbuf,#object
phexbuf:	.space	12
		.size	phexbuf, . - phexbuf

@ phex corrupts {r0, r1, r2, r3}
phex:		adr	r3, phexbuf
		mov	r2, #0
		strb	r2, [r3, r1]
1:		subs	r1, r1, #1
		movmi	r0, r3
		bmi	puts
		and	r2, r0, #15
		mov	r0, r0, lsr #4
		cmp	r2, #10
		addge	r2, r2, #7
		add	r2, r2, #'0'
		strb	r2, [r3, r1]
		b	1b

@ puts corrupts {r0, r1, r2, r3}
puts:		loadsp	r3, r1
1:		ldrb	r2, [r0], #1
		teq	r2, #0
		moveq	pc, lr
2:		writeb	r2, r3
		mov	r1, #0x00020000
3:		subs	r1, r1, #1
		bne	3b
		teq	r2, #'\n'
		moveq	r2, #'\r'
		beq	2b
		teq	r0, #0
		bne	1b
		mov	pc, lr
@ putc corrupts {r0, r1, r2, r3}
putc:
		mov	r2, r0
		mov	r0, #0
		loadsp	r3, r1
		b	2b

@ memdump corrupts {r0, r1, r2, r3, r10, r11, r12, lr}
memdump:	mov	r12, r0
		mov	r10, lr
		mov	r11, #0
2:		mov	r0, r11, lsl #2
		add	r0, r0, r12
		mov	r1, #8
		bl	phex
		mov	r0, #':'
		bl	putc
1:		mov	r0, #' '
		bl	putc
		ldr	r0, [r12, r11, lsl #2]
		mov	r1, #8
		bl	phex
		and	r0, r11, #7
		teq	r0, #3
		moveq	r0, #' '
		bleq	putc
		and	r0, r11, #7
		add	r11, r11, #1
		teq	r0, #7
		bne	1b
		mov	r0, #'\n'
		bl	putc
		cmp	r11, #64
		blt	2b
		mov	pc, r10
#endif

		.ltorg

#ifdef CONFIG_ARM_VIRT_EXT
.align 5
__hyp_reentry_vectors:
		W(b)	.			@ reset
		W(b)	.			@ undef
		W(b)	.			@ svc
		W(b)	.			@ pabort
		W(b)	.			@ dabort
		W(b)	__enter_kernel		@ hyp
		W(b)	.			@ irq
		W(b)	.			@ fiq
#endif /* CONFIG_ARM_VIRT_EXT */

__enter_kernel:
		mov	r0, #0			@ must be 0
 ARM(		mov	pc, r4	)		@ call kernel
 THUMB(		bx	r4	)		@ entry point is always ARM

reloc_code_end:

		.align
		.section ".stack", "aw", %nobits
.L_user_stack:	.space	4096
.L_user_stack_end:
	
