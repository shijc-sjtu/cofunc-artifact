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

#include <common/asm.h>
#include <common/vars.h>

BEGIN_FUNC(idle_thread_routine)
#ifndef CHCORE_PLAT_INTEL_TDX
idle:   hlt
        jmp idle
#else /* CHCORE_PLAT_INTEL_TDX */
idle:   jmp idle
#endif /* CHCORE_PLAT_INTEL_TDX */
END_FUNC(idle_thread_routine)
