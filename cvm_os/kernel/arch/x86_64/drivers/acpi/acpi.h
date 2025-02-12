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

#pragma once
#include <common/types.h>

/*
 * ACPI System Description Table (SDT) layout:
 * https://uefi.org/specs/ACPI/6.4/05_ACPI_Software_Programming_Model/ACPI_Software_Programming_Model.html
 */

struct acpi_sdt_header { // 36 bytes size
	char signature[4];
	u32 length;
	u8 revision;
	u8 checksum;
	char oem_id[6];
	char oem_table_id[8];
	u32 oem_revision;
	u32 creator_id;
	u32 creator_revision;
} __attribute__((packed));

struct rsdt_t {
	struct acpi_sdt_header h;
	u32 others[];
}__attribute__((packed));

struct xsdt_t {
	struct acpi_sdt_header h;
	u64 others[];
}__attribute__((packed));

struct rsdp_t {
	u8 signature[8];
	u8 checksum;
	u8 oemid[6];
	u8 revision;
	u32 rsdt_addr;
} __attribute__((packed));

struct xsdp_t {
	struct rsdp_t first_part;

	u32 length;
	u64 xsdt_addr;
	u8 extended_checksum;
	u8 reserved[3];
} __attribute__((packed));