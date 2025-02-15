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

/* 
 * Copyright (c) 2006-2017 Frans Kaashoek, Robert Morris, Russ Cox, Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * ( a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/*
 * TODO: This file contains pci enumeration logic. We leave it here in
 * the kernel because port IO (IN/OUT) is needed. We should handle the
 * IO permission bitmap in TSS structure and move PCI enumeration to user
 * space in the future.
 * P.S. Rewrite this file because most part of this file comes from github.
*/
#include <arch/pci.h>
#include <arch/pciregister.h>
#include <common/util.h>
#include <common/macro.h>
#include <lib/printk.h>
#include <mm/uaccess.h>

struct pci_device pcidevs[NPCI] = {0};
int pcikeys[NPCI] = {0};

static int alloc_pci(void)
{
        struct pci_device* dev;
        int index = -1;

        for (dev = pcidevs; dev < &pcidevs[NPCI]; dev++) {
                index += 1;
                if (dev->state == PCI_FREE) {
                        goto found;
                }
        }
        return -1;

found:
        dev->state = PCI_USED;
        return index;
}

static void free_pci(int fd)
{
        struct pci_device dev = pcidevs[fd];
        memset(&dev, 0, sizeof(struct pci_device));
        dev.state = PCI_FREE;
}

int get_pci_dev(int dev_class)
{
        return pcikeys[dev_class];
}

/*
 * Class codes of PCI devices at their offsets
 */
char* PCI_CLASSES[18] = {
        "Unclassified",
        "Mass storage controller",
        "Network controller",
        "Display controller",
        "Multimedia controller",
        "Memory controller",
        "Bridge device",
        "Simple communication controller",
        "Base system peripheral",
        "Input device controller",
        "Docking station",
        "Processor",
        "Serial bus controller",
        "Wireless controller",
        "Intelligent controller",
        "Satellite communication controller",
        "Encryption controller",
        "Signal processing controller",
};

/*
 * Simple function to log PCI devices
 */
static void log_pci_device(struct pci_device* dev)
{
        char* class = PCI_CLASSES[PCI_CLASS(dev->dev_class)];
        uint32 bus_num = dev->bus->bus_num;
        uint32 dev_id = dev->dev;
        uint32 func = dev->func;
        uint32 vendor_id = PCI_VENDOR_ID(dev->dev_id);
        uint32 product = PCI_PRODUCT(dev->dev_id);
        uint32 class_name = PCI_CLASS(dev->dev_class);
        uint32 sub_class = PCI_SUBCLASS(dev->dev_class);
        uint32 irq_line = dev->irq_line;

        printk("PCI: %x:%x.%d: 0x%x:0x%x: class: %x.%x (%s) irq: %d\n",
                bus_num,
                dev_id,
                func,
                vendor_id,
                product,
                class_name,
                sub_class,
                class,
                irq_line);
}

/*
 * Iterate over the PCI device's Base Address Registers and store their
 * infomation on the deice indexed by the BAR index
 *
 * To determine the amount of address space needed by a PCI device,
 * you must save the original value of the BAR, write a value of all 1's
 * to the register, then read it back. The amount of memory can then be
 * determined by masking the information bits, performing a
 * bitwise NOT ('~' in C), and incrementing the value by 1.
 *
 * http://wiki.osdev.org/PCI
 */
int read_dev_bars(struct pci_device* f)
{
        uint32_t bar_width;
        uint32_t bar;
        for (bar = PCI_MAPREG_START; bar < PCI_MAPREG_END; bar += bar_width) {
                uint32_t oldv = confread32(f, bar);

                bar_width = 4;

                conf_write32(f, bar, 0xffffffff);
                uint32_t rv = confread32(f, bar);

                if (rv == 0)
                        continue;

                int regnum = PCI_MAPREG_NUM(bar);
                u32 base, size;
                if (PCI_MAPREG_TYPE(rv) == PCI_MAPREG_TYPE_MEM) {
                        if (PCI_MAPREG_MEM_TYPE(rv)
                            == PCI_MAPREG_MEM_TYPE_64BIT)
                                bar_width = 8;

                        size = PCI_MAPREG_MEM_SIZE(rv);
                        base = PCI_MAPREG_MEM_ADDR(oldv);
                        f->membase = base;
                        printk("mem region %d: %d bytes at 0x%lx\n",
                                regnum,
                                size,
                                f->membase);
                } else {
                        size = PCI_MAPREG_IO_SIZE(rv);
                        base = PCI_MAPREG_IO_ADDR(oldv);
                        printk("io region %d: %d bytes at 0x%x\n",
                                regnum,
                                size,
                                base);
                        f->iobase = base;
                }

                conf_write32(f, bar, oldv);
                f->reg_base[regnum] = base;
                f->reg_size[regnum] = size;

                if (size && !base)
                        printk("PCI device %x:%x.%d (%x:%x) "
                                "may be misconfigured: "
                                "region %d: base 0x%x, size %d\n",
                                f->bus->bus_num,
                                f->dev,
                                f->func,
                                PCI_VENDOR(f->dev_id),
                                PCI_PRODUCT(f->dev_id),
                                regnum,
                                base,
                                size);
        }

        return 0;
}

void log_pci_cap(uint8 type, uint8 bar, uint32 offset)
{
        switch (type) {
        case VIRTIO_PCI_CAP_COMMON_CFG:
                printk("cap: VIRTIO_PCI_CAP_COMMON_CFG bar: %d offset: %x\n",
                        bar,
                        offset);
                break;
        case VIRTIO_PCI_CAP_NOTIFY_CFG:
                printk("cap: VIRTIO_PCI_CAP_NOTIFY_CFG bar: %d offset: %x\n",
                        bar,
                        offset);
                break;
        case VIRTIO_PCI_CAP_ISR_CFG:
                printk("cap: VIRTIO_PCI_CAP_ISR_CFG bar: %d offset: %x\n",
                        bar,
                        offset);
                break;
        case VIRTIO_PCI_CAP_DEVICE_CFG:
                printk("cap: VIRTIO_PCI_CAP_DEVICE bar: %d offset: %x\n",
                        bar,
                        offset);
                break;
        case VIRTIO_PCI_CAP_PCI_CFG:
                printk("cap: VIRTIO_PCI_CAP_PCI_CFG bar: %d offset: %x\n",
                        bar,
                        offset);
                break;
        default:
                printk("unknown PCI cap type: %d\n", type);
                break;
        }
}

int config_pci(struct pci_device* device)
{
        uint8 next;

        // Enable memory and IO addressing
        conf_write32(device,
                     PCI_COMMAND_STATUS_REG,
                     PCI_COMMAND_IO_ENABLE | PCI_COMMAND_MEM_ENABLE
                             | PCI_COMMAND_MASTER_ENABLE);

        // uint32 status_register = confread32(device, PCI_COMMAND_STATUS_REG);
        // uint16 status = PCI_STATUS(status);
        uint16 status = confread16(device, PCI_COMMAND_STATUS_REG + 2);

        // Check if the device has a capabalities list
        if (!(status & PCI_COMMAND_CAPABALITES_LIST)) {
                printk("No dev capabilities\n");
                return -1;
        }

        uint32 cap_register = confread32(device, PCI_CAP_REG);
        uint8 cap_pointer = PCI_CAP_POINTER(cap_register) & PCI_CAP_MASK;

        while (cap_pointer) {
                next = confread8(device, cap_pointer + PCI_CAP_NEXT)
                       & PCI_CAP_MASK;
                uint8 type = confread8(device, cap_pointer + PCI_CAP_CFG_TYPE);
                uint8 bar = confread8(device, cap_pointer + PCI_CAP_BAR);
                uint32 offset = confread32(device, cap_pointer + PCI_CAP_OFF);
                log_pci_cap(type, bar, offset);
                // Location of the given capability in the PCI config space.
                device->cap[type] = cap_pointer;
                device->cap_bar[type] = bar;
                device->cap_off[type] = offset;

                // printk("cap type: %d pointer: %p\n", type, cap_pointer);

                cap_pointer = next;
        }

        return 0;
}

/*
 * Sets up the window into the BAR. Width is the width of the field access and
 * field_offset is the offset into the BAR.
 */
void setup_window(struct pci_device* dev, uint8 width, uint8 bar,
                  uint32 field_offset)
{
        uint8 cap_pointer = dev->cap[VIRTIO_PCI_CAP_PCI_CFG];

        conf_write8(
                dev, cap_pointer + offsetof(struct virtio_pci_cap, bar), bar);
        conf_write8(dev,
                    cap_pointer + offsetof(struct virtio_pci_cap, length),
                    width);
        conf_write32(dev,
                     cap_pointer + offsetof(struct virtio_pci_cap, offset),
                     field_offset);
}

static int pci_enumerate(struct pci_bus* bus)
{
        int num_dev = 0;
        struct pci_device dev_fn;
        int fd = alloc_pci();

        if (fd < 0 || fd >= NPCI) {
                printk("alloc_pci returns %d\n", fd);
                return -1;
        }

        dev_fn = pcidevs[fd];
        memset(&dev_fn, 0, sizeof(dev_fn));
        dev_fn.state = PCI_USED;
        dev_fn.bus = bus;

        printk("Enter pci_enumerate!\n");
        for (dev_fn.dev = 0; dev_fn.dev < PCI_MAX_DEVICES; dev_fn.dev++) {
                uint32 bhcl = confread32(&dev_fn, PCI_BHLC_REG);

                if (PCI_HDRTYPE_TYPE(bhcl) > 1) {
                        continue;
                }

                num_dev++;

                struct pci_device fn = dev_fn;

                // Configure the device functions
                for (fn.func = 0; fn.func < (PCI_HDRTYPE_MULTIFN(bhcl) ? 8 : 1);
                     fn.func++) {
                        int individual_fd = alloc_pci();

                        if (individual_fd < 0 || individual_fd >= NPCI) {
                                printk("alloc_pci returns %d\n", individual_fd);
                                return -1;
                        }

                        struct pci_device* individual_fn =
                                &pcidevs[individual_fd];
                        memmove(individual_fn, &fn, sizeof(struct pci_device));

                        individual_fn->dev_id = confread32(&fn, PCI_ID_REG);

                        // 0xffff is an invalid vendor ID
                        if (PCI_VENDOR_ID(individual_fn->dev_id) == 0xffff) {
                                free_pci(individual_fd);
                                continue;
                        }

                        uint32 intr =
                                confread32(individual_fn, PCI_INTERRUPT_REG);
                        individual_fn->irq_line = PCI_INTERRUPT_LINE(intr);
                        individual_fn->irq_pin = PCI_INTERRUPT_PIN(intr);

                        individual_fn->dev_class =
                                confread32(individual_fn, PCI_CLASS_REG);

                        // populate BAR information.
                        read_dev_bars(individual_fn);

                        if (PCI_VENDOR_ID(individual_fn->dev_id)
                            == VIRTIO_VENDOR_ID) {
                                switch (PCI_DEVICE_ID(individual_fn->dev_id)) {
                                case (T_NETWORK_CARD):
                                        printk("We have a transitional network device.\n");
                                        config_pci(individual_fn);

                                        // store the index to where the
                                        // pci_device struct is stored in the
                                        // pcidevs slab.
                                        kinfo("Mac addr: ");
                                        pcikeys[PCI_CLASS(
                                                individual_fn->dev_class)] =
                                                individual_fd;
                                        for (int i = 0; i < 6; i++) {
                                                individual_fn->mac[i] = inb(
                                                        individual_fn->iobase
                                                        + VIRTIO_DEV_SPECIFIC_OFF
                                                        + i);
                                                printk("%02x ",
                                                       individual_fn->mac[i]);
                                        }
                                        printk("\n");
                                        break;
                                default:
                                        printk("We have some other transitional device.\n");
                                }
                        } else {
                                pcikeys[PCI_CLASS(individual_fn->dev_class)] =
                                        individual_fd;
                        }

                        log_pci_device(individual_fn);
                }
        }
        return num_dev;
}

int pci_init(void)
{
        static struct pci_bus root;
        memset(&root, 0, sizeof(root));

        return pci_enumerate(&root);
}

void arch_get_pci_device(int class, u64 pci_dev_uaddr)
{
        int pci_fd;
        struct pci_device tmp_pdev;
        struct pci_device* pdev;

        pci_fd = get_pci_dev(class);
        pdev = &pcidevs[pci_fd];

        memcpy((u8*)&tmp_pdev, (u8*)pdev, sizeof(struct pci_device));
        tmp_pdev.bus = NULL;
        tmp_pdev.state = 0;

        copy_to_user((void *)pci_dev_uaddr, &tmp_pdev,
                     sizeof(struct pci_device));
}
