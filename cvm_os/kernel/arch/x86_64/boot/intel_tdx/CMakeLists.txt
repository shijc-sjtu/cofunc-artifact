# Copyright (c) 2023 Institute of Parallel And Distributed Systems (IPADS), Shanghai Jiao Tong University (SJTU)
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

# Add bootloader source files
chcore_target_sources_out_objects(${kernel_target} PRIVATE init_objects
                                  init/header.S init/gdt.c)
set(init_objects ${init_objects} PARENT_SCOPE)

# Make ISO image
add_custom_target(
    chcore.iso ALL
    COMMAND [ -f chcore.iso ] && rm -f chcore.iso || true
    COMMAND [ -d iso ] && rm -rf iso || true
    COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/iso .
    COMMAND cp $<TARGET_FILE:${kernel_target}> iso/boot
    COMMAND grub-mkrescue -o chcore.iso iso
    COMMAND test -f chcore.iso
    DEPENDS ${kernel_target})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/chcore.iso
        DESTINATION ${CMAKE_INSTALL_PREFIX})

# Note: `$basedir` is a shell variable in `emulate.tpl.sh`
if (CHCORE_KERNEL_ENABLE_QEMU_VIRTIO_NET)
    chcore_generate_emulate_sh(
        "qemu-system-x86_64"
        "--enable-kvm -m 4G -cpu host -smp 4 -serial mon:stdio -nographic -cdrom \$basedir/chcore.iso -nic user,model=virtio-net-pci,hostfwd=tcp::1234-:9000,hostfwd=tcp::4096-:4096"
    )
else()
    chcore_generate_emulate_sh(
        "qemu-system-x86_64"
        "--enable-kvm -m 4G -cpu host -smp 4 -serial mon:stdio -nographic -cdrom \$basedir/chcore.iso"
    )
endif()
