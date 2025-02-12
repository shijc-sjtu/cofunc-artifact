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

#Build/OvmfX64/DEBUG_GCC5/FV/OVMF.fd

# Make AMD-SEV OVMF
# add_custom_target(
#    ovmf ALL
#    COMMAND [ -f Build/OvmfX64/DEBUG_GCC5/FV/OVMF.fd ]
#    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ovmf)

# Make AMD-SEV QEMU
# add_custom_target(
#     qemu ALL
#     COMMAND [ -f build/qemu-system-x86_64 ]
#     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/qemu)

# Make ISO image
add_custom_target(
    chcore.iso ALL
    COMMAND [ -f chcore.iso ] && rm -f chcore.iso || true
    COMMAND dd if=/dev/zero of=chcore.iso bs=512 count=307200
    COMMAND mkfs -t vfat chcore.iso
    COMMAND mount chcore.iso /mnt
    COMMAND grub-install --target x86_64-efi --efi-directory /mnt --boot-directory=/mnt/boot --removable
    COMMAND cp $<TARGET_FILE:${kernel_target}> /mnt/boot
    COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/iso/boot/grub/grub.cfg /mnt/boot/grub
    COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/iso .
    COMMAND cp $<TARGET_FILE:${kernel_target}> iso/boot
    COMMAND umount /mnt
    DEPENDS ${kernel_target})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/chcore.iso
        DESTINATION ${CMAKE_INSTALL_PREFIX})

if (CHCORE_KERNEL_ENABLE_QEMU_VIRTIO_NET)
    message(FATAL_ERROR "virtio-net has not been supported on AMD-SEV")
endif()

# Note: `$basedir` is a shell variable in `emulate.tpl.sh`
# Linux v5.19
# chcore_generate_emulate_sh(
#    "${CMAKE_CURRENT_SOURCE_DIR}/qemu/build/qemu-system-x86_64"
#    "--enable-kvm -m 4G -cpu EPYC-v4 -smp 4 -no-reboot -machine q35,memory-encryption=sev0,vmport=off \
#        -serial mon:stdio -nographic -cdrom \$basedir/chcore.iso \
#        -drive if=pflash,format=raw,unit=0,file=${CMAKE_CURRENT_SOURCE_DIR}/ovmf/Build/OvmfX64/DEBUG_GCC5/FV/OVMF.fd,readonly=on \
#        -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1"
#)
# Linux v6.1
chcore_generate_emulate_sh(
    "$(pwd)/../qemu/build/qemu-system-x86_64"
    "--enable-kvm -m 4G -cpu EPYC-v4,host-phys-bits=true,tsc-freq=1000000000 -smp 96 -no-reboot -machine type=q35,confidential-guest-support=sev0,memory-backend=ram1,kvm-type=protected,vmport=off \
        -serial mon:stdio -nographic -cdrom \$basedir/chcore.iso \
        -drive if=pflash,format=raw,unit=0,file=${CMAKE_CURRENT_SOURCE_DIR}/ovmf/Build/OvmfX64/DEBUG_GCC5/FV/OVMF.fd,readonly=on \
        -object memory-backend-memfd-private,id=ram1,size=4G,share=true -object sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1,init-flags=0x0,host-data=b2l3bmNvd3FuY21wbXA"
)