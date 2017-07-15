---
layout:     post
title:      "How to debug qemu devices"
subtitle:   "Discovering vulnerabilities of qemu"
date:       2017-07-15 19:30:00 -0800
author:     "Dafeng"
header-img: "img/post-bg-universe.jpg"
header-mask: 0.3
catalog: true
tags:
    - Qemu
    - Virtualization
---

## 简述
qemu是一个开源的模拟处理器硬件设备的全虚拟化仿真器和虚拟器.

KVM(kernel virtual machine)是一个Linux内核模块,为用户层提供硬件虚拟化的特性,QEMU通过kvm模拟一个目标架构的时候,可以实现与主机相同的架构,从而极大提高模拟效率。

### 漏洞挖掘

要想实现从虚拟机里(以后统称guest主机)影响qemu,继而影响用户的主机(以后统称Host主机),就需要找到Guest主机与qemu通信的方法,再通过分析qemu对虚拟机传递数据的处理流程来发掘可利用点,比如虚拟机内传递一个异常值,导致qemu堆溢出,然后利用虚拟机传递布置的内容构造exploit,就可以实现控制qemu完成任意代码执行了。

## 测试环境搭建
首先我们下载最新版的qemu：[下载地址](http://www.qemu.org/)

如果使用物理机上的linux作为host最好，但是如果主机是windows，我们也可以采用windows上安装ubuntu虚拟机，然后ubuntu虚拟机中运行qemu来启动vm。
在window上vmware 12上安装ubuntu最新版本(之所以选用最新版本)，然后在ubuntu上编译安装qemu源码，以便后续调试qemu。

### **编译qemu:**

 ./configure --prefix=/usr --target-list=x86_64-softmmu --enable-kvm --enable-debug --enable-debug-info --enable-modules --enable-vnc --enable-trace-backends=log --disable-werror --disable-strip

> * --target-list=x86_64-softmmu 只编译qemu x86_64版本
* --enable-kvm 开启qemu内核支持
* --enable-debug --enable-debug-info 保留qemu调试信息
* --disable-strip 保留qemu程序符号表,以便程序后续gdb调试与IDA逆向分析

>  configure过程可能出现缺少依赖的情况，比如zlib, glib-2.22,gthread-2.0等，可以通过以下命令安装所需的依赖
 sudo apt-get install zlib1g-dev libglib2.0-dev libpixman-1-dev libfdt-dev (安装依赖后重新configure)


make -j 16(多线程编译，节省时间)

sudo make install


### **制作镜像：**
1. qemu-img create -f qcow2 ubuntu64.img 15G 制作空的磁盘文件
2. 在官网下载ubuntu_xxx.iso镜像
3. 将iso镜像安装到img磁盘文件中，脚本： **qemu-system-x86_64 -enable-kvm -smp 4 -m 2048 -hda ./ubuntu64.img -boot d -cdrom ./ubuntu-16.04.2-desktop-amd64.iso**

> * -enable-kvm 开启内核支持，加快qemu运行效率
* -cdrom ./ubuntu-16.04.2-desktop-amd64.iso iso挂载到光驱
* -hda ./ubuntu64.img  指定磁盘文件
* -boot d 从光驱启动

如果没有配置kvm，会找不到kvm驱动，主机与vmware配置如下：
1. 确定CPU支持虚拟化后，要在BIOS中开启虚拟化，我的CPU是Intel的，BIOS是这样的：选Security, 再进Virtualization项，把各项设置成ENABLE，保存退出 。

2. 打开vmware的虚拟化引擎，如图：
![vmare配置选项](/img/qemu_debug/vmware.png)

3. 然后可以看到qemu启动，ubuntu启动界面，安装正常安装ubuntu系统安装即可。(PS: 电脑性能不够，在虚拟机里面运行虚拟机比较慢)



## 运行vm(确定目标设备)
安装成功后，接下来启动vm，当然启动vm时，就有很多种的选择，特别是在设备的选择上，在host上输入 qemu-system-x86_64 -device ?

    $ qemu-system-x86_64 -device ?
    Controller/Bridge/Hub devices:
    name "i82801b11-bridge", bus PCI
    name "ioh3420", bus PCI, desc "Intel IOH device id 3420 PCIE Root Port"
    name "isabus-bridge", bus System
    name "pci-bridge", bus PCI, desc "Standard PCI Bridge"
    name "pci-bridge-seat", bus PCI, desc "Standard PCI Bridge (multiseat)"
    name "pcie-root-port", bus PCI, desc "PCI Express Root Port"
    name "pxb", bus PCI, desc "PCI Expander Bridge"
    name "pxb-pcie", bus PCI, desc "PCI Express Expander Bridge"
    name "usb-hub", bus usb-bus
    name "vfio-pci-igd-lpc-bridge", bus PCI, desc "VFIO dummy ISA/LPC bridge for IGD assignment"
    name "x3130-upstream", bus PCI, desc "TI X3130 Upstream Port of PCI Express Switch"
    name "xio3130-downstream", bus PCI, desc "TI X3130 Downstream Port of PCI Express Switch"

    USB devices:
    name "ich9-usb-ehci1", bus PCI
    name "ich9-usb-ehci2", bus PCI
    name "ich9-usb-uhci1", bus PCI
    name "ich9-usb-uhci2", bus PCI
    name "ich9-usb-uhci3", bus PCI
    name "ich9-usb-uhci4", bus PCI
    name "ich9-usb-uhci5", bus PCI
    name "ich9-usb-uhci6", bus PCI
    name "nec-usb-xhci", bus PCI
    name "pci-ohci", bus PCI, desc "Apple USB Controller"
    name "piix3-usb-uhci", bus PCI
    name "piix4-usb-uhci", bus PCI
    name "qemu-xhci", bus PCI
    name "sysbus-ohci", bus System, desc "OHCI USB Controller"
    name "usb-ehci", bus PCI
    name "vt82c686b-usb-uhci", bus PCI

    Storage devices:
    name "allwinner-ahci", bus System
    name "am53c974", bus PCI, desc "AMD Am53c974 PCscsi-PCI SCSI adapter"
    name "cfi.pflash01", bus System
    name "dc390", bus PCI, desc "Tekram DC-390 SCSI adapter"
    name "esp", bus System
    name "floppy", bus floppy-bus, desc "virtual floppy drive"
    name "ich9-ahci", bus PCI, alias "ahci"
    name "ide-cd", bus IDE, desc "virtual IDE CD-ROM"
    name "ide-drive", bus IDE, desc "virtual IDE disk or CD-ROM (legacy)"
    name "ide-hd", bus IDE, desc "virtual IDE disk"
    name "isa-fdc", bus ISA
    name "isa-ide", bus ISA
    name "lsi53c810", bus PCI
    name "lsi53c895a", bus PCI, alias "lsi"
    name "megasas", bus PCI, desc "LSI MegaRAID SAS 1078"
    name "megasas-gen2", bus PCI, desc "LSI MegaRAID SAS 2108"
    name "nvme", bus PCI, desc "Non-Volatile Memory Express"
    name "piix3-ide", bus PCI
    name "piix3-ide-xen", bus PCI
    name "piix4-ide", bus PCI
    name "pvscsi", bus PCI
    name "scsi-block", bus SCSI, desc "SCSI block device passthrough"
    name "scsi-cd", bus SCSI, desc "virtual SCSI CD-ROM"
    name "scsi-disk", bus SCSI, desc "virtual SCSI disk or CD-ROM (legacy)"
    name "scsi-generic", bus SCSI, desc "pass through generic scsi device (/dev/sg*)"
    name "scsi-hd", bus SCSI, desc "virtual SCSI disk"
    name "sdhci-pci", bus PCI
    name "SUNW,fdtwo", bus System
    name "sysbus-ahci", bus System
    name "sysbus-fdc", bus System
    name "usb-bot", bus usb-bus
    name "usb-mtp", bus usb-bus, desc "USB Media Transfer Protocol device"
    name "usb-storage", bus usb-bus
    name "usb-uas", bus usb-bus
    name "vhost-scsi", bus virtio-bus
    name "vhost-scsi-pci", bus PCI
    name "virtio-blk-device", bus virtio-bus
    name "virtio-blk-pci", bus PCI, alias "virtio-blk"
    name "virtio-scsi-device", bus virtio-bus
    name "virtio-scsi-pci", bus PCI, alias "virtio-scsi"

    Network devices:
    name "e1000", bus PCI, alias "e1000-82540em", desc "Intel Gigabit Ethernet"
    name "e1000-82544gc", bus PCI, desc "Intel Gigabit Ethernet"
    name "e1000-82545em", bus PCI, desc "Intel Gigabit Ethernet"
    name "e1000e", bus PCI, desc "Intel 82574L GbE Controller"
    name "i82550", bus PCI, desc "Intel i82550 Ethernet"
    name "i82551", bus PCI, desc "Intel i82551 Ethernet"
    name "i82557a", bus PCI, desc "Intel i82557A Ethernet"
    name "i82557b", bus PCI, desc "Intel i82557B Ethernet"
    name "i82557c", bus PCI, desc "Intel i82557C Ethernet"
    name "i82558a", bus PCI, desc "Intel i82558A Ethernet"
    name "i82558b", bus PCI, desc "Intel i82558B Ethernet"
    name "i82559a", bus PCI, desc "Intel i82559A Ethernet"
    name "i82559b", bus PCI, desc "Intel i82559B Ethernet"
    name "i82559c", bus PCI, desc "Intel i82559C Ethernet"
    name "i82559er", bus PCI, desc "Intel i82559ER Ethernet"
    name "i82562", bus PCI, desc "Intel i82562 Ethernet"
    name "i82801", bus PCI, desc "Intel i82801 Ethernet"
    name "ne2k_isa", bus ISA
    name "ne2k_pci", bus PCI
    name "pcnet", bus PCI
    name "rocker", bus PCI, desc "Rocker Switch"
    name "rtl8139", bus PCI
    name "usb-bt-dongle", bus usb-bus
    name "usb-net", bus usb-bus
    name "virtio-net-device", bus virtio-bus
    name "virtio-net-pci", bus PCI, alias "virtio-net"
    name "vmxnet3", bus PCI, desc "VMWare Paravirtualized Ethernet v3"

    Input devices:
    name "ipoctal232", bus IndustryPack, desc "GE IP-Octal 232 8-channel RS-232 IndustryPack"
    name "isa-parallel", bus ISA
    name "isa-serial", bus ISA
    name "pci-serial", bus PCI
    name "pci-serial-2x", bus PCI
    name "pci-serial-4x", bus PCI
    name "tpci200", bus PCI, desc "TEWS TPCI200 IndustryPack carrier"
    name "usb-braille", bus usb-bus
    name "usb-ccid", bus usb-bus, desc "CCID Rev 1.1 smartcard reader"
    name "usb-kbd", bus usb-bus
    name "usb-mouse", bus usb-bus
    name "usb-serial", bus usb-bus
    name "usb-tablet", bus usb-bus
    name "usb-wacom-tablet", bus usb-bus, desc "QEMU PenPartner Tablet"
    name "virtconsole", bus virtio-serial-bus
    name "virtio-input-host-device", bus virtio-bus
    name "virtio-input-host-pci", bus PCI, alias "virtio-input-host"
    name "virtio-keyboard-device", bus virtio-bus
    name "virtio-keyboard-pci", bus PCI, alias "virtio-keyboard"
    name "virtio-mouse-device", bus virtio-bus
    name "virtio-mouse-pci", bus PCI, alias "virtio-mouse"
    name "virtio-serial-device", bus virtio-bus
    name "virtio-serial-pci", bus PCI, alias "virtio-serial"
    name "virtio-tablet-device", bus virtio-bus
    name "virtio-tablet-pci", bus PCI, alias "virtio-tablet"
    name "virtserialport", bus virtio-serial-bus

    Display devices:
    name "cirrus-vga", bus PCI, desc "Cirrus CLGD 54xx VGA"
    name "isa-cirrus-vga", bus ISA
    name "isa-vga", bus ISA
    name "secondary-vga", bus PCI
    name "sga", bus ISA, desc "Serial Graphics Adapter"
    name "VGA", bus PCI
    name "virtio-gpu-pci", bus PCI, alias "virtio-gpu"
    name "virtio-vga", bus PCI
    name "vmware-svga", bus PCI

    Sound devices:
    name "AC97", bus PCI, desc "Intel 82801AA AC97 Audio"
    name "adlib", bus ISA, desc "Yamaha YM3812 (OPL2)"
    name "cs4231a", bus ISA, desc "Crystal Semiconductor CS4231A"
    name "ES1370", bus PCI, desc "ENSONIQ AudioPCI ES1370"
    name "gus", bus ISA, desc "Gravis Ultrasound GF1"
    name "hda-duplex", bus HDA, desc "HDA Audio Codec, duplex (line-out, line-in)"
    name "hda-micro", bus HDA, desc "HDA Audio Codec, duplex (speaker, microphone)"
    name "hda-output", bus HDA, desc "HDA Audio Codec, output-only (line-out)"
    name "ich9-intel-hda", bus PCI, desc "Intel HD Audio Controller (ich9)"
    name "intel-hda", bus PCI, desc "Intel HD Audio Controller (ich6)"
    name "sb16", bus ISA, desc "Creative Sound Blaster 16"
    name "usb-audio", bus usb-bus

    Misc devices:
    name "hyperv-testdev", bus ISA
    name "i6300esb", bus PCI
    name "ib700", bus ISA
    name "isa-applesmc", bus ISA
    name "isa-debug-exit", bus ISA
    name "isa-debugcon", bus ISA
    name "ivshmem", bus PCI, desc "Inter-VM shared memory (legacy)"
    name "ivshmem-doorbell", bus PCI, desc "Inter-VM shared memory"
    name "ivshmem-plain", bus PCI, desc "Inter-VM shared memory"
    name "kvm-pci-assign", bus PCI, alias "pci-assign", desc "KVM-based PCI passthrough"
    name "pc-testdev", bus ISA
    name "pci-testdev", bus PCI, desc "PCI Test Device"
    name "pvpanic", bus ISA
    name "vfio-pci", bus PCI, desc "VFIO-based PCI device assignment"
    name "vhost-vsock-device", bus virtio-bus
    name "vhost-vsock-pci", bus PCI
    name "virtio-balloon-device", bus virtio-bus
    name "virtio-balloon-pci", bus PCI, alias "virtio-balloon"
    name "virtio-crypto-device", bus virtio-bus
    name "virtio-crypto-pci", bus PCI
    name "virtio-mmio", bus System
    name "virtio-rng-device", bus virtio-bus
    name "virtio-rng-pci", bus PCI, alias "virtio-rng"

    CPU devices:
    name "486-x86_64-cpu"
    name "athlon-x86_64-cpu"
    name "base-x86_64-cpu"
    name "Broadwell-noTSX-x86_64-cpu"
    name "Broadwell-x86_64-cpu"
    name "Conroe-x86_64-cpu"
    name "core2duo-x86_64-cpu"
    name "coreduo-x86_64-cpu"
    name "Haswell-noTSX-x86_64-cpu"
    name "Haswell-x86_64-cpu"
    name "host-x86_64-cpu"
    name "IvyBridge-x86_64-cpu"
    name "kvm32-x86_64-cpu"
    name "kvm64-x86_64-cpu"
    name "max-x86_64-cpu"
    name "n270-x86_64-cpu"
    name "Nehalem-x86_64-cpu"
    name "Opteron_G1-x86_64-cpu"
    name "Opteron_G2-x86_64-cpu"
    name "Opteron_G3-x86_64-cpu"
    name "Opteron_G4-x86_64-cpu"
    name "Opteron_G5-x86_64-cpu"
    name "Penryn-x86_64-cpu"
    name "pentium-x86_64-cpu"
    name "pentium2-x86_64-cpu"
    name "pentium3-x86_64-cpu"
    name "phenom-x86_64-cpu"
    name "qemu32-x86_64-cpu"
    name "qemu64-x86_64-cpu"
    name "SandyBridge-x86_64-cpu"
    name "Skylake-Client-x86_64-cpu"
    name "Westmere-x86_64-cpu"

    Uncategorized devices:
    name "amd-iommu", bus System
    name "AMDVI-PCI", bus PCI
    name "edu", bus PCI
    name "fw_cfg_io", bus System
    name "fw_cfg_mem", bus System
    name "generic-sdhci", bus System
    name "hpet", bus System
    name "i8042", bus ISA
    name "igd-passthrough-isa-bridge", bus PCI, desc "ISA bridge faked to support IGD PT"
    name "intel-iommu", bus System
    name "ioapic", bus System
    name "ipmi-bmc-extern"
    name "ipmi-bmc-sim"
    name "isa-ipmi-bt", bus ISA
    name "isa-ipmi-kcs", bus ISA
    name "kvm-ioapic", bus System
    name "kvmclock", bus System
    name "kvmvapic", bus System
    name "loader", desc "Generic Loader"
    name "mptsas1068", bus PCI, desc "LSI SAS 1068"
    name "nvdimm", desc "DIMM memory module"
    name "pc-dimm", desc "DIMM memory module"
    name "sd-card", bus sd-bus
    name "tpm-tis", bus ISA
    name "unimplemented-device", bus System
    name "virtio-gpu-device", bus virtio-bus
    name "vmgenid"


若想了解设备的使用信息可以这样:

$ qemu-system-x86_64 -device mptsas1068,help

    $ qemu-system-x86_64 -device mptsas1068,help
    mptsas1068.rombar=uint32
    mptsas1068.x-pcie-lnksta-dllla=bool (on/off)
    mptsas1068.multifunction=bool (on/off)
    mptsas1068.msi=OnOffAuto (on/off/auto)
    mptsas1068.romfile=str
    mptsas1068.command_serr_enable=bool (on/off)
    mptsas1068.x-pcie-extcap-init=bool (on/off)
    mptsas1068.addr=int32 (Slot and optional function number, example: 06.0 or 06)
    mptsas1068.sas_address=uint64

通过以上命令，可以找到当前版本的qemu支持的所有设备类型和设备名称，以及各个设备的详细参数列表。

选取想要测试的设备，在qemu启动vm时，指定设备名称。如我们想要测试vga显卡与ne2k_pci网卡，使用如下命令启动vm:

$ qemu-system-x86_64 -enable-kvm -smp 1 -m 1024 -hda ./ubuntu64.img -boot c -vnc 0.0.0.0:8 -device VGA -device ne2k_pci &

> * -enable-kvm 开启内核支持，加快qemu运行效率
* -vnc 0.0.0.0:8 指定vm vnc端口为hostip:5908
* -device VGA -device ne2k_pci  指定待测试的显卡与网卡
* & 程序后台启动，不启动qemu界面


## 确定设备对应的IO端口/IO内存

在运行vm时，我们指定视频设备vga与网卡设备vmxnet3,那我们在运行的vm中来查看设备IO端口地址或者IO内存地址，然后我们可以通过读写设备PIO或者设备内存地址。然后我们通过gdb脚本来找到对应PIO端口/内存端口读写触发的处理函数。
1. 执行lspci -nnv，查看vm pci设备。
![](/img/qemu_debug/devices.png)
这个设备对应的IO端口是 0xc000,大小为256(意味着最大可以inl(0xc000+255)).

2. 针对ne2k设备,从 lspci -nnv命令,我们知道其对应的bus信息是 00:04.0 ,我们也可以通过下列方式获取对应的IO内存和端口的信息.

* $cat /proc/iomem | grep 00:04.0
* $cat /proc/ioports |grep 00:04.0

#### 查看设备IO处理函数
在host上执行ps -aux | grep qemu, 查看qemu进程PID(如：6666)，gdb -p 6666，为了方便操作编写gdb脚本：

**gdbinit.txt**
```c
set confirm off
set pagination off
set disassembly-flavor intel
handle SIGALRM nostop nopass noprint
disp /i $pc

define p
si
end

define o
ni
end

define l
x/16i $arg0
end

define ln
x/16i
end

define d
x/16xg $arg0
end

define dn
x/16xg
end

define ds
x/s $arg0
end

define dr
print/x $$arg0
end

define pv
print/x {int}$arg0
end

define pc
x/i $pc
end
```

在断点处执行gdb脚本获取qemu程序中各IO地址与内存中对应的注册函数：(gdb脚本涉及太多的程序数据结构分析，在此不展开)

**Qemu启动后所有的pio设备信息：**

```c
set pagination off
set $dispatch = address_space_io.dispatch
set $sections = $dispatch->map->sections
printf "sections=0x%lx\n", $sections

set $count = address_space_io.dispatch->map.sections_nb
printf "total %lu entries.\n", $count
while ($count > 0)
    set $size = *(short*)(&$sections->size)
    set $addr = $sections->offset_within_address_space
    printf "port=0x%04lx, size=0x%04lx, next=0x%04lx, ", $addr, $size, $addr + $size

    set $mr = $sections->mr
    set $ops = $mr->ops
    set $pf_read = $ops
    printf "0x%016lx, ", $pf_read
    x/8xb $ops

    set $count = $count - 1
    set $sections = $sections + 1
end

printf "total %lu entries.\n", $count
```
设备PIO信息截图：

![pio](/img/qemu_debug/pio.png)


**Qemu启动后所有的mmio设备信息：**
```c
set pagination off
set $dispatch = address_space_memory.dispatch
set $sections = $dispatch->map->sections
printf "sections=0x%lx\n", $sections

set $count = address_space_memory.dispatch->map.sections_nb
printf "total %lu entries.\n", $count
while ($count > 0)
set $size = *(long*)(&$sections->size)
set $addr = $sections->offset_within_address_space
printf "addr=0x%08lx, size=0x%08lx, next=0x%08lx, ", $addr, $size, $addr + $size

set $mr = $sections->mr
set $ops = $mr->ops
set $pf_read = $ops
printf "0x%016lx, ", $pf_read
x/8xb $ops

set $count = $count - 1
set $sections = $sections + 1
end

printf "total %lu entries.\n", $count
```
设备PIO信息截图：

![mmio](/img/qemu_debug/mmio.png)

打开source insight, 路径/hw/net/Ne2000.c,从pio信息图中得到ne2k_pci设备PIO端口的处理函数是ne2000_ops：
![source](/img/qemu_debug/source.png)

在 .read = ne2000_read, .write = ne2000_write,函数处打断点，然后编写程序读写PIO端口或者MMIO内存，就可以在断点处断下来，结合gdb调试以及IDA堆qemu可执行程序综合分析，就可以深入的堆qemu设备进行分析了。结合攻击模式库以及对漏洞的敏感度，进行漏洞挖掘工作。

### 交互代码

MMIO读写驱动程序：
```c
#include <sys/io.h>
void main(){
  iopl(3);
  inb(0xc050);
}

//针对IO内存
#include <asm/io.h>
#include <linux/module.h>
#include <linux/ioport.h>
#include <linux/random.h>
 
long pmem; //注意这里不要使用指针类型,不然后面地址加偏移的时候很容易出错
void m_init(){
	printk("m_init\n");
	int i,cmd,cmd_size;
	int va,offset;
	pmem=ioremap(0xfebf0000,0x8000);//映射io内存
	offset=0x10;//根据设备情况而定
	if (pmem){
	     writel(value,pmem+offset);//通常情况下都是写4字节,你也可以根据源码的处理方式选择
	}else printk("ioremap fail\n");
	iounmap(pmem);
	return;
}
void m_exit(){
	printk("m_exit\n");
	return;
}
module_init(m_init);
module_exit(m_exit);

```


## 审计源码
已经找到处理输入的文件了,怎么找到哪一个函数是第一个处理我们输入的函数呢??通用的方法:找包含 read,write 关键字的函数名.通过不断找函数的caller,我们最终会找到第一个处理的函数,而有的设备有多个映射IO内存和端口,就意味着有多个处理函数分别对应不同的内存和端口.自此能说的也不多了,你都已经知道怎么控制数据了,剩下就是去查看qemu怎么处理数据了.qemu在获取数据的时候也会通过调用Guest系统的内存来读取数据,处理guest地址转换的函数叫 dma_memory_read,dma_memory_write。



## 总结
qemu是个非常强大的软件，也是虚拟化、云计算的基础；在硬件模拟方面，模拟各平台设备；用于源码插桩，linux内核调试等。
以上总结要感谢实验室大牛莫老师指导，非常感谢！！！

## 参考
* [QEMU漏洞挖掘](http://www.tuicool.com/articles/MzqYbia)
