#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:188. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(49666);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_cve_id("CVE-2008-7256", "CVE-2009-2287", "CVE-2009-2846", "CVE-2009-3228", "CVE-2009-3620", "CVE-2009-3722", "CVE-2009-4308", "CVE-2010-0415", "CVE-2010-0622", "CVE-2010-1088", "CVE-2010-1162", "CVE-2010-1173", "CVE-2010-1187", "CVE-2010-1643", "CVE-2010-2226", "CVE-2010-2240", "CVE-2010-2248", "CVE-2010-2492", "CVE-2010-2521", "CVE-2010-2798", "CVE-2010-2803", "CVE-2010-2959", "CVE-2010-3080", "CVE-2010-3081", "CVE-2010-3301");
  script_bugtraq_id(35529, 36004, 36304, 36824, 37221, 38144, 38165, 39044, 39120, 39480, 39794, 40377, 40920, 42124, 42217, 42237, 42242, 42249, 42505, 42577, 42585, 43062, 43239, 43355);
  script_xref(name:"MDVSA", value:"2010:188");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2010:188)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Some vulnerabilities were discovered and corrected in the Linux 2.6
kernel :

fs/namei.c in Linux kernel 2.6.18 through 2.6.34 does not always
follow NFS automount symlinks, which allows attackers to have an
unknown impact, related to LOOKUP_FOLLOW. (CVE-2010-1088)

The tc_fill_tclass function in net/sched/sch_api.c in the tc subsystem
in the Linux kernel 2.4.x before 2.4.37.6 and 2.6.x before 2.6.31-rc9
does not initialize certain (1) tcm__pad1 and (2) tcm__pad2 structure
members, which might allow local users to obtain sensitive information
from kernel memory via unspecified vectors. (CVE-2009-3228)

The do_pages_move function in mm/migrate.c in the Linux kernel before
2.6.33-rc7 does not validate node values, which allows local users to
read arbitrary kernel memory locations, cause a denial of service
(OOPS), and possibly have unspecified other impact by specifying a
node that is not part of the kernel node set. (CVE-2010-0415)

The ATI Rage 128 (aka r128) driver in the Linux kernel before
2.6.31-git11 does not properly verify Concurrent Command Engine (CCE)
state initialization, which allows local users to cause a denial of
service (NULL pointer dereference and system crash) or possibly gain
privileges via unspecified ioctl calls. (CVE-2009-3620)

The wake_futex_pi function in kernel/futex.c in the Linux kernel
before 2.6.33-rc7 does not properly handle certain unlock operations
for a Priority Inheritance (PI) futex, which allows local users to
cause a denial of service (OOPS) and possibly have unspecified other
impact via vectors involving modification of the futex value from user
space. (CVE-2010-0622)

The kvm_arch_vcpu_ioctl_set_sregs function in the KVM in Linux kernel
2.6 before 2.6.30, when running on x86 systems, does not validate the
page table root in a KVM_SET_SREGS call, which allows local users to
cause a denial of service (crash or hang) via a crafted cr3 value,
which triggers a NULL pointer dereference in the gfn_to_rmap function.
(CVE-2009-2287)

The handle_dr function in arch/x86/kvm/vmx.c in the KVM subsystem in
the Linux kernel before 2.6.31.1 does not properly verify the Current
Privilege Level (CPL) before accessing a debug register, which allows
guest OS users to cause a denial of service (trap) on the host OS via
a crafted application. (CVE-2009-3722)

The ext4_decode_error function in fs/ext4/super.c in the ext4
filesystem in the Linux kernel before 2.6.32 allows user-assisted
remote attackers to cause a denial of service (NULL pointer
dereference), and possibly have unspecified other impact, via a
crafted read-only filesystem that lacks a journal. (CVE-2009-4308)

The eisa_eeprom_read function in the parisc isa-eeprom component
(drivers/parisc/eisa_eeprom.c) in the Linux kernel before 2.6.31-rc6
allows local users to access restricted memory via a negative ppos
argument, which bypasses a check that assumes that ppos is positive
and causes an out-of-bounds read in the readb function.
(CVE-2009-2846)

Multiple buffer overflows in fs/nfsd/nfs4xdr.c in the XDR
implementation in the NFS server in the Linux kernel before 2.6.34-rc6
allow remote attackers to cause a denial of service (panic) or
possibly execute arbitrary code via a crafted NFSv4 compound WRITE
request, related to the read_buf and nfsd4_decode_compound functions.
(CVE-2010-2521)

mm/shmem.c in the Linux kernel before 2.6.28-rc8, when strict
overcommit is enabled and CONFIG_SECURITY is disabled, does not
properly handle the export of shmemfs objects by knfsd, which allows
attackers to cause a denial of service (NULL pointer dereference and
knfsd crash) or possibly have unspecified other impact via unknown
vectors. NOTE: this vulnerability exists because of an incomplete fix
for CVE-2010-1643. (CVE-2008-7256)

The release_one_tty function in drivers/char/tty_io.c in the Linux
kernel before 2.6.34-rc4 omits certain required calls to the put_pid
function, which has unspecified impact and local attack vectors.
(CVE-2010-1162)

mm/shmem.c in the Linux kernel before 2.6.28-rc3, when strict
overcommit is enabled, does not properly handle the export of shmemfs
objects by knfsd, which allows attackers to cause a denial of service
(NULL pointer dereference and knfsd crash) or possibly have
unspecified other impact via unknown vectors. (CVE-2010-1643)

The sctp_process_unk_param function in net/sctp/sm_make_chunk.c in the
Linux kernel 2.6.33.3 and earlier, when SCTP is enabled, allows remote
attackers to cause a denial of service (system crash) via an
SCTPChunkInit packet containing multiple invalid parameters that
require a large amount of error data. (CVE-2010-1173)

The Transparent Inter-Process Communication (TIPC) functionality in
Linux kernel 2.6.16-rc1 through 2.6.33, and possibly other versions,
allows local users to cause a denial of service (kernel OOPS) by
sending datagrams through AF_TIPC before entering network mode, which
triggers a NULL pointer dereference. (CVE-2010-1187)

The sctp_process_unk_param function in net/sctp/sm_make_chunk.c in the
Linux kernel 2.6.33.3 and earlier, when SCTP is enabled, allows remote
attackers to cause a denial of service (system crash) via an
SCTPChunkInit packet containing multiple invalid parameters that
require a large amount of error data. (CVE-2010-1173)

fs/cifs/cifssmb.c in the CIFS implementation in the Linux kernel
before 2.6.34-rc4 allows remote attackers to cause a denial of service
(panic) via an SMB response packet with an invalid CountHigh value, as
demonstrated by a response from an OS/2 server, related to the
CIFSSMBWrite and CIFSSMBWrite2 functions. (CVE-2010-2248)

Buffer overflow in the ecryptfs_uid_hash macro in
fs/ecryptfs/messaging.c in the eCryptfs subsystem in the Linux kernel
before 2.6.35 might allow local users to gain privileges or cause a
denial of service (system crash) via unspecified vectors.
(CVE-2010-2492)

The xfs_swapext function in fs/xfs/xfs_dfrag.c in the Linux kernel
before 2.6.35 does not properly check the file descriptors passed to
the SWAPEXT ioctl, which allows local users to leverage write access
and obtain read access by swapping one file into another file.
(CVE-2010-2226)

The gfs2_dirent_find_space function in fs/gfs2/dir.c in the Linux
kernel before 2.6.35 uses an incorrect size value in calculations
associated with sentinel directory entries, which allows local users
to cause a denial of service (NULL pointer dereference and panic) and
possibly have unspecified other impact by renaming a file in a GFS2
filesystem, related to the gfs2_rename function in
fs/gfs2/ops_inode.c. (CVE-2010-2798)

The do_anonymous_page function in mm/memory.c in the Linux kernel
before 2.6.27.52, 2.6.32.x before 2.6.32.19, 2.6.34.x before 2.6.34.4,
and 2.6.35.x before 2.6.35.2 does not properly separate the stack and
the heap, which allows context-dependent attackers to execute
arbitrary code by writing to the bottom page of a shared memory
segment, as demonstrated by a memory-exhaustion attack against the
X.Org X server. (CVE-2010-2240)

The drm_ioctl function in drivers/gpu/drm/drm_drv.c in the Direct
Rendering Manager (DRM) subsystem in the Linux kernel before
2.6.27.53, 2.6.32.x before 2.6.32.21, 2.6.34.x before 2.6.34.6, and
2.6.35.x before 2.6.35.4 allows local users to obtain potentially
sensitive information from kernel memory by requesting a large
memory-allocation amount. (CVE-2010-2803)

Integer overflow in net/can/bcm.c in the Controller Area Network (CAN)
implementation in the Linux kernel before 2.6.27.53, 2.6.32.x before
2.6.32.21, 2.6.34.x before 2.6.34.6, and 2.6.35.x before 2.6.35.4
allows attackers to execute arbitrary code or cause a denial of
service (system crash) via crafted CAN traffic. (CVE-2010-2959)

Double free vulnerability in the snd_seq_oss_open function in
sound/core/seq/oss/seq_oss_init.c in the Linux kernel before
2.6.36-rc4 might allow local users to cause a denial of service or
possibly have unspecified other impact via an unsuccessful attempt to
open the /dev/sequencer device. (CVE-2010-3080)

A vulnerability in Linux kernel caused by insecure allocation of user
space memory when translating system call inputs to 64-bit. A stack
pointer underflow can occur when using the compat_alloc_user_space
method with an arbitrary length input. (CVE-2010-3081)

The IA32 system call emulation functionality in
arch/x86/ia32/ia32entry.S in the Linux kernel before 2.6.36-rc4-git2
on the x86_64 platform does not zero extend the %eax register after
the 32-bit entry path to ptrace is used, which allows local users to
gain privileges by triggering an out-of-bounds access to the system
call table using the %rax register. NOTE: this vulnerability exists
because of a CVE-2007-4573 regression. (CVE-2010-3301)

To update your kernel, please follow the directions located at :

http://www.mandriva.com/en/security/kernelupdate"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://qa.mandriva.com/61084"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-2.6.33.7-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-2.6.33.7-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-2.6.33.7-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-2.6.33.7-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-2.6.33.7-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-2.6.33.7-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-2.6.33.7-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-2.6.33.7-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-2.6.33.7-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.33.7-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.33.7-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.33.7-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.33.7-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.33.7-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.33.7-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.33.7-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-2.6.33.7-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-devel-2.6.33.7-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-2.6.33.7-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-devel-2.6.33.7-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-2.6.33.7-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel-2.6.33.7-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6.33.7-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-2.6.33.7-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-2.6.33.7-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-2.6.33.7-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.33.7-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.33.7-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.33.7-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.33.7-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.33.7-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.33.7-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.33.7-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.33.7-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.33.7-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.33.7-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.33.7-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.33.7-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.33.7-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.33.7-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.33.7-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.33.7-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.33.7-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.33.7-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.33.7-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.33.7-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.33.7-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-2.6.33.7-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-2.6.33.7-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-2.6.33.7-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.33.7-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.33.7-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.33.7-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.33.7-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.33.7-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.33.7-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.33.7-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.33.7-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.33.7-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2010.1", reference:"broadcom-wl-kernel-2.6.33.7-desktop-2mnb-5.10.91.9.3-2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"broadcom-wl-kernel-2.6.33.7-desktop586-2mnb-5.10.91.9.3-2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"broadcom-wl-kernel-2.6.33.7-server-2mnb-5.10.91.9.3-2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"broadcom-wl-kernel-desktop-latest-5.10.91.9.3-1.20100921.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"broadcom-wl-kernel-desktop586-latest-5.10.91.9.3-1.20100921.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"broadcom-wl-kernel-server-latest-5.10.91.9.3-1.20100921.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"em8300-kernel-2.6.33.7-desktop-2mnb-0.18.0-1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"em8300-kernel-2.6.33.7-desktop586-2mnb-0.18.0-1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"em8300-kernel-2.6.33.7-server-2mnb-0.18.0-1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"em8300-kernel-desktop-latest-0.18.0-1.20100921.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"em8300-kernel-desktop586-latest-0.18.0-1.20100921.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"em8300-kernel-server-latest-0.18.0-1.20100921.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"fglrx-kernel-2.6.33.7-desktop-2mnb-8.723.1-7.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"fglrx-kernel-2.6.33.7-desktop586-2mnb-8.723.1-7.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"fglrx-kernel-2.6.33.7-server-2mnb-8.723.1-7.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"fglrx-kernel-desktop-latest-8.723.1-1.20100921.7.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"fglrx-kernel-desktop586-latest-8.723.1-1.20100921.7.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"fglrx-kernel-server-latest-8.723.1-1.20100921.7.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.33.7-desktop-2mnb-1.20-1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.33.7-desktop586-2mnb-1.20-1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.33.7-server-2mnb-1.20-1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"hcfpcimodem-kernel-desktop-latest-1.20-1.20100921.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"hcfpcimodem-kernel-desktop586-latest-1.20-1.20100921.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"hcfpcimodem-kernel-server-latest-1.20-1.20100921.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"hsfmodem-kernel-2.6.33.7-desktop-2mnb-7.80.02.05-4mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"hsfmodem-kernel-2.6.33.7-desktop586-2mnb-7.80.02.05-4mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"hsfmodem-kernel-2.6.33.7-server-2mnb-7.80.02.05-4mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"hsfmodem-kernel-desktop-latest-7.80.02.05-1.20100921.4mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"hsfmodem-kernel-desktop586-latest-7.80.02.05-1.20100921.4mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"hsfmodem-kernel-server-latest-7.80.02.05-1.20100921.4mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"kernel-2.6.33.7-2mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"kernel-desktop-2.6.33.7-2mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"kernel-desktop-devel-2.6.33.7-2mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"kernel-desktop-devel-latest-2.6.33.7-2mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"kernel-desktop-latest-2.6.33.7-2mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"kernel-desktop586-2.6.33.7-2mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"kernel-desktop586-devel-2.6.33.7-2mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"kernel-desktop586-devel-latest-2.6.33.7-2mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"kernel-desktop586-latest-2.6.33.7-2mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"kernel-doc-2.6.33.7-2mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"kernel-server-2.6.33.7-2mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"kernel-server-devel-2.6.33.7-2mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"kernel-server-devel-latest-2.6.33.7-2mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"kernel-server-latest-2.6.33.7-2mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"kernel-source-2.6.33.7-2mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"kernel-source-latest-2.6.33.7-2mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"libafs-kernel-2.6.33.7-desktop-2mnb-1.4.12-1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libafs-kernel-2.6.33.7-desktop586-2mnb-1.4.12-1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"libafs-kernel-2.6.33.7-server-2mnb-1.4.12-1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"libafs-kernel-desktop-latest-1.4.12-1.20100921.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libafs-kernel-desktop586-latest-1.4.12-1.20100921.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"libafs-kernel-server-latest-1.4.12-1.20100921.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"lirc-kernel-2.6.33.7-desktop-2mnb-0.8.7-0.20100505.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"lirc-kernel-2.6.33.7-desktop586-2mnb-0.8.7-0.20100505.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"lirc-kernel-2.6.33.7-server-2mnb-0.8.7-0.20100505.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"lirc-kernel-desktop-latest-0.8.7-1.20100921.0.20100505.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"lirc-kernel-desktop586-latest-0.8.7-1.20100921.0.20100505.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"lirc-kernel-server-latest-0.8.7-1.20100921.0.20100505.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"lzma-kernel-2.6.33.7-desktop-2mnb-4.43-29mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"lzma-kernel-2.6.33.7-desktop586-2mnb-4.43-29mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"lzma-kernel-2.6.33.7-server-2mnb-4.43-29mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"lzma-kernel-desktop-latest-4.43-1.20100921.29mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"lzma-kernel-desktop586-latest-4.43-1.20100921.29mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"lzma-kernel-server-latest-4.43-1.20100921.29mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"madwifi-kernel-2.6.33.7-desktop-2mnb-0.9.4-4.r4119mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"madwifi-kernel-2.6.33.7-desktop586-2mnb-0.9.4-4.r4119mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"madwifi-kernel-2.6.33.7-server-2mnb-0.9.4-4.r4119mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"madwifi-kernel-desktop-latest-0.9.4-1.20100921.4.r4119mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"madwifi-kernel-desktop586-latest-0.9.4-1.20100921.4.r4119mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"madwifi-kernel-server-latest-0.9.4-1.20100921.4.r4119mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nvidia-current-kernel-2.6.33.7-desktop-2mnb-195.36.24-3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"nvidia-current-kernel-2.6.33.7-desktop586-2mnb-195.36.24-3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nvidia-current-kernel-2.6.33.7-server-2mnb-195.36.24-3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nvidia-current-kernel-desktop-latest-195.36.24-1.20100921.3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"nvidia-current-kernel-desktop586-latest-195.36.24-1.20100921.3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nvidia-current-kernel-server-latest-195.36.24-1.20100921.3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nvidia173-kernel-2.6.33.7-desktop-2mnb-173.14.25-3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"nvidia173-kernel-2.6.33.7-desktop586-2mnb-173.14.25-3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nvidia173-kernel-2.6.33.7-server-2mnb-173.14.25-3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nvidia173-kernel-desktop-latest-173.14.25-1.20100921.3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"nvidia173-kernel-desktop586-latest-173.14.25-1.20100921.3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nvidia173-kernel-server-latest-173.14.25-1.20100921.3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nvidia96xx-kernel-2.6.33.7-desktop-2mnb-96.43.16-2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"nvidia96xx-kernel-2.6.33.7-desktop586-2mnb-96.43.16-2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nvidia96xx-kernel-2.6.33.7-server-2mnb-96.43.16-2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nvidia96xx-kernel-desktop-latest-96.43.16-1.20100921.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"nvidia96xx-kernel-desktop586-latest-96.43.16-1.20100921.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nvidia96xx-kernel-server-latest-96.43.16-1.20100921.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"slmodem-kernel-2.6.33.7-desktop-2mnb-2.9.11-0.20080817.7mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"slmodem-kernel-2.6.33.7-desktop586-2mnb-2.9.11-0.20080817.7mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"slmodem-kernel-2.6.33.7-server-2mnb-2.9.11-0.20080817.7mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"slmodem-kernel-desktop-latest-2.9.11-1.20100921.0.20080817.7mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"slmodem-kernel-desktop586-latest-2.9.11-1.20100921.0.20080817.7mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"slmodem-kernel-server-latest-2.9.11-1.20100921.0.20080817.7mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"squashfs-lzma-kernel-2.6.33.7-desktop-2mnb-3.3-12mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"squashfs-lzma-kernel-2.6.33.7-desktop586-2mnb-3.3-12mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"squashfs-lzma-kernel-2.6.33.7-server-2mnb-3.3-12mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"squashfs-lzma-kernel-desktop-latest-3.3-1.20100921.12mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"squashfs-lzma-kernel-desktop586-latest-3.3-1.20100921.12mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"squashfs-lzma-kernel-server-latest-3.3-1.20100921.12mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"vboxadditions-kernel-2.6.33.7-desktop-2mnb-3.1.8-3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"vboxadditions-kernel-2.6.33.7-desktop586-2mnb-3.1.8-3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"vboxadditions-kernel-2.6.33.7-server-2mnb-3.1.8-3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"vboxadditions-kernel-desktop-latest-3.1.8-1.20100921.3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"vboxadditions-kernel-desktop586-latest-3.1.8-1.20100921.3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"vboxadditions-kernel-server-latest-3.1.8-1.20100921.3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"virtualbox-kernel-2.6.33.7-desktop-2mnb-3.1.8-3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"virtualbox-kernel-2.6.33.7-desktop586-2mnb-3.1.8-3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"virtualbox-kernel-2.6.33.7-server-2mnb-3.1.8-3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"virtualbox-kernel-desktop-latest-3.1.8-1.20100921.3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"virtualbox-kernel-desktop586-latest-3.1.8-1.20100921.3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"virtualbox-kernel-server-latest-3.1.8-1.20100921.3mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"vpnclient-kernel-2.6.33.7-desktop-2mnb-4.8.02.0030-2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"vpnclient-kernel-2.6.33.7-desktop586-2mnb-4.8.02.0030-2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"vpnclient-kernel-2.6.33.7-server-2mnb-4.8.02.0030-2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"vpnclient-kernel-desktop-latest-4.8.02.0030-1.20100921.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"vpnclient-kernel-desktop586-latest-4.8.02.0030-1.20100921.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"vpnclient-kernel-server-latest-4.8.02.0030-1.20100921.2mdv2010.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
