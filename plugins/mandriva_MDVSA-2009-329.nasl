#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:329. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(48161);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id("CVE-2009-1298", "CVE-2009-2903", "CVE-2009-3547", "CVE-2009-3612", "CVE-2009-3621", "CVE-2009-3638", "CVE-2009-3726", "CVE-2009-4131");
  script_bugtraq_id(36379, 36723, 36803, 36827, 36901, 36936);
  script_xref(name:"MDVSA", value:"2009:329");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2009:329)");
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

Memory leak in the appletalk subsystem in the Linux kernel 2.4.x
through 2.4.37.6 and 2.6.x through 2.6.31, when the appletalk and
ipddp modules are loaded but the ipddpN device is not found, allows
remote attackers to cause a denial of service (memory consumption) via
IP-DDP datagrams. (CVE-2009-2903)

Multiple race conditions in fs/pipe.c in the Linux kernel before
2.6.32-rc6 allow local users to cause a denial of service (NULL
pointer dereference and system crash) or gain privileges by attempting
to open an anonymous pipe via a /proc/*/fd/ pathname. (CVE-2009-3547)

The tcf_fill_node function in net/sched/cls_api.c in the netlink
subsystem in the Linux kernel 2.6.x before 2.6.32-rc5, and 2.4.37.6
and earlier, does not initialize a certain tcm__pad2 structure member,
which might allow local users to obtain sensitive information from
kernel memory via unspecified vectors. NOTE: this issue exists because
of an incomplete fix for CVE-2005-4881. (CVE-2009-3612)

net/unix/af_unix.c in the Linux kernel 2.6.31.4 and earlier allows
local users to cause a denial of service (system hang) by creating an
abstract-namespace AF_UNIX listening socket, performing a shutdown
operation on this socket, and then performing a series of connect
operations to this socket. (CVE-2009-3621)

Integer overflow in the kvm_dev_ioctl_get_supported_cpuid function in
arch/x86/kvm/x86.c in the KVM subsystem in the Linux kernel before
2.6.31.4 allows local users to have an unspecified impact via a
KVM_GET_SUPPORTED_CPUID request to the kvm_arch_dev_ioctl function.
(CVE-2009-3638)

The nfs4_proc_lock function in fs/nfs/nfs4proc.c in the NFSv4 client
in the Linux kernel before 2.6.31-rc4 allows remote NFS servers to
cause a denial of service (NULL pointer dereference and panic) by
sending a certain response containing incorrect file attributes, which
trigger attempted use of an open file that lacks NFSv4 state.
(CVE-2009-3726)

The ip_frag_reasm function in ipv4/ip_fragment.c in Linux kernel
2.6.32-rc8, and possibly earlier versions, calls IP_INC_STATS_BH with
an incorrect argument, which allows remote attackers to cause a denial
of service (NULL pointer dereference and hang) via long IP packets,
possibly related to the ip_defrag function. (CVE-2009-1298)

To update your kernel, please follow the directions located at :

http://www.mandriva.com/en/security/kernelupdate"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 189, 200, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-2.6.31.6-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-2.6.31.6-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-2.6.31.6-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-2.6.31.6-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-2.6.31.6-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-2.6.31.6-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-2.6.31.6-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-2.6.31.6-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-2.6.31.6-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.31.6-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.31.6-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.31.6-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.31.6-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.31.6-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.31.6-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.29.6-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.31.6-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-2.6.29.6-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-2.6.31.6-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-devel-2.6.29.6-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-devel-2.6.31.6-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-2.6.29.6-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-2.6.31.6-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-devel-2.6.29.6-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-devel-2.6.31.6-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-2.6.29.6-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-2.6.31.6-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel-2.6.29.6-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel-2.6.31.6-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6.29.6-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6.31.6-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-2.6.31.6-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-2.6.31.6-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-2.6.31.6-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.31.6-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.31.6-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.31.6-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.31.6-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.31.6-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.31.6-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.31.6-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.31.6-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.31.6-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.31.6-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.31.6-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.31.6-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.31.6-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.31.6-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.31.6-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.31.6-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.31.6-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.31.6-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.31.6-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.31.6-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.31.6-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-2.6.31.6-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-2.6.31.6-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-2.6.31.6-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.31.6-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.31.6-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.31.6-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.31.6-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.31.6-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.31.6-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.31.6-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.31.6-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.31.6-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");
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
if (rpm_check(release:"MDK2009.1", reference:"broadcom-wl-kernel-2.6.29.6-desktop-3mnb-5.10.79.10-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"broadcom-wl-kernel-2.6.29.6-desktop586-3mnb-5.10.79.10-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"broadcom-wl-kernel-2.6.29.6-server-3mnb-5.10.79.10-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"broadcom-wl-kernel-desktop-latest-5.10.79.10-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"broadcom-wl-kernel-desktop586-latest-5.10.79.10-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"broadcom-wl-kernel-server-latest-5.10.79.10-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"em8300-kernel-2.6.29.6-desktop-3mnb-0.17.2-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"em8300-kernel-2.6.29.6-desktop586-3mnb-0.17.2-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"em8300-kernel-2.6.29.6-server-3mnb-0.17.2-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"em8300-kernel-desktop-latest-0.17.2-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"em8300-kernel-desktop586-latest-0.17.2-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"em8300-kernel-server-latest-0.17.2-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"fcpci-kernel-2.6.29.6-desktop-3mnb-3.11.07-7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"fcpci-kernel-2.6.29.6-desktop586-3mnb-3.11.07-7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"fcpci-kernel-2.6.29.6-server-3mnb-3.11.07-7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"fcpci-kernel-desktop-latest-3.11.07-1.20091209.7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"fcpci-kernel-desktop586-latest-3.11.07-1.20091209.7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"fcpci-kernel-server-latest-3.11.07-1.20091209.7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.29.6-desktop-3mnb-1.18-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.29.6-desktop586-3mnb-1.18-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.29.6-server-3mnb-1.18-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hcfpcimodem-kernel-desktop-latest-1.18-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hcfpcimodem-kernel-desktop586-latest-1.18-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hcfpcimodem-kernel-server-latest-1.18-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"hsfmodem-kernel-2.6.29.6-desktop-3mnb-7.80.02.03-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hsfmodem-kernel-2.6.29.6-desktop586-3mnb-7.80.02.03-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"hsfmodem-kernel-2.6.29.6-server-3mnb-7.80.02.03-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"hsfmodem-kernel-desktop-latest-7.80.02.03-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hsfmodem-kernel-desktop586-latest-7.80.02.03-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"hsfmodem-kernel-server-latest-7.80.02.03-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-2.6.29.6-3mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-desktop-2.6.29.6-3mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-desktop-devel-2.6.29.6-3mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-desktop-devel-latest-2.6.29.6-3mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-desktop-latest-2.6.29.6-3mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"kernel-desktop586-2.6.29.6-3mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"kernel-desktop586-devel-2.6.29.6-3mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"kernel-desktop586-devel-latest-2.6.29.6-3mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"kernel-desktop586-latest-2.6.29.6-3mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-doc-2.6.29.6-3mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-server-2.6.29.6-3mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-server-devel-2.6.29.6-3mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-server-devel-latest-2.6.29.6-3mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-server-latest-2.6.29.6-3mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-source-2.6.29.6-3mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-source-latest-2.6.29.6-3mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"libafs-kernel-2.6.29.6-desktop-3mnb-1.4.10-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libafs-kernel-2.6.29.6-desktop586-3mnb-1.4.10-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"libafs-kernel-2.6.29.6-server-3mnb-1.4.10-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"libafs-kernel-desktop-latest-1.4.10-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libafs-kernel-desktop586-latest-1.4.10-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"libafs-kernel-server-latest-1.4.10-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"lirc-kernel-2.6.29.6-desktop-3mnb-0.8.5-0.20090320.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"lirc-kernel-2.6.29.6-desktop586-3mnb-0.8.5-0.20090320.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"lirc-kernel-2.6.29.6-server-3mnb-0.8.5-0.20090320.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"lirc-kernel-desktop-latest-0.8.5-1.20091209.0.20090320.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"lirc-kernel-desktop586-latest-0.8.5-1.20091209.0.20090320.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"lirc-kernel-server-latest-0.8.5-1.20091209.0.20090320.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"lzma-kernel-2.6.29.6-desktop-3mnb-4.43-27.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"lzma-kernel-2.6.29.6-desktop586-3mnb-4.43-27.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"lzma-kernel-2.6.29.6-server-3mnb-4.43-27.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"lzma-kernel-desktop-latest-4.43-1.20091209.27.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"lzma-kernel-desktop586-latest-4.43-1.20091209.27.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"lzma-kernel-server-latest-4.43-1.20091209.27.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"madwifi-kernel-2.6.29.6-desktop-3mnb-0.9.4-4.r3998mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"madwifi-kernel-2.6.29.6-desktop586-3mnb-0.9.4-4.r3998mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"madwifi-kernel-2.6.29.6-server-3mnb-0.9.4-4.r3998mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"madwifi-kernel-desktop-latest-0.9.4-1.20091209.4.r3998mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"madwifi-kernel-desktop586-latest-0.9.4-1.20091209.4.r3998mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"madwifi-kernel-server-latest-0.9.4-1.20091209.4.r3998mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia-current-kernel-2.6.29.6-desktop-3mnb-180.51-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"nvidia-current-kernel-2.6.29.6-desktop586-3mnb-180.51-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia-current-kernel-2.6.29.6-server-3mnb-180.51-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia-current-kernel-desktop-latest-180.51-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"nvidia-current-kernel-desktop586-latest-180.51-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia-current-kernel-server-latest-180.51-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia173-kernel-2.6.29.6-desktop-3mnb-173.14.18-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"nvidia173-kernel-2.6.29.6-desktop586-3mnb-173.14.18-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia173-kernel-2.6.29.6-server-3mnb-173.14.18-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia173-kernel-desktop-latest-173.14.18-1.20091209.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"nvidia173-kernel-desktop586-latest-173.14.18-1.20091209.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia173-kernel-server-latest-173.14.18-1.20091209.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia96xx-kernel-2.6.29.6-desktop-3mnb-96.43.11-5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"nvidia96xx-kernel-2.6.29.6-desktop586-3mnb-96.43.11-5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia96xx-kernel-2.6.29.6-server-3mnb-96.43.11-5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia96xx-kernel-desktop-latest-96.43.11-1.20091209.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"nvidia96xx-kernel-desktop586-latest-96.43.11-1.20091209.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia96xx-kernel-server-latest-96.43.11-1.20091209.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"slmodem-kernel-2.6.29.6-desktop-3mnb-2.9.11-0.20080817.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"slmodem-kernel-2.6.29.6-desktop586-3mnb-2.9.11-0.20080817.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"slmodem-kernel-2.6.29.6-server-3mnb-2.9.11-0.20080817.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"slmodem-kernel-desktop-latest-2.9.11-1.20091209.0.20080817.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"slmodem-kernel-desktop586-latest-2.9.11-1.20091209.0.20080817.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"slmodem-kernel-server-latest-2.9.11-1.20091209.0.20080817.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vboxadditions-kernel-2.6.29.6-desktop-3mnb-2.2.0-4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"vboxadditions-kernel-2.6.29.6-desktop586-3mnb-2.2.0-4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vboxadditions-kernel-2.6.29.6-server-3mnb-2.2.0-4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vboxadditions-kernel-desktop-latest-2.2.0-1.20091209.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"vboxadditions-kernel-desktop586-latest-2.2.0-1.20091209.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vboxadditions-kernel-server-latest-2.2.0-1.20091209.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"virtualbox-kernel-2.6.29.6-desktop-3mnb-2.2.0-4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"virtualbox-kernel-2.6.29.6-desktop586-3mnb-2.2.0-4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"virtualbox-kernel-2.6.29.6-server-3mnb-2.2.0-4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"virtualbox-kernel-desktop-latest-2.2.0-1.20091209.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"virtualbox-kernel-desktop586-latest-2.2.0-1.20091209.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"virtualbox-kernel-server-latest-2.2.0-1.20091209.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"vpnclient-kernel-2.6.29.6-desktop-3mnb-4.8.02.0030-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"vpnclient-kernel-2.6.29.6-desktop-3mnb-4.8.01.0640-3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"vpnclient-kernel-2.6.29.6-desktop586-3mnb-4.8.02.0030-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"vpnclient-kernel-2.6.29.6-server-3mnb-4.8.02.0030-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"vpnclient-kernel-2.6.29.6-server-3mnb-4.8.01.0640-3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"vpnclient-kernel-desktop-latest-4.8.02.0030-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"vpnclient-kernel-desktop-latest-4.8.01.0640-1.20091209.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"vpnclient-kernel-desktop586-latest-4.8.02.0030-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"vpnclient-kernel-server-latest-4.8.02.0030-1.20091209.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"vpnclient-kernel-server-latest-4.8.01.0640-1.20091209.3mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"broadcom-wl-kernel-2.6.31.6-desktop-1mnb-5.10.91.9-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"broadcom-wl-kernel-2.6.31.6-desktop586-1mnb-5.10.91.9-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"broadcom-wl-kernel-2.6.31.6-server-1mnb-5.10.91.9-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"broadcom-wl-kernel-desktop-latest-5.10.91.9-1.20091209.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"broadcom-wl-kernel-desktop586-latest-5.10.91.9-1.20091209.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"broadcom-wl-kernel-server-latest-5.10.91.9-1.20091209.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"em8300-kernel-2.6.31.6-desktop-1mnb-0.17.4-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"em8300-kernel-2.6.31.6-desktop586-1mnb-0.17.4-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"em8300-kernel-2.6.31.6-server-1mnb-0.17.4-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"em8300-kernel-desktop-latest-0.17.4-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"em8300-kernel-desktop586-latest-0.17.4-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"em8300-kernel-server-latest-0.17.4-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"fglrx-kernel-2.6.31.6-desktop-1mnb-8.650-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"fglrx-kernel-2.6.31.6-desktop586-1mnb-8.650-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"fglrx-kernel-2.6.31.6-server-1mnb-8.650-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"fglrx-kernel-desktop-latest-8.650-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"fglrx-kernel-desktop586-latest-8.650-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"fglrx-kernel-server-latest-8.650-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.31.6-desktop-1mnb-1.19-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.31.6-desktop586-1mnb-1.19-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.31.6-server-1mnb-1.19-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"hcfpcimodem-kernel-desktop-latest-1.19-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"hcfpcimodem-kernel-desktop586-latest-1.19-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"hcfpcimodem-kernel-server-latest-1.19-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"hsfmodem-kernel-2.6.31.6-desktop-1mnb-7.80.02.05-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"hsfmodem-kernel-2.6.31.6-desktop586-1mnb-7.80.02.05-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"hsfmodem-kernel-2.6.31.6-server-1mnb-7.80.02.05-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"hsfmodem-kernel-desktop-latest-7.80.02.05-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"hsfmodem-kernel-desktop586-latest-7.80.02.05-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"hsfmodem-kernel-server-latest-7.80.02.05-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-2.6.31.6-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-desktop-2.6.31.6-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-desktop-devel-2.6.31.6-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-desktop-devel-latest-2.6.31.6-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-desktop-latest-2.6.31.6-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"kernel-desktop586-2.6.31.6-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"kernel-desktop586-devel-2.6.31.6-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"kernel-desktop586-devel-latest-2.6.31.6-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"kernel-desktop586-latest-2.6.31.6-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-doc-2.6.31.6-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-server-2.6.31.6-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-server-devel-2.6.31.6-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-server-devel-latest-2.6.31.6-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-server-latest-2.6.31.6-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-source-2.6.31.6-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kernel-source-latest-2.6.31.6-1mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"libafs-kernel-2.6.31.6-desktop-1mnb-1.4.11-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libafs-kernel-2.6.31.6-desktop586-1mnb-1.4.11-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"libafs-kernel-2.6.31.6-server-1mnb-1.4.11-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"libafs-kernel-desktop-latest-1.4.11-1.20091209.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libafs-kernel-desktop586-latest-1.4.11-1.20091209.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"libafs-kernel-server-latest-1.4.11-1.20091209.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"lirc-kernel-2.6.31.6-desktop-1mnb-0.8.6-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"lirc-kernel-2.6.31.6-desktop586-1mnb-0.8.6-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"lirc-kernel-2.6.31.6-server-1mnb-0.8.6-2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"lirc-kernel-desktop-latest-0.8.6-1.20091209.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"lirc-kernel-desktop586-latest-0.8.6-1.20091209.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"lirc-kernel-server-latest-0.8.6-1.20091209.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"lzma-kernel-2.6.31.6-desktop-1mnb-4.43-28mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"lzma-kernel-2.6.31.6-desktop586-1mnb-4.43-28mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"lzma-kernel-2.6.31.6-server-1mnb-4.43-28mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"lzma-kernel-desktop-latest-4.43-1.20091209.28mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"lzma-kernel-desktop586-latest-4.43-1.20091209.28mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"lzma-kernel-server-latest-4.43-1.20091209.28mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"madwifi-kernel-2.6.31.6-desktop-1mnb-0.9.4-4.r4068mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"madwifi-kernel-2.6.31.6-desktop586-1mnb-0.9.4-4.r4068mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"madwifi-kernel-2.6.31.6-server-1mnb-0.9.4-4.r4068mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"madwifi-kernel-desktop-latest-0.9.4-1.20091209.4.r4068mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"madwifi-kernel-desktop586-latest-0.9.4-1.20091209.4.r4068mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"madwifi-kernel-server-latest-0.9.4-1.20091209.4.r4068mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia-current-kernel-2.6.31.6-desktop-1mnb-185.18.36-4mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"nvidia-current-kernel-2.6.31.6-desktop586-1mnb-185.18.36-4mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia-current-kernel-2.6.31.6-server-1mnb-185.18.36-4mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia-current-kernel-desktop-latest-185.18.36-1.20091209.4mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"nvidia-current-kernel-desktop586-latest-185.18.36-1.20091209.4mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia-current-kernel-server-latest-185.18.36-1.20091209.4mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia173-kernel-2.6.31.6-desktop-1mnb-173.14.20-7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"nvidia173-kernel-2.6.31.6-desktop586-1mnb-173.14.20-7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia173-kernel-2.6.31.6-server-1mnb-173.14.20-7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia173-kernel-desktop-latest-173.14.20-1.20091209.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"nvidia173-kernel-desktop586-latest-173.14.20-1.20091209.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia173-kernel-server-latest-173.14.20-1.20091209.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia96xx-kernel-2.6.31.6-desktop-1mnb-96.43.13-7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"nvidia96xx-kernel-2.6.31.6-desktop586-1mnb-96.43.13-7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia96xx-kernel-2.6.31.6-server-1mnb-96.43.13-7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia96xx-kernel-desktop-latest-96.43.13-1.20091209.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"nvidia96xx-kernel-desktop586-latest-96.43.13-1.20091209.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nvidia96xx-kernel-server-latest-96.43.13-1.20091209.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"slmodem-kernel-2.6.31.6-desktop-1mnb-2.9.11-0.20080817.4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"slmodem-kernel-2.6.31.6-desktop586-1mnb-2.9.11-0.20080817.4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"slmodem-kernel-2.6.31.6-server-1mnb-2.9.11-0.20080817.4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"slmodem-kernel-desktop-latest-2.9.11-1.20091209.0.20080817.4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"slmodem-kernel-desktop586-latest-2.9.11-1.20091209.0.20080817.4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"slmodem-kernel-server-latest-2.9.11-1.20091209.0.20080817.4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"squashfs-lzma-kernel-2.6.31.6-desktop-1mnb-3.3-11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"squashfs-lzma-kernel-2.6.31.6-desktop586-1mnb-3.3-11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"squashfs-lzma-kernel-2.6.31.6-server-1mnb-3.3-11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"squashfs-lzma-kernel-desktop-latest-3.3-1.20091209.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"squashfs-lzma-kernel-desktop586-latest-3.3-1.20091209.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"squashfs-lzma-kernel-server-latest-3.3-1.20091209.11mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"vboxadditions-kernel-2.6.31.6-desktop-1mnb-3.0.8-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vboxadditions-kernel-2.6.31.6-desktop586-1mnb-3.0.8-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"vboxadditions-kernel-2.6.31.6-server-1mnb-3.0.8-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"vboxadditions-kernel-desktop-latest-3.0.8-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vboxadditions-kernel-desktop586-latest-3.0.8-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"vboxadditions-kernel-server-latest-3.0.8-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"virtualbox-kernel-2.6.31.6-desktop-1mnb-3.0.8-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"virtualbox-kernel-2.6.31.6-desktop586-1mnb-3.0.8-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"virtualbox-kernel-2.6.31.6-server-1mnb-3.0.8-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"virtualbox-kernel-desktop-latest-3.0.8-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"virtualbox-kernel-desktop586-latest-3.0.8-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"virtualbox-kernel-server-latest-3.0.8-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vpnclient-kernel-2.6.31.6-desktop-1mnb-4.8.02.0030-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vpnclient-kernel-2.6.31.6-desktop586-1mnb-4.8.02.0030-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vpnclient-kernel-2.6.31.6-server-1mnb-4.8.02.0030-1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vpnclient-kernel-desktop-latest-4.8.02.0030-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vpnclient-kernel-desktop586-latest-4.8.02.0030-1.20091209.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vpnclient-kernel-server-latest-4.8.02.0030-1.20091209.1mdv2010.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
