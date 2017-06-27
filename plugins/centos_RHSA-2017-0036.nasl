#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0036 and 
# CentOS Errata and Security Advisory 2017:0036 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(96456);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/01/17 14:52:07 $");

  script_cve_id("CVE-2016-4998", "CVE-2016-6828", "CVE-2016-7117");
  script_osvdb_id(140494, 142992, 145048);
  script_xref(name:"RHSA", value:"2017:0036");

  script_name(english:"CentOS 6 : kernel (CESA-2017:0036)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* A use-after-free vulnerability was found in the kernels socket
recvmmsg subsystem. This may allow remote attackers to corrupt memory
and may allow execution of arbitrary code. This corruption takes place
during the error handling routines within __sys_recvmmsg() function.
(CVE-2016-7117, Important)

* An out-of-bounds heap memory access leading to a Denial of Service,
heap disclosure, or further impact was found in setsockopt(). The
function call is normally restricted to root, however some processes
with cap_sys_admin may also be able to trigger this flaw in privileged
container environments. (CVE-2016-4998, Moderate)

* A use-after-free vulnerability was found in
tcp_xmit_retransmit_queue and other tcp_* functions. This condition
could allow an attacker to send an incorrect selective acknowledgment
to existing connections, possibly resetting a connection.
(CVE-2016-6828, Moderate)

Bug Fix(es) :

* When parallel NFS returned a file layout, a kernel crash sometimes
occurred. This update removes the call to the BUG_ON() function from a
code path of a client that returns the file layout. As a result, the
kernel no longer crashes in the described situation. (BZ#1385480)

* When a guest virtual machine (VM) on Microsoft Hyper-V was set to
crash on a Nonmaskable Interrupt (NMI) that was injected from the
host, this VM became unresponsive and did not create the vmcore dump
file. This update applies a set of patches to the Virtual Machine Bus
kernel driver (hv_vmbus) that fix this bug. As a result, the VM now
first creates and saves the vmcore dump file and then reboots.
(BZ#1385482)

* From Red Hat Enterprise Linux 6.6 to 6.8, the IPv6 routing cache
occasionally showed incorrect values. This update fixes the
DST_NOCOUNT mechanism, and the IPv6 routing cache now shows correct
values. (BZ#1391974)

* When using the ixgbe driver and the software Fibre Channel over
Ethernet (FCoE) stack, suboptimal performance in some cases occurred
on systems with a large number of CPUs. This update fixes the
fc_exch_alloc() function to try all the available exchange managers in
the list for an available exchange ID. This change avoids failing
allocations, which previously led to the host busy status.
(BZ#1392818)

* When the vmwgfx kernel module loads, it overrides the boot
resolution automatically. Consequently, users were not able to change
the resolution by manual setting of the kernel's 'vga=' parameter in
the /boot/grub/grub.conf file. This update adds the 'nomodeset'
parameter, which can be set in the /boot/grub/grub.conf file. The
'nomodeset' parameter allows the users to prevent the vmwgfx driver
from loading. As a result, the setting of the 'vga=' parameter works
as expected, in case that vmwgfx does not load. (BZ#1392875)

* When Red Hat Enterprise Linux 6.8 was booted on SMBIOS 3.0 based
systems, Desktop Management Interface (DMI) information, which is
referenced by several applications, such as NEC server's memory RAS
utility, was missing entries in the sysfs virtual file system. This
update fixes the underlying source code, and sysfs now shows the DMI
information as expected. (BZ#1393464)

* Previously, bonding mode active backup and the propagation of the
media access control (MAC) address to a VLAN interface did not work in
Red Hat Enterprise Linux 6.8, when the fail_over_mac bonding parameter
was set to fail_over_mac=active. With this update, the underlying
source code has been fixed so that the VLANs continue inheriting the
MAC address of the active physical interface until the VLAN MAC
address is explicitly set to any value. As a result, IPv6 EUI64
addresses for the VLAN can reflect any changes to the MAC address of
the physical interface, and Duplicate Address Detection (DAD) behaves
as expected. (BZ#1396479)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-January/022206.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3650f607"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-abi-whitelists-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-642.13.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
