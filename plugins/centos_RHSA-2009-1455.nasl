#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1455 and 
# CentOS Errata and Security Advisory 2009:1455 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43794);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/19 23:43:06 $");

  script_cve_id("CVE-2009-2849");
  script_xref(name:"RHSA", value:"2009:1455");

  script_name(english:"CentOS 5 : kernel (CESA-2009:1455)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

[Updated 23rd February 2010] This update adds references to two KBase
articles that includes greater detail regarding some bug fixes that
could not be fully documented in the errata note properly.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fix :

* a NULL pointer dereference flaw was found in the Multiple Devices
(md) driver in the Linux kernel. If the 'suspend_lo' or 'suspend_hi'
file on the sysfs file system ('/sys/') is modified when the disk
array is inactive, it could lead to a local denial of service or
privilege escalation. Note: By default, only the root user can write
to the files noted above. (CVE-2009-2849, Moderate)

Bug fixes :

* a bug in nlm_lookup_host() could lead to un-reclaimed file system
locks, resulting in umount failing & NFS service relocation issues for
clusters. (BZ#517967)

* a bug in the sky2 driver prevented the phy from being reset properly
on some hardware when it hung, preventing a link from coming back up.
(BZ#517976)

* disabling MSI-X for qla2xxx also disabled MSI interrupts.
(BZ#519782)

* performance issues with reads when using the qlge driver on PowerPC
systems. A system hang could also occur during reboot. (BZ#519783)

* unreliable time keeping for Red Hat Enterprise Linux virtual
machines. The KVM pvclock code is now used to detect/correct lost
ticks. (BZ#520685)

* /proc/cpuinfo was missing flags for new features in supported
processors, possibly preventing the operating system & applications
from getting the best performance. (BZ#520686)

* reading/writing with a serial loopback device on a certain IBM
system did not work unless booted with 'pnpacpi=off'. (BZ#520905)

* mlx4_core failed to load on systems with more than 32 CPUs.
(BZ#520906)

* on big-endian platforms, interfaces using the mlx4_en driver & Large
Receive Offload (LRO) did not handle VLAN traffic properly (a
segmentation fault in the VLAN stack in the kernel occurred).
(BZ#520908)

* due to a lock being held for a long time, some systems may have
experienced 'BUG: soft lockup' messages under heavy load. (BZ#520919)

* incorrect APIC timer calibration may have caused a system hang
during boot, as well as the system time becoming faster or slower. A
warning is now provided. (BZ#521238)

* a Fibre Channel device re-scan via 'echo '---' >
/sys/class/scsi_host/ host[x]/scan' may not complete after hot adding
a drive, leading to soft lockups ('BUG: soft lockup detected').
(BZ#521239)

* the Broadcom BCM5761 network device could not to be initialized
properly; therefore, the associated interface could not obtain an IP
address via DHCP or be assigned one manually. (BZ#521241)

* when a process attempted to read from a page that had first been
accessed by writing to part of it (via write(2)), the NFS client
needed to flush the modified portion of the page out to the server, &
then read the entire page back in. This flush caused performance
issues. (BZ#521244)

* a kernel panic when using bnx2x devices & LRO in a bridge. A warning
is now provided to disable LRO in these situations. (BZ#522636)

* the scsi_dh_rdac driver was updated to recognize the Sun StorageTek
Flexline 380. (BZ#523237)

* in FIPS mode, random number generators are required to not return
the first block of random data they generate, but rather save it to
seed the repetition check. This update brings the random number
generator into conformance. (BZ#523289)

* an option to disable/enable the use of the first random block is now
provided to bring ansi_cprng into compliance with FIPS-140 continuous
test requirements. (BZ#523290)

* running the SAP Linux Certification Suite in a KVM guest caused
severe SAP kernel errors, causing it to exit. (BZ#524150)

* attempting to 'online' a CPU for a KVM guest via sysfs caused a
system crash. (BZ#524151)

* when using KVM, pvclock returned bogus wallclock values. (BZ#524152)

* the clock could go backwards when using the vsyscall infrastructure.
(BZ#524527)

See References for KBase links re BZ#519782 & BZ#520906.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. Reboot the system for this
update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016234.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09ac109a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016235.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a49cd7e2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-164.2.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-164.2.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-164.2.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-164.2.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-164.2.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-164.2.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-164.2.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-164.2.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-164.2.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-164.2.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
