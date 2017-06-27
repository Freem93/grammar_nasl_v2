#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0326 and 
# CentOS Errata and Security Advisory 2009:0326 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43729);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2008-3528", "CVE-2008-5700", "CVE-2009-0028", "CVE-2009-0269", "CVE-2009-0322", "CVE-2009-0675", "CVE-2009-0676", "CVE-2009-0778");
  script_bugtraq_id(33846);
  script_osvdb_id(52204, 56444);
  script_xref(name:"RHSA", value:"2009:0326");

  script_name(english:"CentOS 5 : kernel (CESA-2009:0326)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

* memory leaks were found on some error paths in the icmp_send()
function in the Linux kernel. This could, potentially, cause the
network connectivity to cease. (CVE-2009-0778, Important)

* Chris Evans reported a deficiency in the clone() system call when
called with the CLONE_PARENT flag. This flaw permits the caller (the
parent process) to indicate an arbitrary signal it wants to receive
when its child process exits. This could lead to a denial of service
of the parent process. (CVE-2009-0028, Moderate)

* an off-by-one underflow flaw was found in the eCryptfs subsystem.
This could potentially cause a local denial of service when the
readlink() function returned an error. (CVE-2009-0269, Moderate)

* a deficiency was found in the Remote BIOS Update (RBU) driver for
Dell systems. This could allow a local, unprivileged user to cause a
denial of service by reading zero bytes from the image_type or
packet_size files in '/sys/devices/platform/dell_rbu/'.
(CVE-2009-0322, Moderate)

* an inverted logic flaw was found in the SysKonnect FDDI PCI adapter
driver, allowing driver statistics to be reset only when the
CAP_NET_ADMIN capability was absent (local, unprivileged users could
reset driver statistics). (CVE-2009-0675, Moderate)

* the sock_getsockopt() function in the Linux kernel did not properly
initialize a data structure that can be directly returned to
user-space when the getsockopt() function is called with SO_BSDCOMPAT
optname set. This flaw could possibly lead to memory disclosure.
(CVE-2009-0676, Moderate)

* the ext2 and ext3 file system code failed to properly handle
corrupted data structures, leading to a possible local denial of
service when read or write operations were performed on a specially
crafted file system. (CVE-2008-3528, Low)

* a deficiency was found in the libATA implementation. This could,
potentially, lead to a local denial of service. Note: by default, the
'/dev/sg*' devices are accessible only to the root user.
(CVE-2008-5700, Low)

Bug fixes :

* a bug in aic94xx may have caused kernel panics during boot on some
systems with certain SATA disks. (BZ#485909)

* a word endianness problem in the qla2xx driver on PowerPC-based
machines may have corrupted flash-based devices. (BZ#485908)

* a memory leak in pipe() may have caused a system deadlock. The
workaround in Section 1.5, Known Issues, of the Red Hat Enterprise
Linux 5.3 Release Notes Updates, which involved manually allocating
extra file descriptors to processes calling do_pipe, is no longer
necessary. (BZ#481576)

* CPU soft-lockups in the network rate estimator. (BZ#481746)

* bugs in the ixgbe driver caused it to function unreliably on some
systems with 16 or more CPU cores. (BZ#483210)

* the iwl4965 driver may have caused a kernel panic. (BZ#483206)

* a bug caused NFS attributes to not update for some long-lived NFS
mounted file systems. (BZ#483201)

* unmounting a GFS2 file system may have caused a panic. (BZ#485910)

* a bug in ptrace() may have caused a panic when single stepping a
target. (BZ#487394)

* on some 64-bit systems, notsc was incorrectly set at boot, causing
slow gettimeofday() calls. (BZ#488239)

* do_machine_check() cleared all Machine Check Exception (MCE) status
registers, preventing the BIOS from using them to determine the cause
of certain panics and errors. (BZ#490433)

* scaling problems caused performance problems for LAPI applications.
(BZ#489457)

* a panic may have occurred on systems using certain Intel WiFi Link
5000 products when booting with the RF Kill switch on. (BZ#489846)

* the TSC is invariant with C/P/T states, and always runs at constant
frequency from now on. (BZ#489310)

All users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015712.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7decbd2b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015713.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e301236"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-128.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-128.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-128.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-128.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-128.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-debuginfo-2.6.18-128.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-128.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debuginfo-2.6.18-128.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debuginfo-common-2.6.18-128.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-128.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-128.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-128.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-128.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-debuginfo-2.6.18-128.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-128.1.6.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
