#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1193 and 
# CentOS Errata and Security Advisory 2009:1193 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43773);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2007-5966", "CVE-2009-1385", "CVE-2009-1388", "CVE-2009-1389", "CVE-2009-1895", "CVE-2009-2406", "CVE-2009-2407");
  script_bugtraq_id(26880, 35185, 35281, 35647, 35850, 35851);
  script_osvdb_id(55807);
  script_xref(name:"RHSA", value:"2009:1193");

  script_name(english:"CentOS 5 : kernel (CESA-2009:1193)");
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

* the possibility of a timeout value overflow was found in the Linux
kernel high-resolution timers functionality, hrtimers. This could
allow a local, unprivileged user to execute arbitrary code, or cause a
denial of service (kernel panic). (CVE-2007-5966, Important)

* a flaw was found in the Intel PRO/1000 network driver in the Linux
kernel. Frames with sizes near the MTU of an interface may be split
across multiple hardware receive descriptors. Receipt of such a frame
could leak through a validation check, leading to a corruption of the
length check. A remote attacker could use this flaw to send a
specially crafted packet that would cause a denial of service or code
execution. (CVE-2009-1385, Important)

* Michael Tokarev reported a flaw in the Realtek r8169 Ethernet driver
in the Linux kernel. This driver allowed interfaces using this driver
to receive frames larger than could be handled, which could lead to a
remote denial of service or code execution. (CVE-2009-1389, Important)

* the ADDR_COMPAT_LAYOUT and MMAP_PAGE_ZERO flags were not cleared
when a setuid or setgid program was executed. A local, unprivileged
user could use this flaw to bypass the mmap_min_addr protection
mechanism and perform a NULL pointer dereference attack, or bypass the
Address Space Layout Randomization (ASLR) security feature.
(CVE-2009-1895, Important)

* Ramon de Carvalho Valle reported two flaws in the Linux kernel
eCryptfs implementation. A local attacker with permissions to perform
an eCryptfs mount could modify the metadata of the files in that
eCrypfts mount to cause a buffer overflow, leading to a denial of
service or privilege escalation. (CVE-2009-2406, CVE-2009-2407,
Important)

* Konstantin Khlebnikov discovered a race condition in the ptrace
implementation in the Linux kernel. This race condition can occur when
the process tracing and the process being traced participate in a core
dump. A local, unprivileged user could use this flaw to trigger a
deadlock, resulting in a partial denial of service. (CVE-2009-1388,
Moderate)

Bug fixes (see References below for a link to more detailed notes) :

* possible dom0 crash when a Xen para-virtualized guest was installed
while another para-virtualized guest was rebooting. (BZ#497812)

* no directory removal audit record if the directory and its subtree
were recursively watched by an audit rule. (BZ#507561)

* running 'echo 1 > /proc/sys/vm/drop_caches' under high memory load
could cause a kernel panic. (BZ#503692)

* on 32-bit systems, core dumps for some multithreaded applications
did not include all thread information. (BZ#505322)

* a stack buffer used by get_event_name() was too small for nul
terminator sprintf() writes. This could lead to an invalid pointer or
kernel panic. (BZ#506906)

* when using the aic94xx driver, systems with SATA drives may not boot
due to a libsas bug. (BZ#506029)

* Wacom Cintiq 21UX and Intuos stylus buttons were handled incorrectly
when moved away from and back to these tablets. (BZ#508275)

* CPU 'soft lockup' messages and possibe system hangs on systems with
certain Broadcom network devices and running the Linux kernel from the
kernel-xen package. (BZ#503689)

* on 64-bit PowerPC, getitimer() failed for programs using the
ITIMER_REAL timer that were also compiled for 64-bit systems. This
caused such programs to abort. (BZ#510018)

* write operations could be blocked even when using O_NONBLOCK.
(BZ#510239)

* the 'pci=nomsi' option was required for installing and booting Red
Hat Enterprise Linux 5.2 on systems with VIA VT3364 chipsets.
(BZ#507529)

* shutting down, destroying, or migrating Xen guests with large
amounts of memory could cause other guests to be temporarily
unresponsive. (BZ#512311)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. Systems must be rebooted
for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016062.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37e75381"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016063.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9da280a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 119, 189, 362);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/05");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-128.4.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
