#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:1017 and 
# CentOS Errata and Security Advisory 2008:1017 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43719);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2008-3831", "CVE-2008-4554", "CVE-2008-4576");
  script_bugtraq_id(31634, 31792, 31903);
  script_xref(name:"RHSA", value:"2008:1017");

  script_name(english:"CentOS 5 : kernel (CESA-2008:1017)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that resolve several security issues and fix
various bugs are now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* Olaf Kirch reported a flaw in the i915 kernel driver. This flaw
could, potentially, lead to local privilege escalation. Note: the flaw
only affects systems based on the Intel G33 Express Chipset and newer.
(CVE-2008-3831, Important)

* Miklos Szeredi reported a missing check for files opened with
O_APPEND in the sys_splice(). This could allow a local, unprivileged
user to bypass the append-only file restrictions. (CVE-2008-4554,
Important)

* a deficiency was found in the Linux kernel Stream Control
Transmission Protocol (SCTP) implementation. This could lead to a
possible denial of service if one end of a SCTP connection did not
support the AUTH extension. (CVE-2008-4576, Important)

In addition, these updated packages fix the following bugs :

* on Itanium(r) systems, when a multithreaded program was traced using
the command 'strace -f', messages such as

PANIC: attached pid 10740 exited PANIC: handle_group_exit: 10740
leader 10721 ...

will be displayed, and after which the trace would stop. With these
updated packages, 'strace -f' command no longer results in these error
messages, and strace terminates normally after tracing all threads.

* on big-endian systems such as PowerPC, the getsockopt() function
incorrectly returned 0 depending on the parameters passed to it when
the time to live (TTL) value equaled 255.

* when using an NFSv4 file system, accessing the same file with two
separate processes simultaneously resulted in the NFS client process
becoming unresponsive.

* on AMD64 and Intel(r) 64 hypervisor-enabled systems, when a syscall
correctly returned '-1' in code compiled on Red Hat Enterprise Linux
5, the same code, when run with the strace utility, would incorrectly
return an invalid return value. This has been fixed: on AMD64 and
Intel(r) 64 hypervisor-enabled systems, syscalls in compiled code
return the same, correct values as syscalls run with strace.

* on the Itanium(r) architecture, fully-virtualized guest domains
created using more than 64 GB of memory caused other guest domains not
to receive interrupts. This caused soft lockups on other guests. All
guest domains are now able to receive interrupts regardless of their
allotted memory.

* when user-space used SIGIO notification, which was not disabled
before closing a file descriptor and was then re-enabled in a
different process, an attempt by the kernel to dereference a stale
pointer led to a kernel crash. With this fix, such a situation no
longer causes a kernel crash.

* modifications to certain pages made through a memory-mapped region
could have been lost in cases when the NFS client needed to invalidate
the page cache for that particular memory-mapped file.

* fully-virtualized Windows(r) guests became unresponsive due to the
vIOSAPIC component being multiprocessor-unsafe. With this fix,
vIOSAPIC is multiprocessor-safe and Windows guests do not become
unresponsive.

* on certain systems, keyboard controllers could not withstand
continuous requests to switch keyboard LEDs on or off. This resulted
in some or all key presses not being registered by the system.

* on the Itanium(r) architecture, setting the 'vm.nr_hugepages' sysctl
parameter caused a kernel stack overflow resulting in a kernel panic,
and possibly stack corruption. With this fix, setting vm.nr_hugepages
works correctly.

* hugepages allow the Linux kernel to utilize the multiple page size
capabilities of modern hardware architectures. In certain
configurations, systems with large amounts of memory could fail to
allocate most of this memory for hugepages even if it was free. This
could result, for example, in database restart failures.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-December/015497.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb26cb25"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-December/015498.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?876948af"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264, 287, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/16");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-92.1.22.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
