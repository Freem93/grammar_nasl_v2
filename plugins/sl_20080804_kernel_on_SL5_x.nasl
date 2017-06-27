#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60459);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-1294", "CVE-2008-2136", "CVE-2008-2812");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"These updated packages fix the following security issues :

  - a possible kernel memory leak was found in the Linux
    kernel Simple Internet Transition (SIT) INET6
    implementation. This could allow a local unprivileged
    user to cause a denial of service. (CVE-2008-2136,
    Important)

  - a flaw was found in the Linux kernel setrlimit system
    call, when setting RLIMIT_CPU to a certain value. This
    could allow a local unprivileged user to bypass the CPU
    time limit. (CVE-2008-1294, Moderate)

  - multiple NULL pointer dereferences were found in various
    Linux kernel network drivers. These drivers were missing
    checks for terminal validity, which could allow
    privilege escalation. (CVE-2008-2812, Moderate)

These updated packages fix the following bugs :

  - the GNU libc stub resolver is a minimal resolver that
    works with Domain Name System (DNS) servers to satisfy
    requests from applications for names. The GNU libc stub
    resolver did not specify a source UDP port, and
    therefore used predictable port numbers. This could have
    made DNS spoofing attacks easier.

The Linux kernel has been updated to implement random UDP source ports
where none are specified by an application. This allows applications,
such as those using the GNU libc stub resolver, to use random UDP
source ports, helping to make DNS spoofing attacks harder.

  - when using certain hardware, a bug in UART_BUG_TXEN may
    have caused incorrect hardware detection, causing data
    flow to '/dev/ttyS1' to hang.

  - a 50-75% drop in NFS server rewrite performance,
    compared to Red Hat Enterprise Linux 4.6, has been
    resolved.

  - due a bug in the fast userspace mutex code, while one
    thread fetched a pointer, another thread may have
    removed it, causing the first thread to fetch the wrong
    pointer, possibly causing a system crash.

  - on certain Hitachi hardware, removing the 'uhci_hcd'
    module caused a kernel oops, and the following error :

BUG: warning at
arch/ia64/kernel/iosapic.c:1001/iosapic_unregister_intr()

Even after the 'uhci_hcd' module was reloaded, there was no access to
USB devices. As well, on systems that have legacy interrupts,
'acpi_unregister_gsi' incorrectly called 'iosapci_unregister_intr()',
causing warning messages to be logged.

  - when a page was mapped with mmap(), and 'PROT_WRITE' was
    the only 'prot' argument, the first read of that page
    caused a segmentation fault. If the page was read after
    it was written to, no fault occurred. This was
    incompatible with the Red Hat Enterprise Linux 4
    behavior.

  - due to a NULL pointer dereference in powernowk8_init(),
    a panic may have occurred.

  - certain error conditions handled by the bonding sysfs
    interface could have left rtnl_lock() unbalanced, either
    by locking and returning without unlocking, or by
    unlocking when it did not lock, possibly causing a
    'kernel: RTNL: assertion failed at net/core/fib_rules.c'
    error.

  - the kernel currently expects a maximum of six Machine
    Check Exception (MCE) banks to be exposed by a CPU.
    Certain CPUs have 7 or more, which may have caused the
    MCE to be incorrectly reported.

  - a race condition in UNIX domain sockets may have caused
    recv() to return zero. For clusters, this may have
    caused unexpected failovers.

  - msgrcv() frequently returned an incorrect
    'ERESTARTNOHAND (514)' error number.

  - on certain Intel Itanium-based systems, when kdump was
    configured to halt the system after a dump operation,
    after the 'System halted.' output, the kernel continued
    to output endless 'soft lockup' messages."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0808&L=scientific-linux-errata&T=0&P=819
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d73b11b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-92.1.10.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-92.1.10.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-92.1.10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-92.1.10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-92.1.10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-92.1.10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-92.1.10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-92.1.10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-92.1.10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-92.1.10.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
