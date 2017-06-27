#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60508);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-3831", "CVE-2008-4554", "CVE-2008-4576");

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
"  - Olaf Kirch reported a flaw in the i915 kernel driver
    that only affects the Intel G33 series and newer. This
    flaw could, potentially, lead to local privilege
    escalation. (CVE-2008-3831, Important)

  - Miklos Szeredi reported a missing check for files opened
    with O_APPEND in the sys_splice(). This could allow a
    local, unprivileged user to bypass the append-only file
    restrictions. (CVE-2008-4554, Important)

  - a deficiency was found in the Linux kernel Stream
    Control Transmission Protocol (SCTP) implementation.
    This could lead to a possible denial of service if one
    end of a SCTP connection did not support the AUTH
    extension. (CVE-2008-4576, Important)

In addition, these updated packages fix the following bugs :

  - on Itanium&reg; systems, when a multithreaded program
    was traced using the command 'strace -f', messages
    similar to the following ones were displayed, after
    which the trace would stop :

    PANIC: attached pid 10740 exited PANIC:
    handle_group_exit: 10740 leader 10721 PANIC: attached
    pid 10739 exited PANIC: handle_group_exit: 10739 leader
    10721 ...

In these updated packages, tracing a multithreaded program using the
'strace -f' command no longer results in these error messages, and
strace terminates normally after tracing all threads.

  - on big-endian systems such as PowerPC, the getsockopt()
    function incorrectly returned 0 depending on the
    parameters passed to it when the time to live (TTL)
    value equaled 255.

  - when using an NFSv4 file system, accessing the same file
    with two separate processes simultaneously resulted in
    the NFS client process becoming unresponsive.

  - on AMD64 and Intel&reg; 64 hypervisor-enabled systems,
    in cases in which a syscall correctly returned '-1' in
    code compiled on Red Hat Enterprise Linux 5, the same
    code, when run with the strace utility, would
    incorrectly return an invalid return value. This has
    been fixed so that on AMD64 and Intel&reg; 64
    hypervisor-enabled systems, syscalls in compiled code
    return the same, correct values as syscalls do when run
    with strace.

  - on the Itanium&reg; architecture, fully-virtualized
    guest domains which were created using more than 64 GB
    of memory caused other guest domains not to receive
    interrupts, which caused a soft lockup on other guests.
    All guest domains are now able to receive interrupts
    regardless of their allotted memory.

  - when user-space used SIGIO notification, which wasn't
    disabled before closing a file descriptor, and was then
    re-enabled in a different process, an attempt by the
    kernel to dereference a stale pointer led to a kernel
    crash. With this fix, such a situation no longer causes
    a kernel crash.

  - modifications to certain pages made through a
    memory-mapped region could have been lost in cases when
    the NFS client needed to invalidate the page cache for
    that particular memory-mapped file.

  - fully-virtualized Windows guests became unresponsive due
    to the vIOSAPIC component being multiprocessor-unsafe.
    With this fix, vIOSAPIC is multiprocessor-safe and
    Windows guests do not become unresponsive.

  - on certain systems, keyboard controllers were not able
    to withstand a continuous flow of requests to switch
    keyboard LEDs on or off, which resulted in some or all
    key presses not being registered by the system.

  - on the Itanium&reg; architecture, setting the
    'vm.nr_hugepages' sysctl parameter caused a kernel stack
    overflow resulting in a kernel panic, and possibly stack
    corruption. With this fix, setting vm.nr_hugepages works
    correctly.

  - hugepages allow the Linux kernel to utilize the multiple
    page size capabilities of modern hardware architectures.
    In certain configurations, systems with large amounts of
    memory could fail to allocate most of memory for
    hugepages even if it was free, which could have
    resulted, for example, in database restart failures."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0812&L=scientific-linux-errata&T=0&P=1388
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67b2dac3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/16");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-92.1.22.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-92.1.22.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
