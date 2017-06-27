#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:0459 and 
# Oracle Linux Security Advisory ELSA-2009-0459 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67853);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/07 20:57:50 $");

  script_cve_id("CVE-2008-4307", "CVE-2009-0028", "CVE-2009-0676", "CVE-2009-0834");
  script_bugtraq_id(33846, 33951);
  script_osvdb_id(52204);
  script_xref(name:"RHSA", value:"2009:0459");

  script_name(english:"Oracle Linux 4 : kernel (ELSA-2009-0459)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:0459 :

Updated kernel packages that fix several security issues and various
bugs are now available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

* a logic error was found in the do_setlk() function of the Linux
kernel Network File System (NFS) implementation. If a signal
interrupted a lock request, the local POSIX lock was incorrectly
created. This could cause a denial of service on the NFS server if a
file descriptor was closed before its corresponding lock request
returned. (CVE-2008-4307, Important)

* a deficiency was found in the Linux kernel system call auditing
implementation on 64-bit systems. This could allow a local,
unprivileged user to circumvent a system call audit configuration, if
that configuration filtered based on the 'syscall' number or
arguments. (CVE-2009-0834, Important)

* Chris Evans reported a deficiency in the Linux kernel signals
implementation. The clone() system call permits the caller to indicate
the signal it wants to receive when its child exits. When clone() is
called with the CLONE_PARENT flag, it permits the caller to clone a
new child that shares the same parent as itself, enabling the
indicated signal to be sent to the caller's parent (instead of the
caller), even if the caller's parent has different real and effective
user IDs. This could lead to a denial of service of the parent.
(CVE-2009-0028, Moderate)

* the sock_getsockopt() function in the Linux kernel did not properly
initialize a data structure that can be directly returned to
user-space when the getsockopt() function is called with SO_BSDCOMPAT
optname set. This flaw could possibly lead to memory disclosure.
(CVE-2009-0676, Moderate)

Bug fixes :

* a kernel crash may have occurred for Red Hat Enterprise Linux 4.7
guests if their guest configuration file specified 'vif = [
'type=ioemu' ]'. This crash only occurred when starting guests via the
'xm create' command. (BZ#477146)

* a bug in IO-APIC NMI watchdog may have prevented Red Hat Enterprise
Linux 4.7 from being installed on HP ProLiant DL580 G5 systems. Hangs
during installation and 'NMI received for unknown reason [xx]' errors
may have occurred. (BZ#479184)

* a kernel deadlock on some systems when using netdump through a
network interface that uses the igb driver. (BZ#480579)

* a possible kernel hang in sys_ptrace() on the Itanium(r)
architecture, possibly triggered by tracing a threaded process with
strace. (BZ#484904)

* the RHSA-2008:0665 errata only fixed the known problem with the LSI
Logic LSI53C1030 Ultra320 SCSI controller, for tape devices. Read
commands sent to tape devices may have received incorrect data. This
issue may have led to data corruption. This update includes a fix for
all types of devices. (BZ#487399)

* a missing memory barrier caused a race condition in the AIO
subsystem between the read_events() and aio_complete() functions. This
may have caused a thread in read_events() to sleep indefinitely,
possibly causing an application hang. (BZ#489935)

* due to a lack of synchronization in the NFS client code,
modifications to some pages (for files on an NFS mounted file system)
made through a region of memory mapped by mmap() may be lost if the
NFS client invalidates its page cache for particular files.
(BZ#490119)

* a NULL pointer dereference in the megaraid_mbox driver caused a
system crash on some systems. (BZ#493420)

* the ext3_symlink() function in the ext3 file system code used an
illegal __GFP_FS allocation inside some transactions. This may have
resulted in a kernel panic and 'Assertion failure' errors. (BZ#493422)

* do_machine_check() cleared all Machine Check Exception (MCE) status
registers, preventing the BIOS from using them to determine the cause
of certain panics and errors. (BZ#494915)

* a bug prevented NMI watchdog from initializing on HP ProLiant DL580
G5 systems. (BZ#497330)

This update contains backported patches to fix these issues. The
system must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-May/000993.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL4", rpm:"kernel-2.6.9") && rpm_check(release:"EL4", reference:"kernel-2.6.9-78.0.22.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-devel-2.6.9") && rpm_check(release:"EL4", reference:"kernel-devel-2.6.9-78.0.22.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-doc-2.6.9") && rpm_check(release:"EL4", reference:"kernel-doc-2.6.9-78.0.22.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-hugemem-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-78.0.22.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-hugemem-devel-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-78.0.22.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-2.6.9") && rpm_check(release:"EL4", cpu:"ia64", reference:"kernel-largesmp-2.6.9-78.0.22.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-78.0.22.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"ia64", reference:"kernel-largesmp-devel-2.6.9-78.0.22.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-78.0.22.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-smp-2.6.9-78.0.22.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-78.0.22.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-78.0.22.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-78.0.22.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-xenU-2.6.9-78.0.22.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-78.0.22.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-devel-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-xenU-devel-2.6.9-78.0.22.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-devel-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-78.0.22.0.1.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
