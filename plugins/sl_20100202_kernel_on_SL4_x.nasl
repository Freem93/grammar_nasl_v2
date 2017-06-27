#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60728);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-3080", "CVE-2009-3889", "CVE-2009-3939", "CVE-2009-4005", "CVE-2009-4020", "CVE-2009-4537");

  script_name(english:"Scientific Linux Security Update : kernel on SL4.x i386/x86_64");
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
"CVE-2009-3889 CVE-2009-3939 kernel: megaraid_sas permissions in sysfs

CVE-2009-3080 kernel: gdth: Prevent negative offsets in ioctl

CVE-2009-4005 kernel: isdn: hfc_usb: fix read buffer overflow

CVE-2009-4020 kernel: hfs buffer overflow

This update fixes the following security issues :

  - an array index error was found in the gdth driver in the
    Linux kernel. A local user could send a specially
    crafted IOCTL request that would cause a denial of
    service or, possibly, privilege escalation.
    (CVE-2009-3080, Important)

  - a flaw was found in the collect_rx_frame() function in
    the HiSax ISDN driver (hfc_usb) in the Linux kernel. An
    attacker could use this flaw to send a specially crafted
    HDLC packet that could trigger a buffer out of bounds,
    possibly resulting in a denial of service.
    (CVE-2009-4005, Important)

  - permission issues were found in the megaraid_sas driver
    (for SAS based RAID controllers) in the Linux kernel.
    The 'dbg_lvl' and 'poll_mode_io' files on the sysfs file
    system ('/sys/') had world-writable permissions. This
    could allow local, unprivileged users to change the
    behavior of the driver. (CVE-2009-3889, CVE-2009-3939,
    Moderate)

  - a buffer overflow flaw was found in the hfs_bnode_read()
    function in the HFS file system implementation in the
    Linux kernel. This could lead to a denial of service if
    a user browsed a specially crafted HFS file system, for
    example, by running 'ls'. (CVE-2009-4020, Low)

This update also fixes the following bugs :

  - if a process was using ptrace() to trace a
    multi-threaded process, and that multi-threaded process
    dumped its core, the process performing the trace could
    hang in wait4(). This issue could be triggered by
    running 'strace -f' on a multi-threaded process that was
    dumping its core, resulting in the strace command
    hanging. (BZ#555869)

  - a bug in the ptrace() implementation could have, in some
    cases, caused ptrace_detach() to create a zombie process
    if the process being traced was terminated with a
    SIGKILL signal. (BZ#555869)

  - the kernel-2.6.9-89.0.19.EL update resolved an issue
    (CVE-2009-4537) in the Realtek r8169 Ethernet driver.
    This update implements a better solution for that issue.
    Note: This is not a security regression. The original
    fix was complete. This update is adding the official
    upstream fix. (BZ#556406)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1002&L=scientific-linux-errata&T=0&P=79
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9fafa8aa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=555869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=556406"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/02");
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
if (rpm_check(release:"SL4", cpu:"i386", reference:"ernel-smp-2.6.9-89.0.20.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-89.0.20.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-89.0.20.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-89.0.20.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-89.0.20.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-89.0.20.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.0.20.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.0.20.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-89.0.20.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-89.0.20.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-89.0.20.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-89.0.20.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
