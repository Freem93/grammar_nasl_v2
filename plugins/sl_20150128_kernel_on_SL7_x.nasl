#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81073);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/29 15:48:27 $");

  script_cve_id("CVE-2014-4171", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-7145", "CVE-2014-7822", "CVE-2014-7841");

  script_name(english:"Scientific Linux Security Update : kernel on SL7.x x86_64");
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
"  - A flaw was found in the way the Linux kernel's SCTP
    implementation validated INIT chunks when performing
    Address Configuration Change (ASCONF). A remote attacker
    could use this flaw to crash the system by sending a
    specially crafted SCTP packet to trigger a NULL pointer
    dereference on the system. (CVE-2014-7841, Important)

  - A race condition flaw was found in the way the Linux
    kernel's mmap(2), madvise(2), and fallocate(2) system
    calls interacted with each other while operating on
    virtual memory file system files. A local user could use
    this flaw to cause a denial of service. (CVE-2014-4171,
    Moderate)

  - A NULL pointer dereference flaw was found in the way the
    Linux kernel's Common Internet File System (CIFS)
    implementation handled mounting of file system shares. A
    remote attacker could use this flaw to crash a client
    system that would mount a file system share from a
    malicious server. (CVE-2014-7145, Moderate)

  - A flaw was found in the way the Linux kernel's splice()
    system call validated its parameters. On certain file
    systems, a local, unprivileged user could use this flaw
    to write past the maximum file size, and thus crash the
    system. (CVE-2014-7822, Moderate)

  - It was found that the parse_rock_ridge_inode_internal()
    function of the Linux kernel's ISOFS implementation did
    not correctly check relocated directories when
    processing Rock Ridge child link (CL) tags. An attacker
    with physical access to the system could use a specially
    crafted ISO image to crash the system or, potentially,
    escalate their privileges on the system. (CVE-2014-5471,
    CVE-2014-5472, Low)

This update also fixes the following bugs :

  - Previously, a kernel panic could occur if a process
    reading from a locked NFS file was killed and the lock
    was not released properly before the read operations
    finished. Consequently, the system crashed. The code
    handling file locks has been fixed, and instead of
    halting, the system now emits a warning about the
    unreleased lock.

  - A race condition in the command abort handling logic of
    the ipr device driver could cause the kernel to panic
    when the driver received a response to an abort command
    prior to receiving other responses to the aborted
    command due to the support for multiple interrupts. With
    this update, the abort handler waits for the aborted
    command's responses first before completing an abort
    operation.

  - Previously, a race condition could occur when changing a
    Page Table Entry (PTE) or a Page Middle Directory (PMD)
    to 'pte_numa' or 'pmd_numa', respectively, causing the
    kernel to crash. This update removes the BUG_ON() macro
    from the __handle_mm_fault() function, preventing the
    kernel panic in the aforementioned scenario.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1501&L=scientific-linux-errata&T=0&P=3219
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ec4b7cc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-abi-whitelists-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-doc-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-3.10.0-123.20.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-123.20.1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
