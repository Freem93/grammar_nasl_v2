#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61215);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-1020", "CVE-2011-3637", "CVE-2011-4077", "CVE-2011-4132", "CVE-2011-4324", "CVE-2011-4325", "CVE-2011-4330", "CVE-2011-4348");

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
"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

  - A buffer overflow flaw was found in the way the Linux
    kernel's XFS file system implementation handled links
    with overly long path names. A local, unprivileged user
    could use this flaw to cause a denial of service or
    escalate their privileges by mounting a specially
    crafted disk. (CVE-2011-4077, Important)

  - The fix for CVE-2011-2482 provided by a previous update
    introduced a regression: on systems that do not have
    Security-Enhanced Linux (SELinux) in Enforcing mode, a
    socket lock race could occur between sctp_rcv() and
    sctp_accept(). A remote attacker could use this flaw to
    cause a denial of service. By default, SELinux runs in
    Enforcing mode on Scientific Linux 5. (CVE-2011-4348,
    Important)

  - The proc file system could allow a local, unprivileged
    user to obtain sensitive information or possibly cause
    integrity issues. (CVE-2011-1020, Moderate)

  - A missing validation flaw was found in the Linux
    kernel's m_stop() implementation. A local, unprivileged
    user could use this flaw to trigger a denial of service.
    (CVE-2011-3637, Moderate)

  - A flaw was found in the Linux kernel's Journaling Block
    Device (JBD). A local attacker could use this flaw to
    crash the system by mounting a specially crafted ext3 or
    ext4 disk. (CVE-2011-4132, Moderate)

  - A flaw was found in the Linux kernel's
    encode_share_access() implementation. A local,
    unprivileged user could use this flaw to trigger a
    denial of service by creating a regular file on an NFSv4
    (Network File System version 4) file system via mknod().
    (CVE-2011-4324, Moderate)

  - A flaw was found in the Linux kernel's NFS
    implementation. A local, unprivileged user could use
    this flaw to cause a denial of service. (CVE-2011-4325,
    Moderate)

  - A missing boundary check was found in the Linux kernel's
    HFS file system implementation. A local attacker could
    use this flaw to cause a denial of service or escalate
    their privileges by mounting a specially crafted disk.
    (CVE-2011-4330, Moderate)

This update also fixes several bugs and adds one enhancement.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues, and fix the bugs and add
the enhancement noted in the Technical Notes. The system must be
rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1201&L=scientific-linux-errata&T=0&P=982
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29ab8e01"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-274.17.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-274.17.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-274.17.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-274.17.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-274.17.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-274.17.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-274.17.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-274.17.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-274.17.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-274.17.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-274.17.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-274.17.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-274.17.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-274.17.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-274.17.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
