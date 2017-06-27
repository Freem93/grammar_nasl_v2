#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2010-2008.
#

include("compat.inc");

if (description)
{
  script_id(68172);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:57:58 $");

  script_cve_id("CVE-2010-2942", "CVE-2010-2943");

  script_name(english:"Oracle Linux 5 : Unbreakable Enterprise kernel (ELSA-2010-2008)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

Following security fixes are included in this unbreakable enterprise 
kernel errata:

CVE-2010-2942
The actions implementation in the network queueing functionality in the 
Linux kernel before 2.6.36-rc2 does not properly initialize certain 
structure members when performing dump operations, which allows local 
users to obtain potentially sensitive information from kernel memory via 
vectors related to (1) the tcf_gact_dump function in 
net/sched/act_gact.c, (2) the tcf_mirred_dump function in 
net/sched/act_mirred.c, (3) the tcf_nat_dump function in 
net/sched/act_nat.c, (4) the tcf_simp_dump function in 
net/sched/act_simple.c, and (5) the tcf_skbedit_dump function in 
net/sched/act_skbedit.c.

CVE-2010-2943
The xfs implementation in the Linux kernel before 2.6.35 does not look 
up inode allocation btrees before reading inode buffers, which allows 
remote authenticated users to read unlinked files, or read or overwrite 
disk blocks that are currently assigned to an active file but were 
previously assigned to an unlinked file, by accessing a stale NFS file 
handle.

OCFS2
Fix to prevent kernel panic caused by corrupted fast symlinks in ocfs2 
filesystem.

[2.6.32-100.20.1.el5]
- [fs] xfs: return inode fork offset in bulkstat for fsr (Dave Chinner)
- [fs] xfs: always use iget in bulkstat (Dave Chinner) {CVE-2010-2943}
- [fs] xfs: validate untrusted inode numbers during lookup (Dave 
Chinner) {CVE-2010-2943}
- [fs] xfs: rename XFS_IGET_BULKSTAT to XFS_IGET_UNTRUSTED (Dave 
Chinner) {CVE-2010-2943}
- [net] net sched: fix some kernel memory leaks (Eric Dumazet) 
{CVE-2010-2942}
- [fs] ocfs2: Don't walk off the end of fast symlinks (Joel Becker)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-October/001671.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_exists(release:"EL5", rpm:"kernel-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-2.6.32-100.20.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-debug-2.6.32-100.20.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-devel-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-100.20.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-devel-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-devel-2.6.32-100.20.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-doc-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-doc-2.6.32-100.20.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-firmware-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-firmware-2.6.32-100.20.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-headers-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-headers-2.6.32-100.20.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
