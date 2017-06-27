#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2016-3587.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(92656);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/19 14:25:11 $");

  script_cve_id("CVE-2016-2117", "CVE-2016-6197", "CVE-2016-6198");

  script_name(english:"Oracle Linux 6 / 7 : kernel-uek (ELSA-2016-3587)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[4.1.12-37.6.1.el7uek]
- vfs: rename: check backing inode being equal (Miklos Szeredi) 
[Orabug: 24010060]  {CVE-2016-6198} {CVE-2016-6197}
- vfs: add vfs_select_inode() helper (Miklos Szeredi)  [Orabug: 
24010060]  {CVE-2016-6198} {CVE-2016-6197}
- ovl: verify upper dentry before unlink and rename (Miklos Szeredi) 
[Orabug: 24010060]  {CVE-2016-6198} {CVE-2016-6197}
- ovl: fix getcwd() failure after unsuccessful rmdir (Rui Wang) 
[Orabug: 24010060]  {CVE-2016-6198} {CVE-2016-6197}
- xen: use same main loop for counting and remapping pages (Juergen 
Gross)  [Orabug: 24012238]
- Revert 'ocfs2: bump up o2cb network protocol version' (Junxiao Bi) 
[Orabug: 23710417]
- atl2: Disable unimplemented scatter/gather feature (Ben Hutchings) 
[Orabug: 23704078]  {CVE-2016-2117}
- Revert 'perf tools: Bump default sample freq to 4 kHz' 
(ashok.vairavan)  [Orabug: 23634802]
- block: Initialize max_dev_sectors to 0 (Keith Busch)  [Orabug: 23333444]
- sd: Fix rw_max for devices that report an optimal xfer size (Martin K. 
Petersen)  [Orabug: 23333444]
- sd: Fix excessive capacity printing on devices with blocks bigger than 
512 bytes (Martin K. Petersen)  [Orabug: 23333444]
- sd: Optimal I/O size is in bytes, not sectors (Martin K. Petersen) 
[Orabug: 23333444]
- sd: Reject optimal transfer length smaller than page size (Martin K. 
Petersen)  [Orabug: 23333444]
- Fix kabi issue for upstream commit ca369d51 (Joe Jin)  [Orabug: 23333444]
- block/sd: Fix device-imposed transfer length limits (Joe Jin) 
[Orabug: 23333444]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-July/006214.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-July/006215.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-4.1.12-37.6.1.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-4.1.12-37.6.1.el7uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"dtrace-modules-4.1.12-37.6.1.el6uek-0.5.2-1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-4.1.12-37.6.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-4.1.12-37.6.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.1.12-37.6.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-devel-4.1.12-37.6.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-doc-4.1.12-37.6.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-firmware-4.1.12-37.6.1.el6uek")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"dtrace-modules-4.1.12-37.6.1.el7uek-0.5.2-1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-4.1.12-37.6.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-4.1.12-37.6.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.1.12-37.6.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-4.1.12-37.6.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-4.1.12-37.6.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-firmware-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-firmware-4.1.12-37.6.1.el7uek")) flag++;


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
