#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2015-3032.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(83045);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/05/06 17:11:37 $");

  script_cve_id("CVE-2014-3215", "CVE-2014-8171", "CVE-2014-9529", "CVE-2014-9584");
  script_bugtraq_id(71880, 74293);

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2015-3032)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

kernel-uek
[3.8.13-68.1.3.el7uek]
- isofs: Fix unchecked printing of ER records (Jan Kara)  [Orabug: 
20930551]  {CVE-2014-9584}
- KEYS: close race between key lookup and freeing (Sasha Levin) 
[Orabug: 20930548]  {CVE-2014-9529} {CVE-2014-9529}
- mm: memcg: do not allow task about to OOM kill to bypass the limit 
(Johannes Weiner)  [Orabug: 20930539]  {CVE-2014-8171}
- mm: memcg: do not declare OOM from __GFP_NOFAIL allocations (Johannes 
Weiner)  [Orabug: 20930539]  {CVE-2014-8171}
- fs: buffer: move allocation failure loop into the allocator (Johannes 
Weiner)  [Orabug: 20930539]  {CVE-2014-8171}
- mm: memcg: handle non-error OOM situations more gracefully (Johannes 
Weiner)  [Orabug: 20930539]  {CVE-2014-8171}
- mm: memcg: do not trap chargers with full callstack on OOM (Johannes 
Weiner)  [Orabug: 20930539]  {CVE-2014-8171}
- mm: memcg: rework and document OOM waiting and wakeup (Johannes 
Weiner)  [Orabug: 20930539]  {CVE-2014-8171}
- mm: memcg: enable memcg OOM killer only for user faults (Johannes 
Weiner)  [Orabug: 20930539]  {CVE-2014-8171}
- x86: finish user fault error path with fatal signal (Johannes Weiner) 
  [Orabug: 20930539]  {CVE-2014-8171}
- arch: mm: pass userspace fault flag to generic fault handler (Johannes 
Weiner)  [Orabug: 20930539]  {CVE-2014-8171}
- selinux: Permit bounded transitions under NO_NEW_PRIVS or NOSUID. 
(Stephen Smalley)  [Orabug: 20930501]  {CVE-2014-3215}"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-April/005016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-April/005017.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-68.1.3.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-68.1.3.el7uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"dtrace-modules-3.8.13-68.1.3.el6uek-0.4.3-4.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-3.8.13-68.1.3.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-3.8.13-68.1.3.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-devel-3.8.13-68.1.3.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-devel-3.8.13-68.1.3.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-doc-3.8.13-68.1.3.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-firmware-3.8.13-68.1.3.el6uek")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"dtrace-modules-3.8.13-68.1.3.el7uek-0.4.3-4.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-3.8.13-68.1.3.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-3.8.13-68.1.3.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-3.8.13-68.1.3.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-3.8.13-68.1.3.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-3.8.13-68.1.3.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-firmware-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-firmware-3.8.13-68.1.3.el7uek")) flag++;


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
