#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2016-3644.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(95042);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/11/22 15:29:15 $");

  script_cve_id("CVE-2015-8956", "CVE-2016-1583", "CVE-2016-2053", "CVE-2016-3070", "CVE-2016-3699", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4794", "CVE-2016-6136", "CVE-2016-6480");

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2016-3644)");
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
[4.1.12-61.1.19.el7uek]
- acpi: Disable ACPI table override if securelevel is set (Linn 
Crosetto)  [Orabug: 25058966]  {CVE-2016-3699}
- aacraid: Check size values after double-fetch from user (Dave Carroll) 
  [Orabug: 25060060]  {CVE-2016-6480} {CVE-2016-6480}
- audit: fix a double fetch in audit_log_single_execve_arg() (Paul 
Moore)  [Orabug: 25059969]  {CVE-2016-6136}
- ecryptfs: don't allow mmap when the lower fs doesn't support it (Jeff 
Mahoney)  [Orabug: 25023269]  {CVE-2016-1583} {CVE-2016-1583}
- Revert 'ecryptfs: forbid opening files without mmap handler' (Chuck 
Anderson)  [Orabug: 24971921]  {CVE-2016-1583}
- percpu: fix synchronization between synchronous map extension and 
chunk destruction (Tejun Heo)  [Orabug: 25060084]  {CVE-2016-4794}
- percpu: fix synchronization between chunk->map_extend_work and chunk 
destruction (Tejun Heo)  [Orabug: 25060084]  {CVE-2016-4794}
- ALSA: timer: Fix leak in events via snd_timer_user_tinterrupt (Kangjie 
Lu)  [Orabug: 25059898]  {CVE-2016-4578}
- ALSA: timer: Fix leak in events via snd_timer_user_ccallback (Kangjie 
Lu)  [Orabug: 25059898]  {CVE-2016-4578}
- ALSA: timer: Fix leak in SNDRV_TIMER_IOCTL_PARAMS (Kangjie Lu) 
[Orabug: 25059752]  {CVE-2016-4569}
- Bluetooth: Fix potential NULL dereference in RFCOMM bind callback 
(Jaganath Kanakkassery)  [Orabug: 25058894]  {CVE-2015-8956}
- ASN.1: Fix non-match detection failure on data overrun (David Howells) 
  [Orabug: 25059037]  {CVE-2016-2053}
- mm: migrate dirty page without clear_page_dirty_for_io etc (Hugh 
Dickins)  [Orabug: 25059188]  {CVE-2016-3070}"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-November/006525.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-November/006526.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-4.1.12-61.1.19.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-4.1.12-61.1.19.el7uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/22");
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
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"dtrace-modules-4.1.12-61.1.19.el6uek-0.5.3-2.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-4.1.12-61.1.19.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-4.1.12-61.1.19.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.1.12-61.1.19.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-devel-4.1.12-61.1.19.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-doc-4.1.12-61.1.19.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-firmware-4.1.12-61.1.19.el6uek")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"dtrace-modules-4.1.12-61.1.19.el7uek-0.5.3-2.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-4.1.12-61.1.19.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-4.1.12-61.1.19.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.1.12-61.1.19.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-4.1.12-61.1.19.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-4.1.12-61.1.19.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-firmware-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-firmware-4.1.12-61.1.19.el7uek")) flag++;


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
