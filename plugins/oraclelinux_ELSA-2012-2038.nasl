#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2012-2038.
#

include("compat.inc");

if (description)
{
  script_id(68683);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/12/01 17:16:03 $");

  script_cve_id("CVE-2012-2313", "CVE-2012-2390", "CVE-2012-3412", "CVE-2012-3430");
  script_bugtraq_id(53668, 53965, 54702, 54763);

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2012-2038)");
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
[2.6.32-300.37.1.el6uek]
- sfc: Replace some literal constants with EFX_PAGE_SIZE/EFX_BUF_SIZE (Ben Hutchings) [Orabug: 14769994]
- CVE-2012-3412 sfc: Fix maximum number of TSO segments and minimum TX queue size (Ben Hutchings) [Orabug: 14769994] {CVE-2012-3412}

[2.6.32-300.36.1.el6uek]
- dl2k: Clean up rio_ioctl (Stephan Mueller) [Orabug: 14675306] {CVE-2012-2313}
- hugetlb: fix resv_map leak in error path (Christoph Lameter) [Orabug: 14676403] {CVE-2012-2390}
- rds: set correct msg_namelen (Jay Fenlason) [Orabug: 14676504] {CVE-2012-3430}

[2.6.32-300.35.1.el6uek]
- oracleasm: Bring driver in sync with UEK2 (Martin K. Petersen)
- Fix system hang due to bad protection module parameters (CR 130769) (Martin
  K. Petersen)
- sd: Avoid remapping bad reference tags (Martin K. Petersen)
- block: Fix bad range check in bio_sector_offset (Martin K. Petersen)

[2.6.32-300.34.1.el6uek]
- htrimer: fix kabi breakage (Joe Jin)
- 2.6.32.x: timekeeping: Add missing update call in timekeeping_resume()
  (Thomas Gleixner)
- 2.6.32.x: hrtimer: Update hrtimer base offsets each hrtimer_interrupt (John
  Stultz)
- 2.6.32.x: timekeeping: Provide hrtimer update function (Thomas Gleixner)
- 2.6.32.x: hrtimers: Move lock held region in hrtimer_interrupt() (Thomas
  Gleixner)
- 2.6.32.x: timekeeping: Maintain ktime_t based offsets for hrtimers (Thomas
  Gleixner)
- 2.6.32.x: timekeeping: Fix leapsecond triggered load spike issue (John
  Stultz)
- 2.6.32.x: hrtimer: Provide clock_was_set_delayed() (John Stultz)
- 2.6.32.x: time: Move common updates to a function (Thomas Gleixner)
- 2.6.32.x: timekeeping: Fix CLOCK_MONOTONIC inconsistency during leapsecond
  (John Stultz)
- 2.6.32.x: ntp: Correct TAI offset during leap second (Richard Cochran)
- 2.6.32.x: ntp: Fix leap-second hrtimer livelock (John Stultz)
- Revert '2.6.32.x: hrtimer: Fix clock_was_set so it is safe to call from irq
  context' (Joe Jin)
- Revert '2.6.32.x: time: Fix leapsecond triggered hrtimer/futex load spike
  issue' (Joe Jin)
- Revert '2.6.32.x: hrtimer: Update hrtimer base offsets each
  hrtimer_interrupt' (Joe Jin)

[2.6.32-300.33.1.el6uek]
- mpt2sas: Update mpt2sas to 120.105.11.00 (Guru Anbalagane) [Orabug: 14376481]
- Revert 'mpt2sas: update to 12.105.11.00' (Maxim Uvarov)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-October/003086.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-October/003090.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-300.37.1.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-300.37.1.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-300.37.1.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-300.37.1.el6uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-300.37.1.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-300.37.1.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-300.37.1.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-300.37.1.el6uekdebug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/19");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-2.6.32-300.37.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-debug-2.6.32-300.37.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-devel-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-debug-devel-2.6.32-300.37.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-devel-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-devel-2.6.32-300.37.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-doc-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-doc-2.6.32-300.37.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-firmware-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-firmware-2.6.32-300.37.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-headers-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-headers-2.6.32-300.37.1.el5uek")) flag++;
if (rpm_check(release:"EL5", reference:"mlnx_en-2.6.32-300.37.1.el5uek-1.5.7-2")) flag++;
if (rpm_check(release:"EL5", reference:"mlnx_en-2.6.32-300.37.1.el5uekdebug-1.5.7-2")) flag++;
if (rpm_check(release:"EL5", reference:"ofa-2.6.32-300.37.1.el5uek-1.5.1-4.0.58")) flag++;
if (rpm_check(release:"EL5", reference:"ofa-2.6.32-300.37.1.el5uekdebug-1.5.1-4.0.58")) flag++;

if (rpm_exists(release:"EL6", rpm:"kernel-uek-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-2.6.32-300.37.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-debug-2.6.32-300.37.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-debug-devel-2.6.32-300.37.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-devel-2.6.32-300.37.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-doc-2.6.32-300.37.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-firmware-2.6.32-300.37.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-headers-2.6.32-300.37.1.el6uek")) flag++;
if (rpm_check(release:"EL6", reference:"mlnx_en-2.6.32-300.37.1.el6uek-1.5.7-0.1")) flag++;
if (rpm_check(release:"EL6", reference:"mlnx_en-2.6.32-300.37.1.el6uekdebug-1.5.7-0.1")) flag++;
if (rpm_check(release:"EL6", reference:"ofa-2.6.32-300.37.1.el6uek-1.5.1-4.0.58")) flag++;
if (rpm_check(release:"EL6", reference:"ofa-2.6.32-300.37.1.el6uekdebug-1.5.1-4.0.58")) flag++;


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
