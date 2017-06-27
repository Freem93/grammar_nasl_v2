#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2011-2015.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68416);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 17:07:14 $");

  script_cve_id("CVE-2010-4565", "CVE-2010-4649", "CVE-2011-0006", "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-0726", "CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1019", "CVE-2011-1044", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1093", "CVE-2011-1573");

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2011-2015)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[2.6.32-100.28.15.el6]
- sctp: fix to calc the INIT/INIT-ACK chunk length correctly is set 
{CVE-2011-1573}
- dccp: fix oops on Reset after close {CVE-2011-1093}
- bridge: netfilter: fix information leak {CVE-2011-1080}
- Bluetooth: bnep: fix buffer overflow {CVE-2011-1079}
- net: don't allow CAP_NET_ADMIN to load non-netdev kernel modules 
{CVE-2011-1019}
- ipip: add module alias for tunl0 tunnel device
- gre: add module alias for gre0 tunnel device
- drm/radeon/kms: check AA resolve registers on r300 {CVE-2011-1016}
- drm/radeon: fix regression with AA resolve checking {CVE-2011-1016}
- drm: fix unsigned vs signed comparison issue in modeset ctl ioctl 
{CVE-2011-1013}
- proc: protect mm start_code/end_code in /proc/pid/stat {CVE-2011-0726}
- ALSA: caiaq - Fix possible string-buffer overflow {CVE-2011-0712}
- xfs: zero proper structure size for geometry calls {CVE-2011-0711}
- xfs: prevent leaking uninitialized stack memory in FSGEOMETRY_V1 
{CVE-2011-0711}
- ima: fix add LSM rule bug {CVE-2011-0006}
- IB/uverbs: Handle large number of entries in poll CQ {CVE-2010-4649, 
CVE-2011-1044}
- CAN: Use inode instead of kernel address for /proc file {CVE-2010-4565}

[2.6.32-100.28.14.el6]
- IB/qib: fix qib compile warning.
- IB/core: Allow device-specific per-port sysfs files.
- dm crypt: add plain64 iv.
- firmware: add firmware for qib.
- Infiniband: Add QLogic PCIe QLE InfiniBand host channel adapters support."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-May/002134.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-May/002135.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-100.28.15.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-100.28.15.el5debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/12");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-uek-2.6.32-100.28.15.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-uek-debug-2.6.32-100.28.15.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-devel-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-uek-debug-devel-2.6.32-100.28.15.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-devel-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-uek-devel-2.6.32-100.28.15.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-doc-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-uek-doc-2.6.32-100.28.15.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-firmware-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-uek-firmware-2.6.32-100.28.15.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-headers-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-uek-headers-2.6.32-100.28.15.el5")) flag++;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"ofa-2.6.32-100.28.15.el5-1.5.1-4.0.28")) flag++;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"ofa-2.6.32-100.28.15.el5debug-1.5.1-4.0.28")) flag++;

if (rpm_exists(release:"EL6", rpm:"kernel-uek-2.6.32") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-2.6.32-100.28.15.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-2.6.32") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-2.6.32-100.28.15.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-2.6.32") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-devel-2.6.32-100.28.15.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-2.6.32") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-devel-2.6.32-100.28.15.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-2.6.32") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-doc-2.6.32-100.28.15.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-2.6.32") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-firmware-2.6.32-100.28.15.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-headers-2.6.32") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-headers-2.6.32-100.28.15.el6")) flag++;


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
