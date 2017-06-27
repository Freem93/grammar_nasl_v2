#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2013-2585.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(71134);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/12/01 17:25:13 $");

  script_cve_id("CVE-2012-6545", "CVE-2013-0343", "CVE-2013-1928", "CVE-2013-2164", "CVE-2013-2234", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2892", "CVE-2013-3231", "CVE-2013-4345", "CVE-2013-4591");
  script_bugtraq_id(58795, 58906, 58991, 59390, 60375, 60874, 62042, 62043, 62049, 62740, 63791);

  script_name(english:"Oracle Linux 5 / 6 : unbreakable enterprise kernel (ELSA-2013-2585)");
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
[2.6.32-400.33.3.el5uek]
- af_key: fix info leaks in notify messages (Mathias Krause) [Orabug: 
17837974] {CVE-2013-2234}
- drivers/cdrom/cdrom.c: use kzalloc() for failing hardware (Jonathan 
Salwan) [Orabug: 17837971] {CVE-2013-2164}
- fs/compat_ioctl.c: VIDEO_SET_SPU_PALETTE missing error check (Kees 
Cook) [Orabug: 17837966] {CVE-2013-1928}
- Bluetooth: RFCOMM - Fix info leak in ioctl(RFCOMMGETDEVLIST) (Mathias 
Krause) [Orabug: 17837959] {CVE-2012-6545}
- Bluetooth: RFCOMM - Fix info leak via getsockname() (Mathias Krause) 
[Orabug: 17838023] {CVE-2012-6545}
- llc: Fix missing msg_namelen update in llc_ui_recvmsg() (Mathias 
Krause) [Orabug: 17837945] {CVE-2013-3231}
- HID: pantherlord: validate output report details (Kees Cook) [Orabug: 
17837942] {CVE-2013-2892}
- HID: zeroplus: validate output report details (Kees Cook) [Orabug: 
17837936] {CVE-2013-2889}
- HID: provide a helper for validating hid reports (Kees Cook) [Orabug: 
17837936] - NFSv4: Check for buffer length in __nfs4_get_acl_uncached 
(Sven Wegener) [Orabug: 17837931] {CVE-2013-4591}
- ansi_cprng: Fix off by one error in non-block size request (Neil 
Horman) [Orabug: 17837999] {CVE-2013-4345}
- HID: validate HID report id size (Kees Cook) [Orabug: 17837925] 
{CVE-2013-2888}
- ipv6: remove max_addresses check from ipv6_create_tempaddr (Hannes 
Frederic Sowa) [Orabug: 17837923] {CVE-2013-0343}"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-November/003837.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-November/003838.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.33.3.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.33.3.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.33.3.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.33.3.el6uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.33.3.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.33.3.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.33.3.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.33.3.el6uekdebug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/29");
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
if (rpm_exists(release:"EL5", rpm:"kernel-uek-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-2.6.32-400.33.3.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-debug-2.6.32-400.33.3.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-devel-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-debug-devel-2.6.32-400.33.3.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-devel-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-devel-2.6.32-400.33.3.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-doc-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-doc-2.6.32-400.33.3.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-firmware-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-firmware-2.6.32-400.33.3.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-headers-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-headers-2.6.32-400.33.3.el5uek")) flag++;
if (rpm_check(release:"EL5", reference:"mlnx_en-2.6.32-400.33.3.el5uek-1.5.7-2")) flag++;
if (rpm_check(release:"EL5", reference:"mlnx_en-2.6.32-400.33.3.el5uekdebug-1.5.7-2")) flag++;
if (rpm_check(release:"EL5", reference:"ofa-2.6.32-400.33.3.el5uek-1.5.1-4.0.58")) flag++;
if (rpm_check(release:"EL5", reference:"ofa-2.6.32-400.33.3.el5uekdebug-1.5.1-4.0.58")) flag++;

if (rpm_exists(release:"EL6", rpm:"kernel-uek-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-2.6.32-400.33.3.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-debug-2.6.32-400.33.3.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-debug-devel-2.6.32-400.33.3.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-devel-2.6.32-400.33.3.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-doc-2.6.32-400.33.3.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-firmware-2.6.32-400.33.3.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-headers-2.6.32-400.33.3.el6uek")) flag++;
if (rpm_check(release:"EL6", reference:"mlnx_en-2.6.32-400.33.3.el6uek-1.5.7-0.1")) flag++;
if (rpm_check(release:"EL6", reference:"mlnx_en-2.6.32-400.33.3.el6uekdebug-1.5.7-0.1")) flag++;
if (rpm_check(release:"EL6", reference:"ofa-2.6.32-400.33.3.el6uek-1.5.1-4.0.58")) flag++;
if (rpm_check(release:"EL6", reference:"ofa-2.6.32-400.33.3.el6uekdebug-1.5.1-4.0.58")) flag++;


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
