#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2012-2014.
#

include("compat.inc");

if (description)
{
  script_id(68674);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 17:16:03 $");

  script_cve_id("CVE-2011-4086");

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2012-2014)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

* CVE-2011-4086: Denial of service in journaling block device.

The journal block device assumed that a buffer marked as unwritten
or delay could be live without checking if the buffer was mapped.

An unprivileged local user could use this flaw to crash the system.


[2.6.32-300.25.1.el6uek]
- jbd2: clear BH_Delay   BH_Unwritten in journal_unmap_buffer (Eric Sandeen)
   [Bugdb: 13871] {CVE-2011-4086}"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-May/002818.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-May/002819.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-300.25.1.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-300.25.1.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-300.25.1.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-300.25.1.el6uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-300.25.1.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-300.25.1.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-300.25.1.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-300.25.1.el6uekdebug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/21");
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
if (rpm_exists(release:"EL5", rpm:"kernel-uek-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-2.6.32-300.25.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-debug-2.6.32-300.25.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-devel-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-debug-devel-2.6.32-300.25.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-devel-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-devel-2.6.32-300.25.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-doc-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-doc-2.6.32-300.25.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-firmware-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-firmware-2.6.32-300.25.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-headers-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-headers-2.6.32-300.25.1.el5uek")) flag++;
if (rpm_check(release:"EL5", reference:"mlnx_en-2.6.32-300.25.1.el5uek-1.5.7-2")) flag++;
if (rpm_check(release:"EL5", reference:"mlnx_en-2.6.32-300.25.1.el5uekdebug-1.5.7-2")) flag++;
if (rpm_check(release:"EL5", reference:"ofa-2.6.32-300.25.1.el5uek-1.5.1-4.0.58")) flag++;
if (rpm_check(release:"EL5", reference:"ofa-2.6.32-300.25.1.el5uekdebug-1.5.1-4.0.58")) flag++;

if (rpm_exists(release:"EL6", rpm:"kernel-uek-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-2.6.32-300.25.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-debug-2.6.32-300.25.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-debug-devel-2.6.32-300.25.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-devel-2.6.32-300.25.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-doc-2.6.32-300.25.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-firmware-2.6.32-300.25.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-headers-2.6.32-300.25.1.el6uek")) flag++;
if (rpm_check(release:"EL6", reference:"mlnx_en-2.6.32-300.25.1.el6uek-1.5.7-0.1")) flag++;
if (rpm_check(release:"EL6", reference:"mlnx_en-2.6.32-300.25.1.el6uekdebug-1.5.7-0.1")) flag++;
if (rpm_check(release:"EL6", reference:"ofa-2.6.32-300.25.1.el6uek-1.5.1-4.0.47")) flag++;
if (rpm_check(release:"EL6", reference:"ofa-2.6.32-300.25.1.el6uekdebug-1.5.1-4.0.47")) flag++;


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
