#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0893 and 
# Oracle Linux Security Advisory ELSA-2008-0893 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67750);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:41:02 $");

  script_cve_id("CVE-2008-1372");
  script_osvdb_id(43425);
  script_xref(name:"RHSA", value:"2008:0893");

  script_name(english:"Oracle Linux 3 / 4 / 5 : bzip2 (ELSA-2008-0893)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0893 :

Updated bzip2 packages that fix a security issue are now available for
Red Hat Enterprise Linux 2.1, 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Bzip2 is a freely available, high-quality data compressor. It provides
both stand-alone compression and decompression utilities, as well as a
shared library for use with other programs.

A buffer over-read flaw was discovered in the bzip2 decompression
routine. This issue could cause an application linked against the
libbz2 library to crash when decompressing malformed archives.
(CVE-2008-1372)

Users of bzip2 should upgrade to these updated packages, which contain
a backported patch to resolve this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-September/000735.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-September/000736.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-September/000737.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bzip2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bzip2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bzip2-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/16");
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
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"bzip2-1.0.2-12.EL3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"bzip2-1.0.2-12.EL3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"bzip2-devel-1.0.2-12.EL3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"bzip2-devel-1.0.2-12.EL3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"bzip2-libs-1.0.2-12.EL3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"bzip2-libs-1.0.2-12.EL3")) flag++;

if (rpm_check(release:"EL4", reference:"bzip2-1.0.2-14.el4_7")) flag++;
if (rpm_check(release:"EL4", reference:"bzip2-devel-1.0.2-14.el4_7")) flag++;
if (rpm_check(release:"EL4", reference:"bzip2-libs-1.0.2-14.el4_7")) flag++;

if (rpm_check(release:"EL5", reference:"bzip2-1.0.3-4.el5_2")) flag++;
if (rpm_check(release:"EL5", reference:"bzip2-devel-1.0.3-4.el5_2")) flag++;
if (rpm_check(release:"EL5", reference:"bzip2-libs-1.0.3-4.el5_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bzip2 / bzip2-devel / bzip2-libs");
}
