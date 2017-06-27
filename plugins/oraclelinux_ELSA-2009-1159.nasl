#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1159 and 
# Oracle Linux Security Advisory ELSA-2009-1159 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67892);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/24 13:36:52 $");

  script_cve_id("CVE-2009-2285", "CVE-2009-2347");
  script_bugtraq_id(35451, 35652);
  script_osvdb_id(55265, 55821, 55822);
  script_xref(name:"RHSA", value:"2009:1159");

  script_name(english:"Oracle Linux 3 / 4 / 5 : libtiff (ELSA-2009-1159)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1159 :

Updated libtiff packages that fix several security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The libtiff packages contain a library of functions for manipulating
Tagged Image File Format (TIFF) files.

Several integer overflow flaws, leading to heap-based buffer
overflows, were found in various libtiff color space conversion tools.
An attacker could create a specially crafted TIFF file, which once
opened by an unsuspecting user, would cause the conversion tool to
crash or, potentially, execute arbitrary code with the privileges of
the user running the tool. (CVE-2009-2347)

A buffer underwrite flaw was found in libtiff's Lempel-Ziv-Welch (LZW)
compression algorithm decoder. An attacker could create a specially
crafted LZW-encoded TIFF file, which once opened by an unsuspecting
user, would cause an application linked with libtiff to access an
out-of-bounds memory location, leading to a denial of service
(application crash). (CVE-2009-2285)

The CVE-2009-2347 flaws were discovered by Tielei Wang from
ICST-ERCIS, Peking University.

All libtiff users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
this update, all applications linked with the libtiff library (such as
Konqueror) must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-July/001078.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-July/001079.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-July/001080.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL3", cpu:"i386", reference:"libtiff-3.5.7-33.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libtiff-3.5.7-33.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libtiff-devel-3.5.7-33.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libtiff-devel-3.5.7-33.el3")) flag++;

if (rpm_check(release:"EL4", reference:"libtiff-3.6.1-12.el4_8.4")) flag++;
if (rpm_check(release:"EL4", reference:"libtiff-devel-3.6.1-12.el4_8.4")) flag++;

if (rpm_check(release:"EL5", reference:"libtiff-3.8.2-7.el5_3.4")) flag++;
if (rpm_check(release:"EL5", reference:"libtiff-devel-3.8.2-7.el5_3.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff / libtiff-devel");
}
