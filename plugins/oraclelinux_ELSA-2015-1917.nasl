#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1917 and 
# Oracle Linux Security Advisory ELSA-2015-1917 respectively.
#

include("compat.inc");

if (description)
{
  script_id(86487);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  script_cve_id("CVE-2015-0848", "CVE-2015-4588", "CVE-2015-4695", "CVE-2015-4696");
  script_osvdb_id(122812, 123385, 123541, 123542);
  script_xref(name:"RHSA", value:"2015:1917");

  script_name(english:"Oracle Linux 6 / 7 : libwmf (ELSA-2015-1917)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1917 :

Updated libwmf packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

libwmf is a library for reading and converting Windows Metafile Format
(WMF) vector graphics. libwmf is used by applications such as GIMP and
ImageMagick.

It was discovered that libwmf did not correctly process certain WMF
(Windows Metafiles) with embedded BMP images. By tricking a victim
into opening a specially crafted WMF file in an application using
libwmf, a remote attacker could possibly use this flaw to execute
arbitrary code with the privileges of the user running the
application. (CVE-2015-0848, CVE-2015-4588)

It was discovered that libwmf did not properly process certain WMF
files. By tricking a victim into opening a specially crafted WMF file
in an application using libwmf, a remote attacker could possibly
exploit this flaw to cause a crash or execute arbitrary code with the
privileges of the user running the application. (CVE-2015-4696)

It was discovered that libwmf did not properly process certain WMF
files. By tricking a victim into opening a specially crafted WMF file
in an application using libwmf, a remote attacker could possibly
exploit this flaw to cause a crash. (CVE-2015-4695)

All users of libwmf are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the update, all applications using libwmf must be restarted
for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-October/005461.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-October/005462.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libwmf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libwmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libwmf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libwmf-lite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");
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

flag = 0;
if (rpm_check(release:"EL6", reference:"libwmf-0.2.8.4-25.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libwmf-devel-0.2.8.4-25.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libwmf-lite-0.2.8.4-25.el6_7")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libwmf-0.2.8.4-41.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libwmf-devel-0.2.8.4-41.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libwmf-lite-0.2.8.4-41.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwmf / libwmf-devel / libwmf-lite");
}
