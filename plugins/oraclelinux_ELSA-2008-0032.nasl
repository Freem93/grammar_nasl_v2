#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0032 and 
# Oracle Linux Security Advisory ELSA-2008-0032 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67637);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 16:16:28 $");

  script_cve_id("CVE-2007-6284");
  script_bugtraq_id(27248);
  script_osvdb_id(40194);
  script_xref(name:"RHSA", value:"2008:0032");

  script_name(english:"Oracle Linux 3 / 4 / 5 : libxml2 (ELSA-2008-0032)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0032 :

Updated libxml2 packages that fix a security issue are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The libxml2 packages provide a library that allows you to manipulate
XML files. It includes support to read, modify, and write XML and HTML
files.

A denial of service flaw was found in the way libxml2 processes
certain content. If an application linked against libxml2 processes
malformed XML content, it could cause the application to stop
responding. (CVE-2007-6284)

Red Hat would like to thank the Google Security Team for responsibly
disclosing this issue.

All users are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-January/000481.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-January/000482.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-January/000485.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/11");
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
if (rpm_check(release:"EL3", cpu:"i386", reference:"libxml2-2.5.10-8.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libxml2-2.5.10-8.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libxml2-devel-2.5.10-8.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libxml2-devel-2.5.10-8.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libxml2-python-2.5.10-8.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libxml2-python-2.5.10-8.0.1")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"libxml2-2.6.16-10.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"libxml2-2.6.16-10.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"libxml2-devel-2.6.16-10.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"libxml2-devel-2.6.16-10.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"libxml2-python-2.6.16-10.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"libxml2-python-2.6.16-10.1.0.1")) flag++;

if (rpm_check(release:"EL5", reference:"libxml2-2.6.26-2.1.2.1.0.1")) flag++;
if (rpm_check(release:"EL5", reference:"libxml2-devel-2.6.26-2.1.2.1.0.1")) flag++;
if (rpm_check(release:"EL5", reference:"libxml2-python-2.6.26-2.1.2.1.0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-devel / libxml2-python");
}
