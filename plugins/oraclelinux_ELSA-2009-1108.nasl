#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1108 and 
# Oracle Linux Security Advisory ELSA-2009-1108 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67876);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/30 15:10:03 $");

  script_cve_id("CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");
  script_bugtraq_id(35221, 35251, 35253);
  script_osvdb_id(55057, 55058, 55059);
  script_xref(name:"RHSA", value:"2009:1108");

  script_name(english:"Oracle Linux 3 : httpd (ELSA-2009-1108)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1108 :

Updated httpd packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular Web server. The httpd package
shipped with Red Hat Enterprise Linux 3 contains an embedded copy of
the Apache Portable Runtime (APR) utility library, a free library of C
data structures and routines, which includes interfaces to support XML
parsing, LDAP connections, database interfaces, URI parsing, and more.

An off-by-one overflow flaw was found in the way apr-util processed a
variable list of arguments. An attacker could provide a specially
crafted string as input for the formatted output conversion routine,
which could, on big-endian platforms, potentially lead to the
disclosure of sensitive information or a denial of service
(application crash). (CVE-2009-1956)

Note: The CVE-2009-1956 flaw only affects big-endian platforms, such
as the IBM S/390 and PowerPC. It does not affect users using the httpd
package on little-endian platforms, due to their different
organization of byte ordering used to represent particular data.

A denial of service flaw was found in the apr-util Extensible Markup
Language (XML) parser. A remote attacker could create a specially
crafted XML document that would cause excessive memory consumption
when processed by the XML decoding engine. (CVE-2009-1955)

A heap-based underwrite flaw was found in the way apr-util created
compiled forms of particular search patterns. An attacker could
formulate a specially crafted search keyword, that would overwrite
arbitrary heap memory locations when processed by the pattern
preparation engine. (CVE-2009-0023)

All httpd users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-June/001048.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/17");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"httpd-2.0.46-73.0.1.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"httpd-2.0.46-73.0.1.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"httpd-devel-2.0.46-73.0.1.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"httpd-devel-2.0.46-73.0.1.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"mod_ssl-2.0.46-73.0.1.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"mod_ssl-2.0.46-73.0.1.ent")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / mod_ssl");
}
