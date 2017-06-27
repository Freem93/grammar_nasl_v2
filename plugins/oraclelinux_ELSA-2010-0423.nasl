#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0423 and 
# Oracle Linux Security Advisory ELSA-2010-0423 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68041);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 16:53:47 $");

  script_cve_id("CVE-2010-1321");
  script_bugtraq_id(40235);
  script_osvdb_id(64744);
  script_xref(name:"RHSA", value:"2010:0423");

  script_name(english:"Oracle Linux 3 / 4 / 5 : krb5 (ELSA-2010-0423)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0423 :

Updated krb5 packages that fix one security issue are now available
for Red Hat Enterprise Linux 3, 4, and 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other using symmetric encryption and a
trusted third party, the Key Distribution Center (KDC).

A NULL pointer dereference flaw was discovered in the MIT Kerberos
Generic Security Service Application Program Interface (GSS-API)
library. A remote, authenticated attacker could use this flaw to crash
any server application using the GSS-API authentication mechanism, by
sending a specially crafted GSS-API token with a missing checksum
field. (CVE-2010-1321)

Red Hat would like to thank the MIT Kerberos Team for responsibly
reporting this issue. Upstream acknowledges Shawn Emery of Oracle as
the original reporter.

All krb5 users should upgrade to these updated packages, which contain
a backported patch to correct this issue. All running services using
the MIT Kerberos libraries must be restarted for the update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-May/001466.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-May/001470.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-May/001471.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL3", cpu:"i386", reference:"krb5-devel-1.2.7-72")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"krb5-devel-1.2.7-72")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"krb5-libs-1.2.7-72")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"krb5-libs-1.2.7-72")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"krb5-server-1.2.7-72")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"krb5-server-1.2.7-72")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"krb5-workstation-1.2.7-72")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"krb5-workstation-1.2.7-72")) flag++;

if (rpm_check(release:"EL4", reference:"krb5-devel-1.3.4-62.el4_8.2")) flag++;
if (rpm_check(release:"EL4", reference:"krb5-libs-1.3.4-62.el4_8.2")) flag++;
if (rpm_check(release:"EL4", reference:"krb5-server-1.3.4-62.el4_8.2")) flag++;
if (rpm_check(release:"EL4", reference:"krb5-workstation-1.3.4-62.el4_8.2")) flag++;

if (rpm_check(release:"EL5", reference:"krb5-devel-1.6.1-36.el5_5.4")) flag++;
if (rpm_check(release:"EL5", reference:"krb5-libs-1.6.1-36.el5_5.4")) flag++;
if (rpm_check(release:"EL5", reference:"krb5-server-1.6.1-36.el5_5.4")) flag++;
if (rpm_check(release:"EL5", reference:"krb5-workstation-1.6.1-36.el5_5.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-devel / krb5-libs / krb5-server / krb5-workstation");
}
