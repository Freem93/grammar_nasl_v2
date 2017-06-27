#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:1001 and 
# Oracle Linux Security Advisory ELSA-2008-1001 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67770);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/01 16:41:02 $");

  script_cve_id("CVE-2008-4313", "CVE-2008-4315");
  script_osvdb_id(50277, 50278);
  script_xref(name:"RHSA", value:"2008:1001");

  script_name(english:"Oracle Linux 5 : tog-pegasus (ELSA-2008-1001)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:1001 :

Updated tog-pegasus packages that fix security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The tog-pegasus packages provide OpenPegasus Web-Based Enterprise
Management (WBEM) services. WBEM is a platform and resource
independent Distributed Management Task Force (DMTF) standard that
defines a common information model and communication protocol for
monitoring and controlling resources.

Red Hat defines additional security enhancements for OpenGroup Pegasus
WBEM services in addition to those defined by the upstream OpenGroup
Pegasus release. For details regarding these enhancements, refer to
the file 'README.RedHat.Security', included in the Red Hat tog-pegasus
package.

After re-basing to version 2.7.0 of the OpenGroup Pegasus code, these
additional security enhancements were no longer being applied. As a
consequence, access to OpenPegasus WBEM services was not restricted to
the dedicated users as described in README.RedHat.Security. An
attacker able to authenticate using a valid user account could use
this flaw to send requests to WBEM services. (CVE-2008-4313)

Note: default SELinux policy prevents tog-pegasus from modifying
system files. This flaw's impact depends on whether or not tog-pegasus
is confined by SELinux, and on any additional CMPI providers installed
and enabled on a particular system.

Failed authentication attempts against the OpenPegasus CIM server were
not logged to the system log as documented in README.RedHat.Security.
An attacker could use this flaw to perform password guessing attacks
against a user account without leaving traces in the system log.
(CVE-2008-4315)

All tog-pegasus users are advised to upgrade to these updated
packages, which contain patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-November/000813.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tog-pegasus packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tog-pegasus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tog-pegasus-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/25");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"tog-pegasus-2.7.0-2.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"tog-pegasus-devel-2.7.0-2.0.1.el5_2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tog-pegasus / tog-pegasus-devel");
}
