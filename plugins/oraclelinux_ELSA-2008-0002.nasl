#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0002 and 
# Oracle Linux Security Advisory ELSA-2008-0002 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67629);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:21:43 $");

  script_cve_id("CVE-2008-0003");
  script_bugtraq_id(27172);
  script_osvdb_id(40082);
  script_xref(name:"RHSA", value:"2008:0002");

  script_name(english:"Oracle Linux 4 / 5 : tog-pegasus (ELSA-2008-0002)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0002 :

Updated tog-pegasus packages that fix a security issue are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

The tog-pegasus packages provide OpenPegasus Web-Based Enterprise
Management (WBEM) services. WBEM is a platform and resource
independent DMTF standard that defines a common information model, and
communication protocol for monitoring and controlling resources.

During a security audit, a stack-based buffer overflow flaw was found
in the PAM authentication code in the OpenPegasus CIM management
server. An unauthenticated remote user could trigger this flaw and
potentially execute arbitrary code with root privileges.
(CVE-2008-0003)

Note that the tog-pegasus packages are not installed by default on Red
Hat Enterprise Linux. The Red Hat Security Response Team believes that
it would be hard to remotely exploit this issue to execute arbitrary
code, due to the default SELinux targeted policy on Red Hat Enterprise
Linux 4 and 5, and the SELinux memory protection tests enabled by
default on Red Hat Enterprise Linux 5.

Users of tog-pegasus should upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing the
updated packages the tog-pegasus service should be restarted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-January/000471.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-January/000474.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tog-pegasus packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tog-pegasus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tog-pegasus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tog-pegasus-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/08");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", cpu:"i386", reference:"tog-pegasus-2.5.1-5.el4_6.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"tog-pegasus-2.5.1-5.el4_6.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"tog-pegasus-devel-2.5.1-5.el4_6.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"tog-pegasus-devel-2.5.1-5.el4_6.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"tog-pegasus-test-2.5.1-5.el4_6.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"tog-pegasus-test-2.5.1-5.el4_6.1.0.1")) flag++;

if (rpm_check(release:"EL5", reference:"tog-pegasus-2.6.1-2.el5_1.1.0.1")) flag++;
if (rpm_check(release:"EL5", reference:"tog-pegasus-devel-2.6.1-2.el5_1.1.0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tog-pegasus / tog-pegasus-devel / tog-pegasus-test");
}
