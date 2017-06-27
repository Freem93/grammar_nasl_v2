#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0971. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34691);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/01/03 17:16:34 $");

  script_cve_id("CVE-2008-4309");
  script_bugtraq_id(32020);
  script_xref(name:"RHSA", value:"2008:0971");

  script_name(english:"RHEL 3 / 4 / 5 : net-snmp (RHSA-2008:0971)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated net-snmp packages that fix a security issue are now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Simple Network Management Protocol (SNMP) is a protocol used for
network management.

A denial-of-service flaw was found in the way Net-SNMP processes SNMP
GETBULK requests. A remote attacker who issued a specially crafted
request could cause the snmpd server to crash. (CVE-2008-4309)

Note: An attacker must have read access to the SNMP server in order to
exploit this flaw. In the default configuration, the community name
'public' grants read-only access. In production deployments, it is
recommended to change this default community name.

All users of net-snmp should upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-4309.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0971.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0971";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL3", reference:"net-snmp-5.0.9-2.30E.25")) flag++;

  if (rpm_check(release:"RHEL3", reference:"net-snmp-devel-5.0.9-2.30E.25")) flag++;

  if (rpm_check(release:"RHEL3", reference:"net-snmp-libs-5.0.9-2.30E.25")) flag++;

  if (rpm_check(release:"RHEL3", reference:"net-snmp-perl-5.0.9-2.30E.25")) flag++;

  if (rpm_check(release:"RHEL3", reference:"net-snmp-utils-5.0.9-2.30E.25")) flag++;


  if (rpm_check(release:"RHEL4", reference:"net-snmp-5.1.2-13.el4_7.2")) flag++;

  if (rpm_check(release:"RHEL4", reference:"net-snmp-devel-5.1.2-13.el4_7.2")) flag++;

  if (rpm_check(release:"RHEL4", reference:"net-snmp-libs-5.1.2-13.el4_7.2")) flag++;

  if (rpm_check(release:"RHEL4", reference:"net-snmp-perl-5.1.2-13.el4_7.2")) flag++;

  if (rpm_check(release:"RHEL4", reference:"net-snmp-utils-5.1.2-13.el4_7.2")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"net-snmp-5.3.1-24.el5_2.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"net-snmp-5.3.1-24.el5_2.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"net-snmp-5.3.1-24.el5_2.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"net-snmp-devel-5.3.1-24.el5_2.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"net-snmp-libs-5.3.1-24.el5_2.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"net-snmp-perl-5.3.1-24.el5_2.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"net-snmp-perl-5.3.1-24.el5_2.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"net-snmp-perl-5.3.1-24.el5_2.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"net-snmp-utils-5.3.1-24.el5_2.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"net-snmp-utils-5.3.1-24.el5_2.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"net-snmp-utils-5.3.1-24.el5_2.2")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp / net-snmp-devel / net-snmp-libs / net-snmp-perl / etc");
  }
}
