#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0583. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33475);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/01/03 17:16:33 $");

  script_cve_id("CVE-2008-2952");
  script_bugtraq_id(30013);
  script_xref(name:"RHSA", value:"2008:0583");

  script_name(english:"RHEL 4 / 5 : openldap (RHSA-2008:0583)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap packages that fix a security issue are now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

OpenLDAP is an open source suite of Lightweight Directory Access
Protocol (LDAP) applications and development tools. LDAP is a set of
protocols for accessing directory services.

A denial of service flaw was found in the way the OpenLDAP slapd
daemon processed certain network messages. An unauthenticated remote
attacker could send a specially crafted request that would crash the
slapd daemon. (CVE-2008-2952)

Users of openldap should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2952.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0583.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/10");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0583";
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
  if (rpm_check(release:"RHEL4", reference:"compat-openldap-2.1.30-8.el4_6.5")) flag++;

  if (rpm_check(release:"RHEL4", reference:"openldap-2.2.13-8.el4_6.5")) flag++;

  if (rpm_check(release:"RHEL4", reference:"openldap-clients-2.2.13-8.el4_6.5")) flag++;

  if (rpm_check(release:"RHEL4", reference:"openldap-devel-2.2.13-8.el4_6.5")) flag++;

  if (rpm_check(release:"RHEL4", reference:"openldap-servers-2.2.13-8.el4_6.5")) flag++;

  if (rpm_check(release:"RHEL4", reference:"openldap-servers-sql-2.2.13-8.el4_6.5")) flag++;


  if (rpm_check(release:"RHEL5", reference:"compat-openldap-2.3.27_2.2.29-8.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"openldap-2.3.27-8.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openldap-clients-2.3.27-8.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openldap-clients-2.3.27-8.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openldap-clients-2.3.27-8.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"openldap-devel-2.3.27-8.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openldap-servers-2.3.27-8.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openldap-servers-2.3.27-8.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openldap-servers-2.3.27-8.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openldap-servers-sql-2.3.27-8.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openldap-servers-sql-2.3.27-8.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openldap-servers-sql-2.3.27-8.el5_2.4")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-openldap / openldap / openldap-clients / openldap-devel / etc");
  }
}
