#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0875. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25970);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/29 15:45:04 $");

  script_cve_id("CVE-2007-3780");
  script_bugtraq_id(25017);
  script_osvdb_id(36732);
  script_xref(name:"RHSA", value:"2007:0875");

  script_name(english:"RHEL 4 / 5 : mysql (RHSA-2007:0875)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix a security flaw are now available for
Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries.

A flaw was discovered in MySQL's authentication protocol. It is
possible for a remote unauthenticated attacker to send a specially
crafted authentication request to the MySQL server causing it to
crash. (CVE-2007-3780)

All users of the MySQL server are advised to upgrade to these updated
packages, which contain a backported patch which fixes this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3780.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0875.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2007:0875";
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
  if (rpm_check(release:"RHEL4", reference:"mysql-4.1.20-2.RHEL4.1.0.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"mysql-bench-4.1.20-2.RHEL4.1.0.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"mysql-devel-4.1.20-2.RHEL4.1.0.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"mysql-server-4.1.20-2.RHEL4.1.0.1")) flag++;


  if (rpm_check(release:"RHEL5", reference:"mysql-5.0.22-2.1.0.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-bench-5.0.22-2.1.0.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-bench-5.0.22-2.1.0.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-bench-5.0.22-2.1.0.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"mysql-devel-5.0.22-2.1.0.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-server-5.0.22-2.1.0.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-server-5.0.22-2.1.0.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-server-5.0.22-2.1.0.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-test-5.0.22-2.1.0.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-test-5.0.22-2.1.0.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-test-5.0.22-2.1.0.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-devel / mysql-server / mysql-test");
  }
}
