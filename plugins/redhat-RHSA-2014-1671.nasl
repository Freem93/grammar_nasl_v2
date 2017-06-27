#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1671. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78595);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/06 15:50:59 $");

  script_cve_id("CVE-2014-3634");
  script_bugtraq_id(70243);
  script_osvdb_id(112338);
  script_xref(name:"RHSA", value:"2014:1671");

  script_name(english:"RHEL 5 / 6 : rsyslog5 and rsyslog (RHSA-2014:1671)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rsyslog5 and rsyslog packages that fix one security issue are
now available for Red Hat Enterprise Linux 5 and 6 respectively.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The rsyslog packages provide an enhanced, multi-threaded syslog daemon
that supports writing to relational databases, syslog/TCP, RFC 3195,
permitted sender lists, filtering on any message part, and fine
grained output format control.

A flaw was found in the way rsyslog handled invalid log message
priority values. In certain configurations, a local attacker, or a
remote attacker able to connect to the rsyslog port, could use this
flaw to crash the rsyslog daemon. (CVE-2014-3634)

Red Hat would like to thank Rainer Gerhards of rsyslog upstream for
reporting this issue.

All rsyslog5 and rsyslog users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue.
After installing the update, the rsyslog service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3634.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1671.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsyslog-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsyslog-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsyslog-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsyslog-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsyslog5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsyslog5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsyslog5-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsyslog5-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsyslog5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsyslog5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsyslog5-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1671";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"rsyslog5-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"rsyslog5-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"rsyslog5-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"rsyslog5-debuginfo-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"rsyslog5-debuginfo-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"rsyslog5-debuginfo-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"rsyslog5-gnutls-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"rsyslog5-gnutls-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"rsyslog5-gnutls-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"rsyslog5-gssapi-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"rsyslog5-gssapi-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"rsyslog5-gssapi-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"rsyslog5-mysql-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"rsyslog5-mysql-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"rsyslog5-mysql-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"rsyslog5-pgsql-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"rsyslog5-pgsql-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"rsyslog5-pgsql-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"rsyslog5-snmp-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"rsyslog5-snmp-5.8.12-5.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"rsyslog5-snmp-5.8.12-5.el5_11")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"rsyslog-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rsyslog-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rsyslog-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"rsyslog-debuginfo-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rsyslog-debuginfo-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rsyslog-debuginfo-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"rsyslog-gnutls-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rsyslog-gnutls-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rsyslog-gnutls-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"rsyslog-gssapi-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rsyslog-gssapi-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rsyslog-gssapi-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"rsyslog-mysql-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rsyslog-mysql-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rsyslog-mysql-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"rsyslog-pgsql-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rsyslog-pgsql-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rsyslog-pgsql-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"rsyslog-relp-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rsyslog-relp-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rsyslog-relp-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"rsyslog-snmp-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rsyslog-snmp-5.8.10-9.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rsyslog-snmp-5.8.10-9.el6_6")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsyslog / rsyslog-debuginfo / rsyslog-gnutls / rsyslog-gssapi / etc");
  }
}
