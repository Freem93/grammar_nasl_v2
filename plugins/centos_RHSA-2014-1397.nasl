#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1397 and 
# CentOS Errata and Security Advisory 2014:1397 respectively.
#

include("compat.inc");

if (description)
{
  script_id(78397);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 13:54:06 $");

  script_cve_id("CVE-2014-3634");
  script_osvdb_id(112338);
  script_xref(name:"RHSA", value:"2014:1397");

  script_name(english:"CentOS 7 : rsyslog (CESA-2014:1397)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rsyslog packages that fix one security issue are now available
for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
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
flaw to crash the rsyslog daemon or, potentially, execute arbitrary
code as the user running the rsyslog daemon. (CVE-2014-3634)

Red Hat would like to thank Rainer Gerhards of rsyslog upstream for
reporting this issue.

All rsyslog users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing the update, the rsyslog service will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-October/020681.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5d27f62"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rsyslog packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-libdbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-mmaudit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-mmjsonparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-mmnormalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-mmsnmptrapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-udpspoof");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-crypto-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-doc-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-elasticsearch-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-gnutls-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-gssapi-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-libdbi-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-mmaudit-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-mmjsonparse-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-mmnormalize-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-mmsnmptrapd-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-mysql-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-pgsql-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-relp-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-snmp-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-udpspoof-7.4.7-7.el7_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
