#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1654 and 
# CentOS Errata and Security Advisory 2014:1654 respectively.
#

include("compat.inc");

if (description)
{
  script_id(79187);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 13:54:06 $");

  script_cve_id("CVE-2014-3634");
  script_bugtraq_id(70243);
  script_osvdb_id(112338);
  script_xref(name:"RHSA", value:"2014:1654");

  script_name(english:"CentOS 6 : rsyslog7 (CESA-2014:1654)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rsyslog7 packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The rsyslog7 packages provide an enhanced, multi-threaded syslog
daemon that supports writing to relational databases, syslog/TCP, RFC
3195, permitted sender lists, filtering on any message part, and fine
grained output format control.

A flaw was found in the way rsyslog handled invalid log message
priority values. In certain configurations, a local attacker, or a
remote attacker able to connect to the rsyslog port, could use this
flaw to crash the rsyslog daemon or, potentially, execute arbitrary
code as the user running the rsyslog daemon. (CVE-2014-3634)

Red Hat would like to thank Rainer Gerhards of rsyslog upstream for
reporting this issue.

All rsyslog7 users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing the update, the rsyslog service will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2014-October/001478.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40754645"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rsyslog7 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog7-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog7-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog7-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog7-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog7-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog7-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog7-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
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
if (rpm_check(release:"CentOS-6", reference:"rsyslog7-7.4.10-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rsyslog7-elasticsearch-7.4.10-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rsyslog7-gnutls-7.4.10-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rsyslog7-gssapi-7.4.10-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rsyslog7-mysql-7.4.10-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rsyslog7-pgsql-7.4.10-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rsyslog7-relp-7.4.10-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rsyslog7-snmp-7.4.10-3.el6_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
