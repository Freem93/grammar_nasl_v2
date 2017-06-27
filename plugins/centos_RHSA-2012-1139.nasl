#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1139 and 
# CentOS Errata and Security Advisory 2012:1139 respectively.
#

include("compat.inc");

if (description)
{
  script_id(61399);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2012-3429");
  script_bugtraq_id(54787);
  script_osvdb_id(84437);
  script_xref(name:"RHSA", value:"2012:1139");

  script_name(english:"CentOS 6 : bind-dyndb-ldap (CESA-2012:1139)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated bind-dyndb-ldap package that fixes one security issue is
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The dynamic LDAP back end is a plug-in for BIND that provides back-end
capabilities to LDAP databases. It features support for dynamic
updates and internal caching that help to reduce the load on LDAP
servers.

A flaw was found in the way bind-dyndb-ldap performed the escaping of
names from DNS requests for use in LDAP queries. A remote attacker
able to send DNS queries to a named server that is configured to use
bind-dyndb-ldap could use this flaw to cause named to exit
unexpectedly with an assertion failure. (CVE-2012-3429)

Red Hat would like to thank Sigbjorn Lie of Atea Norway for reporting
this issue.

All bind-dyndb-ldap users should upgrade to this updated package,
which contains a backported patch to correct this issue. For the
update to take effect, the named service must be restarted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-August/018784.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ecf019e3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bind-dyndb-ldap package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-dyndb-ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"bind-dyndb-ldap-1.1.0-0.9.b1.el6_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
