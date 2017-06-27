#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0126 and 
# CentOS Errata and Security Advisory 2014:0126 respectively.
#

include("compat.inc");

if (description)
{
  script_id(72267);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2013-4449");
  script_bugtraq_id(63190);
  script_osvdb_id(98656);
  script_xref(name:"RHSA", value:"2014:0126");

  script_name(english:"CentOS 6 : openldap (CESA-2014:0126)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

OpenLDAP is an open source suite of Lightweight Directory Access
Protocol (LDAP) applications and development tools. LDAP is a set of
protocols used to access and maintain distributed directory
information services over an IP network. The openldap package contains
configuration files, libraries, and documentation for OpenLDAP.

A denial of service flaw was found in the way the OpenLDAP server
daemon (slapd) performed reference counting when using the rwm
(rewrite/remap) overlay. A remote attacker able to query the OpenLDAP
server could use this flaw to crash the server by immediately
unbinding from the server after sending a search request.
(CVE-2013-4449)

Red Hat would like to thank Michael Vishchers from Seven Principles AG
for reporting this issue.

This update also fixes the following bug :

* Previously, OpenLDAP did not properly handle a number of
simultaneous updates. As a consequence, sending a number of parallel
update requests to the server could cause a deadlock. With this
update, a superfluous locking mechanism causing the deadlock has been
removed, thus fixing the bug. (BZ#1056124)

All openldap users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-February/020132.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d5f5178"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/04");
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
if (rpm_check(release:"CentOS-6", reference:"openldap-2.4.23-34.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openldap-clients-2.4.23-34.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openldap-devel-2.4.23-34.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openldap-servers-2.4.23-34.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openldap-servers-sql-2.4.23-34.el6_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
