#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0920 and 
# CentOS Errata and Security Advisory 2017:0920 respectively.
#

include("compat.inc");

if (description)
{
  script_id(99382);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/18 13:37:17 $");

  script_cve_id("CVE-2017-2668");
  script_osvdb_id(155390);
  script_xref(name:"RHSA", value:"2017:0920");

  script_name(english:"CentOS 7 : 389-ds-base (CESA-2017:0920)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for 389-ds-base is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

389 Directory Server is an LDAP version 3 (LDAPv3) compliant server.
The base packages include the Lightweight Directory Access Protocol
(LDAP) server and command-line utilities for server administration.

Security Fix(es) :

* An invalid pointer dereference flaw was found in the way 389-ds-base
handled LDAP bind requests. A remote unauthenticated attacker could
use this flaw to make ns-slapd crash via a specially crafted LDAP bind
request, resulting in denial of service. (CVE-2017-2668)

Red Hat would like to thank Joachim Jabs (F24) for reporting this
issue.

Bug Fix(es) :

* Previously, when adding a filtered role definition that uses the
'nsrole' virtual attribute in the filter, Directory Server terminated
unexpectedly. A patch has been applied, and now the roles plug-in
ignores all virtual attributes. As a result, an error message is
logged when an invalid filter is used. Additionally, the role is
deactivated and Directory Server no longer fails. (BZ#1429498)

* In a replication topology, Directory Server incorrectly calculated
the size of string format entries when a lot of entries were deleted.
The calculated size of entries was smaller than the actual required
size. Consequently, Directory Server allocated insufficient memory and
terminated unexpectedly when the data was written to it. With this
update, the size of string format entries is now calculated correctly
in the described situation and Directory Server no longer terminates
unexpectedly. (BZ#1429495)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-April/022370.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?acb75b6d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds-base packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-1.3.5.10-20.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.5.10-20.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.5.10-20.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-snmp-1.3.5.10-20.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
