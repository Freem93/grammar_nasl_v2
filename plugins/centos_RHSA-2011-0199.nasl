#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0199 and 
# CentOS Errata and Security Advisory 2011:0199 respectively.
#

include("compat.inc");

if (description)
{
  script_id(53418);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/16 19:09:23 $");

  script_cve_id("CVE-2010-4022", "CVE-2011-0281", "CVE-2011-0282", "CVE-2011-0283");
  script_bugtraq_id(46265, 46271);
  script_osvdb_id(70908, 70909);
  script_xref(name:"RHSA", value:"2011:0199");

  script_name(english:"CentOS 5 : krb5 (CESA-2011:0199)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix two security issues are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other using symmetric encryption and a
trusted third-party, the Key Distribution Center (KDC).

A NULL pointer dereference flaw was found in the way the MIT Kerberos
KDC processed principal names that were not null terminated, when the
KDC was configured to use an LDAP back end. A remote attacker could
use this flaw to crash the KDC via a specially crafted request.
(CVE-2011-0282)

A denial of service flaw was found in the way the MIT Kerberos KDC
processed certain principal names when the KDC was configured to use
an LDAP back end. A remote attacker could use this flaw to cause the
KDC to hang via a specially crafted request. (CVE-2011-0281)

Red Hat would like to thank the MIT Kerberos Team for reporting these
issues. Upstream acknowledges Kevin Longfellow of Oracle Corporation
as the original reporter of the CVE-2011-0281 issue.

All krb5 users should upgrade to these updated packages, which contain
a backported patch to correct these issues. After installing the
updated packages, the krb5kdc daemon will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017352.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43911156"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017353.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f8a9ecd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"krb5-devel-1.6.1-55.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-libs-1.6.1-55.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-server-1.6.1-55.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-server-ldap-1.6.1-55.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-workstation-1.6.1-55.el5_6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
