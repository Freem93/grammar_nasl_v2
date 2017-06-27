#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1131 and 
# CentOS Errata and Security Advisory 2012:1131 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67093);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2012-1013", "CVE-2012-1015");
  script_bugtraq_id(53784);
  script_osvdb_id(82650, 84423);
  script_xref(name:"RHSA", value:"2012:1131");

  script_name(english:"CentOS 6 : krb5 (CESA-2012:1131)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix two security issues are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other using symmetric encryption and a
trusted third-party, the Key Distribution Center (KDC).

An uninitialized pointer use flaw was found in the way the MIT
Kerberos KDC handled initial authentication requests (AS-REQ). A
remote, unauthenticated attacker could use this flaw to crash the KDC
via a specially crafted AS-REQ request. (CVE-2012-1015)

A NULL pointer dereference flaw was found in the MIT Kerberos
administration daemon, kadmind. A Kerberos administrator who has the
'create' privilege could use this flaw to crash kadmind.
(CVE-2012-1013)

Red Hat would like to thank the MIT Kerberos project for reporting
CVE-2012-1015. Upstream acknowledges Emmanuel Bouillon (NCI Agency) as
the original reporter of CVE-2012-1015.

All krb5 users should upgrade to these updated packages, which contain
backported patches to correct these issues. After installing the
updated packages, the krb5kdc and kadmind daemons will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-July/018777.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c32fcbf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-pkinit-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"krb5-devel-1.9-33.el6_3.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-libs-1.9-33.el6_3.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-pkinit-openssl-1.9-33.el6_3.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-server-1.9-33.el6_3.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-server-ldap-1.9-33.el6_3.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-workstation-1.9-33.el6_3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
