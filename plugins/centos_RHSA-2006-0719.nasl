#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0719 and 
# CentOS Errata and Security Advisory 2006:0719 respectively.
#

include("compat.inc");

if (description)
{
  script_id(36238);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/06/28 23:45:04 $");

  script_cve_id("CVE-2006-5170");
  script_osvdb_id(30189);
  script_xref(name:"RHSA", value:"2006:0719");

  script_name(english:"CentOS 4 : nss_ldap (CESA-2006:0719)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss_ldap packages that fix a security flaw are now available
for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

nss_ldap is a set of C library extensions that allow X.500 and LDAP
directory servers to be used as primary sources for aliases, ethers,
groups, hosts, networks, protocols, users, RPCs, services, and shadow
passwords.

A flaw was found in the way nss_ldap handled a PasswordPolicyResponse
control sent by an LDAP server. If an LDAP server responded to an
authentication request with a PasswordPolicyResponse control, it was
possible for an application using nss_ldap to improperly authenticate
certain users. (CVE-2006-5170)

This flaw was only exploitable within applications which did not
properly process nss_ldap error messages. Only xscreensaver is
currently known to exhibit this behavior.

All users of nss_ldap should upgrade to these updated packages, which
contain a backported patch that resolves this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013403.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c23c12cd"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013408.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb6cf8ca"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013409.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a931645"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nss_ldap package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss_ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"nss_ldap-226-17")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
