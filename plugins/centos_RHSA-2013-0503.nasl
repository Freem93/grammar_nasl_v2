#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0503 and 
# CentOS Errata and Security Advisory 2013:0503 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65138);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/11/12 17:08:52 $");

  script_cve_id("CVE-2012-4450");
  script_bugtraq_id(55690);
  script_osvdb_id(85772);
  script_xref(name:"RHSA", value:"2013:0503");

  script_name(english:"CentOS 6 : 389-ds-base (CESA-2013:0503)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated 389-ds-base packages that fix one security issue, numerous
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The 389-ds-base packages provide 389 Directory Server, which is an
LDAPv3 compliant server. The base packages include the Lightweight
Directory Access Protocol (LDAP) server and command-line utilities for
server administration.

A flaw was found in the way 389 Directory Server enforced ACLs after
performing an LDAP modify relative distinguished name (modrdn)
operation. After modrdn was used to move part of a tree, the ACLs
defined on the moved (Distinguished Name) were not properly enforced
until the server was restarted. This could allow LDAP users to access
information that should be restricted by the defined ACLs.
(CVE-2012-4450)

This issue was discovered by Noriko Hosoi of Red Hat.

These updated 389-ds-base packages include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.4
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All users of 389-ds-base are advised to upgrade to these updated
packages, which correct this issue and provide numerous bug fixes and
enhancements. After installing this update, the 389 server service
will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019278.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d810f133"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-February/000468.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9a2983a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-1.2.11.15-11.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-devel-1.2.11.15-11.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-libs-1.2.11.15-11.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
