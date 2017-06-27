#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0997 and 
# CentOS Errata and Security Advisory 2012:0997 respectively.
#

include("compat.inc");

if (description)
{
  script_id(59936);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/28 23:58:55 $");

  script_cve_id("CVE-2012-2678", "CVE-2012-2746");
  script_xref(name:"RHSA", value:"2012:0997");

  script_name(english:"CentOS 6 : 389-ds-base (CESA-2012:0997)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated 389-ds-base packages that fix two security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The 389 Directory Server is an LDAPv3 compliant server. The base
packages include the Lightweight Directory Access Protocol (LDAP)
server and command-line utilities for server administration.

A flaw was found in the way 389 Directory Server handled password
changes. If an LDAP user has changed their password, and the directory
server has not been restarted since that change, an attacker able to
bind to the directory server could obtain the plain text version of
that user's password via the 'unhashed#user#password' attribute.
(CVE-2012-2678)

It was found that when the password for an LDAP user was changed, and
audit logging was enabled (it is disabled by default), the new
password was written to the audit log in plain text form. This update
introduces a new configuration parameter,
'nsslapd-auditlog-logging-hide-unhashed-pw', which when set to 'on'
(the default option), prevents 389 Directory Server from writing plain
text passwords to the audit log. This option can be configured in
'/etc/dirsrv/slapd-[ID]/dse.ldif'. (CVE-2012-2746)

All users of 389-ds-base are advised to upgrade to these updated
packages, which resolve these issues. After installing this update,
the 389 server service will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-July/018726.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d6c9179"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-1.2.10.2-18.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-devel-1.2.10.2-18.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-libs-1.2.10.2-18.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
