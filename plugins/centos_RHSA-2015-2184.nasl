#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2184 and 
# CentOS Errata and Security Advisory 2015:2184 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87141);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/04/28 18:15:07 $");

  script_cve_id("CVE-2015-2704");
  script_osvdb_id(119999);
  script_xref(name:"RHSA", value:"2015:2184");

  script_name(english:"CentOS 7 : realmd (CESA-2015:2184)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated realmd packages that fix two security issues, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The realmd DBus system service manages discovery of and enrollment in
realms and domains, such as Active Directory or Identity Management
(IdM). The realmd service detects available domains, automatically
configures the system, and joins it as an account to a domain.

A flaw was found in the way realmd parsed certain input when writing
configuration into the sssd.conf or smb.conf file. A remote attacker
could use this flaw to inject arbitrary configurations into these
files via a newline character in an LDAP response. (CVE-2015-2704)

It was found that the realm client would try to automatically join an
active directory domain without authentication, which could
potentially lead to privilege escalation within a specified domain.
(BZ#1205751)

The realmd packages have been upgraded to upstream version 0.16.1,
which provides a number of bug fixes and enhancements over the
previous version. (BZ#1174911)

This update also fixes the following bugs :

* Joining a Red Hat Enterprise Linux machine to a domain using the
realm utility creates /home/domainname/[username]/ directories for
domain users. Previously, SELinux labeled the domain users'
directories incorrectly. As a consequence, the domain users sometimes
experienced problems with SELinux policy. This update modifies the
realmd service default behavior so that the domain users' directories
are compatible with the standard SELinux policy. (BZ#1241832)

* Previously, the realm utility was unable to join or discover domains
with domain names containing underscore (_). The realmd service has
been modified to process underscores in domain names correctly, which
fixes the described bug. (BZ#1243771)

In addition, this update adds the following enhancement :

* The realmd utility now allows the user to disable automatic ID
mapping from the command line. To disable the mapping, pass the
'--automatic-id-mapping=no' option to the realmd utility. (BZ#1230941)

All realmd users are advised to upgrade to these updated packages,
which correct these issues and add these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-November/002592.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbff1f5f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected realmd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:realmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:realmd-devel-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"realmd-0.16.1-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"realmd-devel-docs-0.16.1-5.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
