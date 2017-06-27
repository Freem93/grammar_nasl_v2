#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:767 and 
# CentOS Errata and Security Advisory 2005:767 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21961);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-2069", "CVE-2005-2641");
  script_bugtraq_id(14125, 14126);
  script_osvdb_id(17692, 18963);
  script_xref(name:"RHSA", value:"2005:767");

  script_name(english:"CentOS 4 : openldap / nss_ldap (CESA-2005:767)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap and nss_ldap packages that correct a potential
password disclosure issue and possible authentication vulnerability
are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools.

The nss_ldap module is an extension for use with GNU libc which allows
applications to, without internal modification, consult a directory
service using LDAP to supplement information that would be read from
local files such as /etc/passwd, /etc/group, and /etc/shadow.

A bug was found in the way OpenLDAP, nss_ldap, and pam_ldap refer LDAP
servers. If a client connection is referred to a different server, it
is possible that the referred connection will not be encrypted even if
the client has 'ssl start_tls' in its ldap.conf file. The Common
Vulnerabilities and Exposures project has assigned the name
CVE-2005-2069 to this issue.

A bug was found in the way the pam_ldap module processed certain
failure messages. If the server includes supplemental data in an
authentication failure result message, but the data does not include
any specific error code, the pam_ldap module would proceed as if the
authentication request had succeeded, and authentication would
succeed. The Common Vulnerabilities and Exposures project has assigned
the name CVE-2005-2641 to this issue.

Additionally the following issues are corrected in this erratum.

  - The OpenLDAP upgrading documentation has been updated.

  - Fix a database deadlock locking issue.

  - A fix where slaptest segfaults on exit after successful
    check.

  - The library libslapd_db-4.2.so is now located in an
    architecture-dependent directory.

  - The LDAP client no longer enters an infinite loop when
    the server returns a reference to itself.

  - The pam_ldap module adds the ability to check user
    passwords using a directory server to PAM-aware
    applications.

  - The directory server can now include supplemental
    information regarding the state of the user's account if
    a client indicates that it supports such a feature.

All users of OpenLDAP and nss_ldap are advised to upgrade to these
updated packages, which contain backported fixes that resolve these
issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012295.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?582b8e00"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012318.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?719f1d36"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012319.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77745151"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nss_ldap and / or openldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"compat-openldap-2.1.30-4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"nss_ldap-226-10")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openldap-2.2.13-4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openldap-clients-2.2.13-4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openldap-devel-2.2.13-4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openldap-servers-2.2.13-4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openldap-servers-sql-2.2.13-4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
