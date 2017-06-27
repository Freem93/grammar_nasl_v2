#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:527 and 
# CentOS Errata and Security Advisory 2005:527 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67028);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/29 00:08:47 $");

  script_cve_id("CVE-2005-2798", "CVE-2008-1483");
  script_osvdb_id(19141);
  script_xref(name:"RHSA", value:"2005:527");

  script_name(english:"CentOS 4 : openssh (CESA-2005:527)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages that fix a security issue, bugs, and add
support for recording login user IDs for audit are now available for
Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure SHell) protocol implementation.

An error in the way OpenSSH handled GSSAPI credential delegation was
discovered. OpenSSH as distributed with Red Hat Enterprise Linux 4
contains support for GSSAPI user authentication, typically used for
supporting Kerberos. On OpenSSH installations which have GSSAPI
enabled, this flaw could allow a user who sucessfully authenticates
using a method other than GSSAPI to be delegated with GSSAPI
credentials. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-2798 to this issue.

Additionally, the following bugs have been addressed :

The ssh command incorrectly failed when it was issued by the root user
with a non-default group set.

The sshd daemon could fail to properly close the client connection if
multiple X clients were forwarded over the connection and the client
session exited.

The sshd daemon could bind only on the IPv6 address family for X
forwarding if the port on IPv4 address family was already bound. The X
forwarding did not work in such cases.

This update also adds support for recording login user IDs for the
auditing service. The user ID is attached to the audit records
generated from the user's session.

All users of openssh should upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012239.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bc16a1c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-3.9p1-8.RHEL4.9")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-askpass-3.9p1-8.RHEL4.9")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-askpass-gnome-3.9p1-8.RHEL4.9")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-clients-3.9p1-8.RHEL4.9")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-server-3.9p1-8.RHEL4.9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
