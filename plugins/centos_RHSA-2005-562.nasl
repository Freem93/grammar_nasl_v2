#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:562 and 
# CentOS Errata and Security Advisory 2005:562 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21840);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2004-0175", "CVE-2005-0488", "CVE-2005-1175", "CVE-2005-1689");
  script_xref(name:"RHSA", value:"2005:562");

  script_name(english:"CentOS 3 : krb5 (CESA-2005:562)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages which fix multiple security issues are now
available for Red Hat Enterprise Linux 2.1 and 3.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

[Updated 26 Sep 2005] krb5-server packages have been added to this
advisory for Red Hat Enterprise Linux 3 WS and Red Hat Enterprise
Linux 3 Desktop.

Kerberos is a networked authentication system which uses a trusted
third party (a KDC) to authenticate clients and servers to each other.

A double-free flaw was found in the krb5_recvauth() routine which may
be triggered by a remote unauthenticated attacker. Although no exploit
is currently known to exist, this issue could potentially be exploited
to allow arbitrary code execution on a Key Distribution Center (KDC).
The Common Vulnerabilities and Exposures project assigned the name
CVE-2005-1689 to this issue.

Daniel Wachdorf discovered a single byte heap overflow in the
krb5_unparse_name() function, part of krb5-libs. Sucessful
exploitation of this flaw would lead to a denial of service (crash).
To trigger this flaw an attacker would need to have control of a
kerberos realm that shares a cross-realm key with the target, making
exploitation of this flaw unlikely. (CVE-2005-1175).

Gael Delalleau discovered an information disclosure issue in the way
some telnet clients handle messages from a server. An attacker could
construct a malicious telnet server that collects information from the
environment of any victim who connects to it using the Kerberos-aware
telnet client (CVE-2005-0488).

The rcp protocol allows a server to instruct a client to write to
arbitrary files outside of the current directory. This could
potentially cause a security issue if a user uses the Kerberos-aware
rcp to copy files from a malicious server (CVE-2004-0175).

All users of krb5 should update to these erratum packages which
contain backported patches to correct these issues. Red Hat would like
to thank the MIT Kerberos Development Team for their responsible
disclosure of these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011925.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?856ba129"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011926.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4588a66b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011930.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?406ed05c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(22, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"krb5-devel-1.2.7-47")) flag++;
if (rpm_check(release:"CentOS-3", reference:"krb5-libs-1.2.7-47")) flag++;
if (rpm_check(release:"CentOS-3", reference:"krb5-server-1.2.7-47")) flag++;
if (rpm_check(release:"CentOS-3", reference:"krb5-workstation-1.2.7-47")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
