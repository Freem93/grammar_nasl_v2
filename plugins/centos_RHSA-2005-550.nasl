#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:550 and 
# CentOS Errata and Security Advisory 2005:550 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21839);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/06/28 23:40:39 $");

  script_cve_id("CVE-2004-2069");
  script_osvdb_id(16567);
  script_xref(name:"RHSA", value:"2005:550");

  script_name(english:"CentOS 3 : openssh (CESA-2005:550)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages that fix a potential security vulnerability
and various other bugs are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure SHell) protocol implementation. This
includes the core files necessary for both the OpenSSH client and
server.

A bug was found in the way the OpenSSH server handled the MaxStartups
and LoginGraceTime configuration variables. A malicious user could
connect to the SSH daemon in such a way that it would prevent
additional logins from occuring until the malicious connections are
closed. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-2069 to this issue.

Additionally, the following issues are resolved with this update :

  - The -q option of the ssh client did not suppress the
    banner message sent by the server, which caused errors
    when used in scripts.

  - The sshd daemon failed to close the client connection if
    multiple X clients were forwarded over the connection
    and the client session exited.

  - The sftp client leaked memory if used for extended
    periods.

  - The sshd daemon called the PAM functions incorrectly if
    the user was unknown on the system.

All users of openssh should upgrade to these updated packages, which
contain backported patches and resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012216.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?860e6e7b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012229.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5fc8f200"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012230.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2bc3a04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"openssh-3.6.1p2-33.30.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-askpass-3.6.1p2-33.30.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-askpass-gnome-3.6.1p2-33.30.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-clients-3.6.1p2-33.30.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-server-3.6.1p2-33.30.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
