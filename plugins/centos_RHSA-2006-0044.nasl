#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0044 and 
# CentOS Errata and Security Advisory 2006:0044 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21975);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/10/17 13:39:34 $");

  script_cve_id("CVE-2006-0225");
  script_osvdb_id(22692);
  script_xref(name:"RHSA", value:"2006:0044");

  script_name(english:"CentOS 4 : openssh (CESA-2006:0044)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages that fix bugs in sshd and add auditing of
user logins are now available for Red Hat Enterprise Linux 4.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure SHell) protocol implementation. This
package includes the core files necessary for both the OpenSSH client
and server.

An arbitrary command execution flaw was discovered in the way scp
copies files locally. It is possible for a local attacker to create a
file with a carefully crafted name that could execute arbitrary
commands as the user running scp to copy files locally. The Common
Vulnerabilities and Exposures project (cve.mitre.org) assigned the
name CVE-2006-0225 to this issue.

The following issue has also been fixed in this update :

* If the sshd service was stopped using the sshd init script while the
main sshd daemon was not running, the init script would kill other
sshd processes, such as the running sessions. For example, this could
happen when the 'service sshd stop' command was issued twice.

Additionally, this update implements auditing of user logins through
the system audit service.

All users of openssh should upgrade to these updated packages, which
resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012702.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d45ab6d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012731.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1fa9e96"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012738.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4058273d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/28");
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
if (rpm_check(release:"CentOS-4", reference:"openssh-3.9p1-8.RHEL4.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssh-askpass-3.9p1-8.RHEL4.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssh-askpass-gnome-3.9p1-8.RHEL4.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssh-clients-3.9p1-8.RHEL4.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssh-server-3.9p1-8.RHEL4.12")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
