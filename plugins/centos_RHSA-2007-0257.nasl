#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0257 and 
# CentOS Errata and Security Advisory 2007:0257 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67047);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/29 00:08:47 $");

  script_cve_id("CVE-2005-2666");
  script_osvdb_id(39165);
  script_xref(name:"RHSA", value:"2007:0257");

  script_name(english:"CentOS 4 : openssh (CESA-2007:0257)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages that fix a security issue and various bugs
are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure SHell) protocol implementation. This
package includes the core files necessary for both the OpenSSH client
and server.

OpenSSH stores hostnames, IP addresses, and keys in plaintext in the
known_hosts file. A local attacker that has already compromised a
user's SSH account could use this information to generate a list of
additional targets that are likely to have the same password or key.
(CVE-2005-2666)

The following bugs have also been fixed in this update :

* The ssh client could abort the running connection when the server
application generated a large output at once.

* When 'X11UseLocalhost' option was set to 'no' on systems with IPv6
networking enabled, the X11 forwarding socket listened only for IPv6
connections.

* When the privilege separation was enabled in /etc/ssh/sshd_config,
some log messages in the system log were duplicated and also had
timestamps from an incorrect timezone.

All users of openssh should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2007-May/013705.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_cwe_id(255);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");
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
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-3.9p1-8.RHEL4.20")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-askpass-3.9p1-8.RHEL4.20")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-askpass-gnome-3.9p1-8.RHEL4.20")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-clients-3.9p1-8.RHEL4.20")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssh-server-3.9p1-8.RHEL4.20")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
