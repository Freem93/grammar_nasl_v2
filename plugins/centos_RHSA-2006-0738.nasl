#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0738 and 
# CentOS Errata and Security Advisory 2006:0738 respectively.
#

include("compat.inc");

if (description)
{
  script_id(37366);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-5794");
  script_osvdb_id(30232);
  script_xref(name:"RHSA", value:"2006:0738");

  script_name(english:"CentOS 3 / 4 : openssh (CESA-2006:0738)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages that fix an authentication flaw are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure SHell) protocol implementation. This
package includes the core files necessary for both the OpenSSH client
and server.

An authentication flaw was found in OpenSSH's privilege separation
monitor. If it ever becomes possible to alter the behavior of the
unprivileged process when OpenSSH is using privilege separation, an
attacker may then be able to login without possessing proper
credentials. (CVE-2006-5794)

Please note that this flaw by itself poses no direct threat to OpenSSH
users. Without another security flaw that could allow an attacker to
alter the behavior of OpenSSH's unprivileged process, this flaw cannot
be exploited. There are currently no known flaws to exploit this
behavior. However, we have decided to issue this erratum to fix this
flaw to reduce the security impact if an unprivileged process flaw is
ever found.

Users of openssh should upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013400.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05c9a22a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013401.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17e76c77"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013402.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2afbfee5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013404.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb5a6a6f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013410.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d38bf32a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013411.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99885e55"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"openssh-3.6.1p2-33.30.13")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-askpass-3.6.1p2-33.30.13")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-askpass-gnome-3.6.1p2-33.30.13")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-clients-3.6.1p2-33.30.13")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssh-server-3.6.1p2-33.30.13")) flag++;

if (rpm_check(release:"CentOS-4", reference:"openssh-3.9p1-8.RHEL4.17.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssh-askpass-3.9p1-8.RHEL4.17.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssh-askpass-gnome-3.9p1-8.RHEL4.17.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssh-clients-3.9p1-8.RHEL4.17.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssh-server-3.9p1-8.RHEL4.17.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
