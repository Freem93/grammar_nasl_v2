#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1181 and 
# CentOS Errata and Security Advisory 2009:1181 respectively.
#

include("compat.inc");

if (description)
{
  script_id(40423);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/04 14:30:41 $");

  script_cve_id("CVE-2009-0696");
  script_bugtraq_id(35848);
  script_osvdb_id(56584);
  script_xref(name:"RHSA", value:"2009:1181");

  script_name(english:"CentOS 3 : bind (CESA-2009:1181)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind packages that fix a security issue and a bug are now
available for Red Hat Enterprise Linux 3.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

A flaw was found in the way BIND handles dynamic update message
packets containing the 'ANY' record type. A remote attacker could use
this flaw to send a specially crafted dynamic update packet that could
cause named to exit with an assertion failure. (CVE-2009-0696)

Note: even if named is not configured for dynamic updates, receiving
such a specially crafted dynamic update packet could still cause named
to exit unexpectedly.

This update also fixes the following bug :

* the following message could have been logged: 'internal_accept:
fcntl() failed: Too many open files'. With these updated packages,
timeout queries are aborted in order to reduce the number of open UDP
sockets, and when the accept() function returns an EMFILE error value,
that situation is now handled gracefully, thus resolving the issue.
(BZ#498164)

All BIND users are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing
the update, the BIND daemon (named) will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-July/016054.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e7eba1f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-July/016055.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26ed832a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"bind-9.2.4-25.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"bind-9.2.4-25.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"bind-chroot-9.2.4-25.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"bind-chroot-9.2.4-25.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"bind-devel-9.2.4-25.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"bind-devel-9.2.4-25.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"bind-libs-9.2.4-25.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"bind-libs-9.2.4-25.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"bind-utils-9.2.4-25.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"bind-utils-9.2.4-25.el3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
