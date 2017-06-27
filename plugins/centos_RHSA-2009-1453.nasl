#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1453 and 
# CentOS Errata and Security Advisory 2009:1453 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43793);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2009-2703", "CVE-2009-3026", "CVE-2009-3083", "CVE-2009-3085");
  script_bugtraq_id(36277);
  script_xref(name:"RHSA", value:"2009:1453");

  script_name(english:"CentOS 4 / 5 : pidgin (CESA-2009:1453)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pidgin packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.
Info/Query (IQ) is an Extensible Messaging and Presence Protocol
(XMPP) specific request-response mechanism.

A NULL pointer dereference flaw was found in the way the Pidgin XMPP
protocol plug-in processes IQ error responses when trying to fetch a
custom smiley. A remote client could send a specially crafted IQ error
response that would crash Pidgin. (CVE-2009-3085)

A NULL pointer dereference flaw was found in the way the Pidgin IRC
protocol plug-in handles IRC topics. A malicious IRC server could send
a specially crafted IRC TOPIC message, which once received by Pidgin,
would lead to a denial of service (Pidgin crash). (CVE-2009-2703)

It was discovered that, when connecting to certain, very old Jabber
servers via XMPP, Pidgin may ignore the 'Require SSL/TLS' setting. In
these situations, a non-encrypted connection is established rather
than the connection failing, causing the user to believe they are
using an encrypted connection when they are not, leading to sensitive
information disclosure (session sniffing). (CVE-2009-3026)

A NULL pointer dereference flaw was found in the way the Pidgin MSN
protocol plug-in handles improper MSNSLP invitations. A remote
attacker could send a specially crafted MSNSLP invitation request,
which once accepted by a valid Pidgin user, would lead to a denial of
service (Pidgin crash). (CVE-2009-3083)

These packages upgrade Pidgin to version 2.6.2. Refer to the Pidgin
release notes for a full list of changes:
http://developer.pidgin.im/wiki/ChangeLog

All Pidgin users should upgrade to these updated packages, which
correct these issues. Pidgin must be restarted for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016269.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13f21b16"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016270.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5308a3e2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016169.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13e1e686"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016170.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3385dc9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"finch-2.6.2-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"finch-2.6.2-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"finch-devel-2.6.2-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"finch-devel-2.6.2-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpurple-2.6.2-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpurple-2.6.2-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpurple-devel-2.6.2-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpurple-devel-2.6.2-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpurple-perl-2.6.2-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpurple-perl-2.6.2-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpurple-tcl-2.6.2-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpurple-tcl-2.6.2-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"pidgin-2.6.2-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"pidgin-2.6.2-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"pidgin-devel-2.6.2-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"pidgin-devel-2.6.2-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"pidgin-perl-2.6.2-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"pidgin-perl-2.6.2-2.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"finch-2.6.2-2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"finch-devel-2.6.2-2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-2.6.2-2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-devel-2.6.2-2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-perl-2.6.2-2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-tcl-2.6.2-2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-2.6.2-2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-devel-2.6.2-2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-perl-2.6.2-2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
