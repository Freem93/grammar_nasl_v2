#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:397 and 
# CentOS Errata and Security Advisory 2005:397 respectively.
#

include("compat.inc");

if (description)
{
  script_id(23980);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/28 23:40:39 $");

  script_cve_id("CVE-2005-0102", "CVE-2005-0806");
  script_osvdb_id(13160, 14577);
  script_xref(name:"RHSA", value:"2005:397");

  script_name(english:"CentOS 4 : Evolution (CESA-2005:397)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated evolution packages that fix various security issues are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Evolution is a GNOME-based collection of personal information
management (PIM) tools.

A bug was found in the way Evolution displays mail messages. It is
possible that an attacker could create a specially crafted mail
message that when opened by a victim causes Evolution to stop
responding. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0806 to this issue.

A bug was also found in Evolution's helper program camel-lock-helper.
This bug could allow a local attacker to gain root privileges if
camel-lock-helper has been built to execute with elevated privileges.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0102 to this issue. On Red Hat Enterprise
Linux, camel-lock-helper is not built to execute with elevated
privileges by default. Please note however that if users have rebuilt
Evolution from the source RPM, as the root user, camel-lock-helper may
be given elevated privileges.

All users of evolution should upgrade to these updated packages, which
include backported fixes to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011632.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011634.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"evolution-2.0.2-16")) flag++;
if (rpm_check(release:"CentOS-4", reference:"evolution-devel-2.0.2-16")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
