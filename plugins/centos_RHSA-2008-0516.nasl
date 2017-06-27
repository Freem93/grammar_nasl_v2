#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0516 and 
# CentOS Errata and Security Advisory 2008:0516 respectively.
#

include("compat.inc");

if (description)
{
  script_id(33111);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/04 14:30:41 $");

  script_cve_id("CVE-2008-1108");
  script_bugtraq_id(29527);
  script_osvdb_id(46005);
  script_xref(name:"RHSA", value:"2008:0516");

  script_name(english:"CentOS 3 / 4 : evolution (CESA-2008:0516)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated evolution packages that address a buffer overflow
vulnerability are now available for Red Hat Enterprise Linux 3 and Red
Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Evolution is the integrated collection of e-mail, calendaring, contact
management, communications and personal information management (PIM)
tools for the GNOME desktop environment.

A flaw was found in the way Evolution parsed iCalendar timezone
attachment data. If mail which included a carefully crafted iCalendar
attachment was opened, arbitrary code could be executed as the user
running Evolution. (CVE-2008-1108)

Red Hat would like to thank Alin Rad Pop of Secunia Research for
responsibly disclosing this issue.

All users of Evolution should upgrade to these updated packages, which
contains a backported patch which resolves this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014950.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?113a0dd9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014951.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75422f40"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014962.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3230990"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014963.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c983a55d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014968.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42cfc576"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014969.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e3aa627"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"evolution-1.4.5-22.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"evolution-devel-1.4.5-22.el3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"evolution-2.0.2-35.0.4.el4_6.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"evolution-2.0.2-35.0.4.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"evolution-2.0.2-35.0.4.el4_6.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"evolution-devel-2.0.2-35.0.4.el4_6.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"evolution-devel-2.0.2-35.0.4.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"evolution-devel-2.0.2-35.0.4.el4_6.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
