#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1218 and 
# CentOS Errata and Security Advisory 2009:1218 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(40625);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2009-1376", "CVE-2009-2694", "CVE-2009-3025", "CVE-2009-3026");
  script_osvdb_id(54647);
  script_xref(name:"RHSA", value:"2009:1218");

  script_name(english:"CentOS 3 / 5 : pidgin (CESA-2009:1218)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pidgin packages that fix a security issue are now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

Federico Muttis of Core Security Technologies discovered a flaw in
Pidgin's MSN protocol handler. If a user received a malicious MSN
message, it was possible to execute arbitrary code with the
permissions of the user running Pidgin. (CVE-2009-2694)

Note: Users can change their privacy settings to only allow messages
from users on their buddy list to limit the impact of this flaw.

These packages upgrade Pidgin to version 2.5.9. Refer to the Pidgin
release notes for a full list of changes:
http://developer.pidgin.im/wiki/ChangeLog

All Pidgin users should upgrade to these updated packages, which
resolve this issue. Pidgin must be restarted for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016099.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6954565b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016100.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2bad417f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016101.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f49405f9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016102.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d072f5c9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189, 310, 399);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/20");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"pidgin-1.5.1-4.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"pidgin-1.5.1-4.el3")) flag++;

if (rpm_check(release:"CentOS-5", reference:"finch-2.5.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"finch-devel-2.5.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-2.5.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-devel-2.5.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-perl-2.5.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-tcl-2.5.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-2.5.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-devel-2.5.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-perl-2.5.9-1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
