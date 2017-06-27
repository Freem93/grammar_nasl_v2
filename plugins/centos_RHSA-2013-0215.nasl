#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0215 and 
# CentOS Errata and Security Advisory 2013:0215 respectively.
#

include("compat.inc");

if (description)
{
  script_id(64382);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2012-5659", "CVE-2012-5660");
  script_bugtraq_id(57661, 57662);
  script_osvdb_id(91261, 91265);
  script_xref(name:"RHSA", value:"2013:0215");

  script_name(english:"CentOS 6 : abrt / libreport (CESA-2013:0215)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated abrt and libreport packages that fix two security issues are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

ABRT (Automatic Bug Reporting Tool) is a tool to help users to detect
defects in applications and to create a bug report with all the
information needed by a maintainer to fix it. It uses a plug-in system
to extend its functionality. libreport provides an API for reporting
different problems in applications to different bug targets, such as
Bugzilla, FTP, and Trac.

It was found that the
/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache tool did not
sufficiently sanitize its environment variables. This could lead to
Python modules being loaded and run from non-standard directories
(such as /tmp/). A local attacker could use this flaw to escalate
their privileges to that of the abrt user. (CVE-2012-5659)

A race condition was found in the way ABRT handled the directories
used to store information about crashes. A local attacker with the
privileges of the abrt user could use this flaw to perform a symbolic
link attack, possibly allowing them to escalate their privileges to
root. (CVE-2012-5660)

Red Hat would like to thank Martin Carpenter of Citco for reporting
the CVE-2012-5660 issue. CVE-2012-5659 was discovered by Miloslav
Trmac of Red Hat.

All users of abrt and libreport are advised to upgrade to these
updated packages, which correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-February/019225.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3557380"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-February/019226.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1cce3c2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected abrt and / or libreport packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-addon-ccpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-addon-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-addon-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-addon-vmcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-mailx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-reportuploader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-rhtsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"abrt-2.0.8-6.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-addon-ccpp-2.0.8-6.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-addon-kerneloops-2.0.8-6.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-addon-python-2.0.8-6.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-addon-vmcore-2.0.8-6.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-cli-2.0.8-6.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-desktop-2.0.8-6.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-devel-2.0.8-6.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-gui-2.0.8-6.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-libs-2.0.8-6.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-tui-2.0.8-6.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-2.0.9-5.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-cli-2.0.9-5.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-devel-2.0.9-5.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-gtk-2.0.9-5.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-gtk-devel-2.0.9-5.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-newt-2.0.9-5.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-bugzilla-2.0.9-5.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-kerneloops-2.0.9-5.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-logger-2.0.9-5.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-mailx-2.0.9-5.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-reportuploader-2.0.9-5.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-rhtsupport-2.0.9-5.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-python-2.0.9-5.el6.centos.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
