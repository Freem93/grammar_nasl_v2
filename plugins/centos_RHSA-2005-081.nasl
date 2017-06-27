#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:081 and 
# CentOS Errata and Security Advisory 2005:081 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21797);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/03 14:54:57 $");

  script_cve_id("CVE-2004-0467", "CVE-2004-0967");
  script_osvdb_id(11069, 13196);
  script_xref(name:"RHSA", value:"2005:081");

  script_name(english:"CentOS 3 : ghostscript (CESA-2005:081)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ghostscript packages that fix a PDF output issue and a
temporary file security bug are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Ghostscript is a program for displaying PostScript files or printing
them to non-PostScript printers.

A bug was found in the way several of Ghostscript's utility scripts
created temporary files. A local user could cause these utilities to
overwrite files that the victim running the utility has write access
to. The Common Vulnerabilities and Exposures project assigned the name
CVE-2004-0967 to this issue.

Additionally, this update addresses the following issue :

A problem has been identified in the PDF output driver, which can
cause output to be delayed indefinitely on some systems. The fix has
been backported from GhostScript 7.07.

All users of ghostscript should upgrade to these updated packages,
which contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012213.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89f1e541"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012223.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25c52e1a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012224.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72a807d6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hpijs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"ghostscript-7.05-32.1.10")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ghostscript-devel-7.05-32.1.10")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"hpijs-1.3-32.1.10")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"hpijs-1.3-32.1.10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
