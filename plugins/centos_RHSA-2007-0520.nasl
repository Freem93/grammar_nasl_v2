#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0520 and 
# CentOS Errata and Security Advisory 2007:0520 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43644);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/06/28 23:45:05 $");

  script_cve_id("CVE-2007-3103");
  script_osvdb_id(40945);
  script_xref(name:"RHSA", value:"2007:0520");

  script_name(english:"CentOS 5 : xorg-x11-xfs (CESA-2007:0520)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated X.org packages that address a flaw in the way the X.Org X11
xfs font server starts are now available for Red Hat Enterprise Linux
5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The X.Org X11 xfs font server provides a standard mechanism for an X
server to communicate with a font renderer.

A temporary file flaw was found in the way the X.Org X11 xfs font
server startup script executes. A local user could modify the
permissions of a file of their choosing, possibly elevating their
local privileges. (CVE-2007-3103)

Users of the X.org X11 xfs font server should upgrade to these updated
packages, which contain a backported patch and are not vulnerable to
this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014029.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ded70fde"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014030.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b49c23a4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-xfs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-xfs-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-xfs-1.0.2-4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-xfs-utils-1.0.2-4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
