#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:307 and 
# CentOS Errata and Security Advisory 2005:307 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21802);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-0396");
  script_osvdb_id(14813);
  script_xref(name:"RHSA", value:"2005:307");

  script_name(english:"CentOS 3 / 4 : kdelibs (CESA-2005:307)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdelibs packages that fix a local denial of service issue are
now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The kdelibs package provides libraries for the K Desktop Environment.

Sebastian Krahmer discovered a flaw in dcopserver, the KDE Desktop
Communication Protocol (DCOP) daemon. A local user could use this flaw
to stall the DCOP authentication process, affecting any local desktop
users and causing a reduction in their desktop functionality. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0396 to this issue.

Users of KDE should upgrade to these erratum packages, which contain
backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011549.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ea7be02"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011550.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c73ed1a0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011551.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae6fb58a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdelibs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kdelibs-3.1.3-6.10")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kdelibs-3.1.3-6.10")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kdelibs-devel-3.1.3-6.10")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kdelibs-devel-3.1.3-6.10")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kdelibs-3.1.3-6.10")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kdelibs-devel-3.1.3-6.10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
