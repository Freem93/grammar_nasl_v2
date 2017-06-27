#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:612 and 
# CentOS Errata and Security Advisory 2005:612 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21953);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-1920");
  script_osvdb_id(18063);
  script_xref(name:"RHSA", value:"2005:612");

  script_name(english:"CentOS 4 : kdelibs (CESA-2005:612)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdelibs packages are now available for Red Hat Enterprise
Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

kdelibs contains libraries for the K Desktop Environment.

A flaw was discovered affecting Kate, the KDE advanced text editor,
and Kwrite. Depending on system settings, it may be possible for a
local user to read the backup files created by Kate or Kwrite. The
Common Vulnerabilities and Exposures project assigned the name
CVE-2005-1920 to this issue.

Please note this issue does not affect Red Hat Enterprise Linux 3 or
2.1.

Users of Kate or Kwrite should update to these errata packages which
contains a backported patch from the KDE security team correcting this
issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011984.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?123d01b8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011985.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27548c29"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011994.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00ba2744"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdelibs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/06");
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
if (rpm_check(release:"CentOS-4", reference:"kdelibs-3.3.1-3.11")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kdelibs-devel-3.3.1-3.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
