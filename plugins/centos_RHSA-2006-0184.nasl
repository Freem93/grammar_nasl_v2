#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0184 and 
# CentOS Errata and Security Advisory 2006:0184 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21981);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/04/03 11:06:11 $");

  script_cve_id("CVE-2006-0019");
  script_osvdb_id(22659);
  script_xref(name:"RHSA", value:"2006:0184");

  script_name(english:"CentOS 4 : kdelibs (CESA-2006:0184)");
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

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

kdelibs contains libraries for the K Desktop Environment (KDE).

A heap overflow flaw was discovered affecting kjs, the JavaScript
interpreter engine used by Konqueror and other parts of KDE. An
attacker could create a malicious website containing carefully crafted
JavaScript code that would trigger this flaw and possibly lead to
arbitrary code execution. The Common Vulnerabilities and Exposures
project assigned the name CVE-2006-0019 to this issue.

NOTE: this issue does not affect KDE in Red Hat Enterprise Linux 3 or
2.1.

Users of KDE should upgrade to these updated packages, which contain a
backported patch from the KDE security team correcting this issue as
well as two bug fixes."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-January/012587.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0430a664"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-January/012588.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3310d2e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-January/012596.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f7cd91a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdelibs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"kdelibs-3.3.1-3.14")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kdelibs-devel-3.3.1-3.14")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
