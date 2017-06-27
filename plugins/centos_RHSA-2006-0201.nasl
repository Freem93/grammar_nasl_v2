#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0201 and 
# CentOS Errata and Security Advisory 2006:0201 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21984);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2006-0301");
  script_osvdb_id(22833);
  script_xref(name:"RHSA", value:"2006:0201");

  script_name(english:"CentOS 4 : xpdf (CESA-2006:0201)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated xpdf package that fixes a buffer overflow security issue is
now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The xpdf package is an X Window System-based viewer for Portable
Document Format (PDF) files.

A heap based buffer overflow bug was discovered in Xpdf. An attacker
could construct a carefully crafted PDF file that could cause Xpdf to
crash or possibly execute arbitrary code when opened. The Common
Vulnerabilities and Exposures project assigned the name CVE-2006-0301
to this issue.

Users of Xpdf should upgrade to this updated package, which contains a
backported patch to resolve these issues.

Red Hat would like to thank Dirk Mueller for reporting this issue and
providing a patch."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012638.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?513510d0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012645.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32f750a9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012647.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3eef16f7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xpdf package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/01");
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
if (rpm_check(release:"CentOS-4", reference:"xpdf-3.00-11.12")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
