#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:708 and 
# CentOS Errata and Security Advisory 2005:708 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21957);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-2097");
  script_osvdb_id(18666, 18667, 18693);
  script_xref(name:"RHSA", value:"2005:708");

  script_name(english:"CentOS 4 : gpdf (CESA-2005:708)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gpdf package that fixes a security issue is now available
for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The gpdf package is an GNOME based viewer for Portable Document Format
(PDF) files.

Marcus Meissner reported a flaw in gpdf. An attacker could construct a
carefully crafted PDF file that would cause gpdf to consume all
available disk space in /tmp when opened. The Common Vulnerabilities
and Exposures project assigned the name CVE-2005-2097 to this issue.

Note that this issue does not affect the version of gpdf in Red Hat
Enterprise Linux 3 or 2.1.

Users of gpdf should upgrade to this updated package, which contains a
backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012055.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8644934"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012059.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc04ebac"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012060.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20d16209"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gpdf package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/09");
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
if (rpm_check(release:"CentOS-4", reference:"gpdf-2.8.2-4.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
