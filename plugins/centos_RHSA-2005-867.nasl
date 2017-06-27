#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:867 and 
# CentOS Errata and Security Advisory 2005:867 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21971);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/03/19 14:21:00 $");

  script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3628");
  script_bugtraq_id(15721, 15725, 15726, 15727);
  script_osvdb_id(21462, 21463);
  script_xref(name:"RHSA", value:"2005:867");

  script_name(english:"CentOS 4 : gpdf (CESA-2005:867)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gpdf package that fixes several security issues is now
available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The gpdf package is a GNOME based viewer for Portable Document Format
(PDF) files.

Several flaws were discovered in gpdf. An attacker could construct a
carefully crafted PDF file that could cause gpdf to crash or possibly
execute arbitrary code when opened. The Common Vulnerabilities and
Exposures project assigned the names CVE-2005-3191, CVE-2005-3192, and
CVE-2005-3193 to these issues.

Users of gpdf should upgrade to this updated package, which contains a
backported patch to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012495.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2eae5762"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012525.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06e45769"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012526.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec35b125"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gpdf package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/05");
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
if (rpm_check(release:"CentOS-4", reference:"gpdf-2.8.2-7.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
