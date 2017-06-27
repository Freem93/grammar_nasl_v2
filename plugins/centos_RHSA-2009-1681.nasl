#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1681 and 
# CentOS Errata and Security Advisory 2009:1681 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43358);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/08/24 14:07:39 $");

  script_cve_id("CVE-2009-4035");
  script_osvdb_id(61207);
  script_xref(name:"RHSA", value:"2009:1681");

  script_name(english:"CentOS 4 : gpdf (CESA-2009:1681)");
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

This update has been rated as having important security impact by the
Red Hat Security Response Team.

GPdf is a viewer for Portable Document Format (PDF) files.

Petr Gajdos and Christian Kornacker of SUSE reported a buffer overflow
flaw in GPdf's Type 1 font parser. A specially crafted PDF file with
an embedded Type 1 font could cause GPdf to crash or, possibly,
execute arbitrary code when opened. (CVE-2009-4035)

Users are advised to upgrade to this updated package, which contains a
backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016401.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81606f92"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016402.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed927407"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gpdf package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/21");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gpdf-2.8.2-7.7.2.el4_8.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gpdf-2.8.2-7.7.2.el4_8.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
