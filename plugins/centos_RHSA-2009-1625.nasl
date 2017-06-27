#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1625 and 
# CentOS Errata and Security Advisory 2009:1625 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43031);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/06/14 17:29:26 $");

  script_cve_id("CVE-2009-3560", "CVE-2009-3720");
  script_bugtraq_id(36097, 37203);
  script_osvdb_id(59737, 60797);
  script_xref(name:"RHSA", value:"2009:1625");

  script_name(english:"CentOS 3 / 4 / 5 : expat (CESA-2009:1625)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated expat packages that fix two security issues are now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Expat is a C library written by James Clark for parsing XML documents.

Two buffer over-read flaws were found in the way Expat handled
malformed UTF-8 sequences when processing XML files. A specially
crafted XML file could cause applications using Expat to crash while
parsing the file. (CVE-2009-3560, CVE-2009-3720)

All expat users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, applications using the Expat library must be
restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016348.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08b4cd0d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016349.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d14a0bf"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016350.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74689dc2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016351.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df66081f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016378.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5803b3ff"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016379.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7523b98"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected expat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:expat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:expat-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/08");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"expat-1.95.5-6.2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"expat-1.95.5-6.2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"expat-devel-1.95.5-6.2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"expat-devel-1.95.5-6.2")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"expat-1.95.7-4.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"expat-1.95.7-4.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"expat-devel-1.95.7-4.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"expat-devel-1.95.7-4.el4_8.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"expat-1.95.8-8.3.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"expat-devel-1.95.8-8.3.el5_4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
