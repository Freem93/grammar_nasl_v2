#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1572 and 
# CentOS Errata and Security Advisory 2009:1572 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67072);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2009-3720");
  script_bugtraq_id(36097);
  script_osvdb_id(59737);
  script_xref(name:"RHSA", value:"2009:1572");

  script_name(english:"CentOS 3 / 4 : 4Suite (CESA-2009:1572)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated 4Suite package that fixes one security issue is now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The 4Suite package contains XML-related tools and libraries for
Python, including 4DOM, 4XSLT, 4XPath, 4RDF, and 4XPointer.

A buffer over-read flaw was found in the way 4Suite's XML parser
handles malformed UTF-8 sequences when processing XML files. A
specially crafted XML file could cause applications using the 4Suite
library to crash while parsing the file. (CVE-2009-3720)

Note: In Red Hat Enterprise Linux 3, this flaw only affects a
non-default configuration of the 4Suite package: configurations where
the beta version of the cDomlette module is enabled.

All 4Suite users should upgrade to this updated package, which
contains a backported patch to correct this issue. After installing
the updated package, applications using the 4Suite XML-related tools
and libraries must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016312.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7abfd282"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016313.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5102d8e0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016314.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bfac317"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016315.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?251f3cee"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 4suite package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:4Suite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"4Suite-0.11.1-15")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"4Suite-0.11.1-15")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"4Suite-1.0-3.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"4Suite-1.0-3.el4_8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
